<?php

namespace Tests\Feature\Oidc;

use Admin9\OidcServer\Contracts\AtomicStateStore;
use App\Models\Project;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Tests\Support\ArrayAtomicStateStore;
use Tests\TestCase;

/**
 * OAuth 全链路：注册 client → 授权 → code 换 token → userinfo → introspect → revoke。
 *
 * 这条链路是网关的核心契约。此前 DCR 测试只验"注册返回 management token"，
 * 从不用 client_secret 换 token，导致双重哈希 bug（client 认证永远失败）漏网。
 */
class TokenFlowTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Config::set('oidc.dcr_initial_token', 'test-initial-token');
        // 授权端点拒绝 array/cookie 会话驱动，测试改用 database。
        Config::set('session.driver', 'database');
        // 包默认的 Redis 原子状态存储在无 Redis 时 fail-closed，测试绑定内存替身。
        // 必须 singleton：bind 会在每次解析时新建实例，同一请求内状态即刻丢失。
        $this->app->singleton(
            AtomicStateStore::class,
            ArrayAtomicStateStore::class,
        );
        Project::factory()->create();
    }

    /** 走 DCR 注册一个 client，返回 [client_id, client_secret]。 */
    private function registerClient(): array
    {
        return $this->postJson('/api/register', [
            'client_name' => 'Flow App',
            'redirect_uris' => ['https://app.example.com/callback'],
        ], ['Authorization' => 'Bearer test-initial-token'])->json();
    }

    public function test_registered_client_can_exchange_code_for_token(): void
    {
        $user = User::factory()->create();
        $data = $this->registerClient();

        // 登录拿到会话
        $this->post('/login', ['email' => $user->email, 'password' => 'password']);

        // 走授权端点拿授权码（PKCE S256）
        $verifier = Str::random(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $authorize = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $data['client_id'],
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => 'openid profile email',
            'state' => 'xyz',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));

        // 首次授权渲染同意屏（200），从中取出事务与审批令牌后提交同意。
        $authorize->assertOk();
        preg_match('/name="transaction" value="([^"]+)"/', $authorize->getContent(), $tx);
        preg_match('/name="auth_token" value="([^"]+)"/', $authorize->getContent(), $at);
        $this->assertNotEmpty($tx[1] ?? null, '同意屏未返回事务 ID');
        $this->assertNotEmpty($at[1] ?? null, '同意屏未返回审批令牌');

        $approve = $this->post('/oauth/authorize', [
            'transaction' => $tx[1],
            'auth_token' => $at[1],
        ]);
        $approve->assertRedirect();
        $location = $approve->headers->get('Location');
        parse_str(parse_url($location, PHP_URL_QUERY), $query);
        $this->assertNotEmpty($query['code'] ?? null, '同意后未返回授权码：'.$location);

        // 用注册拿到的 client_secret 换 token —— 这一步正是双重哈希 bug 会挂的地方
        $token = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $data['client_id'],
            'client_secret' => $data['client_secret'],
            'redirect_uri' => 'https://app.example.com/callback',
            'code' => $query['code'],
            'code_verifier' => $verifier,
        ]);

        $token->assertOk()->assertJsonStructure(['access_token', 'token_type', 'expires_in']);
        $this->assertNotEmpty($token->json('access_token'));
    }

    public function test_wrong_client_secret_is_rejected(): void
    {
        $data = $this->registerClient();

        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $data['client_id'],
            'client_secret' => 'totally-wrong-secret',
            'redirect_uri' => 'https://app.example.com/callback',
            'code' => 'whatever',
            'code_verifier' => Str::random(64),
        ])->assertUnauthorized();
    }

    public function test_authorize_requires_pkce(): void
    {
        $user = User::factory()->create();
        $data = $this->registerClient();
        $this->post('/login', ['email' => $user->email, 'password' => 'password']);

        // 缺 code_challenge：OAuth 2.1 要求所有客户端强制 PKCE
        $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $data['client_id'],
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => 'openid',
            'state' => 'xyz',
        ]))->assertStatus(400);
    }

    public function test_authorize_rejects_plain_pkce_method(): void
    {
        $user = User::factory()->create();
        $data = $this->registerClient();
        $this->post('/login', ['email' => $user->email, 'password' => 'password']);

        $verifier = Str::random(64);
        $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $data['client_id'],
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => 'openid',
            'state' => 'xyz',
            'code_challenge' => $verifier,
            'code_challenge_method' => 'plain',
        ]))->assertStatus(400);
    }

    public function test_client_credentials_grant_issues_token(): void
    {
        // M2M：注册一个仅 client_credentials 的 client，直接换 token（无需用户/授权码）
        $data = $this->postJson('/api/register', [
            'client_name' => 'M2M',
            'redirect_uris' => ['https://m2m.example.com/cb'],
            'grant_types' => ['client_credentials'],
        ], ['Authorization' => 'Bearer test-initial-token'])->json();

        $token = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $data['client_id'],
            'client_secret' => $data['client_secret'],
            'scope' => 'openid',
        ]);

        $token->assertOk()->assertJsonStructure(['access_token', 'token_type', 'expires_in']);
    }

    public function test_discovery_advertises_supported_grants(): void
    {
        $discovery = $this->getJson('/.well-known/openid-configuration')->assertOk();
        $grants = $discovery->json('grant_types_supported');

        // discovery 宣告的必须都是真实可用的（此前宣告 client_credentials 但配置不支持）
        $this->assertContains('authorization_code', $grants);
        $this->assertContains('refresh_token', $grants);
        $this->assertContains('client_credentials', $grants);
        $this->assertContains('S256', $discovery->json('code_challenge_methods_supported'));
    }
}
