<?php

namespace Tests\Feature\Oidc;

use Admin9\OidcServer\Contracts\AtomicStateStore;
use App\Models\Project;
use App\Models\User;
use App\Models\UserConsent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\Support\ArrayAtomicStateStore;
use Tests\TestCase;

/**
 * 记住授权（skip consent）：首次授权弹同意屏，记录后同 scope 再授权静默跳过，
 * scope 扩大时重新弹窗。
 */
class RememberConsentTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Config::set('oidc.dcr_initial_token', 't');
        Config::set('session.driver', 'database');
        $this->app->singleton(
            AtomicStateStore::class,
            ArrayAtomicStateStore::class,
        );
        Project::factory()->create();
    }

    private function registerClient(array $extra = []): array
    {
        return $this->postJson('/api/register', array_merge([
            'client_name' => 'Consent App',
            'redirect_uris' => ['https://app.example.com/callback'],
        ], $extra), ['Authorization' => 'Bearer t'])->json();
    }

    private function authorize(User $user, array $client, string $scope): TestResponse
    {
        $this->post('/login', ['email' => $user->email, 'password' => 'password']);

        $verifier = Str::random(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client['client_id'],
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => $scope,
            'state' => Str::random(8),
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
    }

    public function test_first_authorization_shows_consent_screen(): void
    {
        $user = User::factory()->create();
        $client = $this->registerClient();

        $response = $this->authorize($user, $client, 'openid');

        // 首次授权：渲染同意屏（200），含"授权并继续"按钮
        $response->assertOk()->assertSee('授权并继续');
    }

    public function test_reauthorization_with_same_scope_skips_consent(): void
    {
        $user = User::factory()->create();
        $client = $this->registerClient();

        // 预置已同意记录（等价于上次授权成功）
        UserConsent::create([
            'user_id' => $user->getKey(),
            'client_id' => $client['client_id'],
            'scopes' => ['openid', 'profile'],
        ]);

        // 同 scope 再授权：静默跳过同意屏，直接 302 带 code
        $response = $this->authorize($user, $client, 'openid profile');
        $response->assertRedirect();
        parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertNotEmpty($query['code'] ?? null, '跳过同意屏后应直接返回授权码');
    }

    public function test_wider_scope_reprompts_consent(): void
    {
        $user = User::factory()->create();
        $client = $this->registerClient();

        UserConsent::create([
            'user_id' => $user->getKey(),
            'client_id' => $client['client_id'],
            'scopes' => ['openid'],
        ]);

        // 请求 scope 超出已同意范围：重新弹同意屏
        $this->authorize($user, $client, 'openid email')->assertOk()->assertSee('授权并继续');
    }

    public function test_prompt_consent_forces_consent_screen(): void
    {
        $user = User::factory()->create();
        $client = $this->registerClient();

        UserConsent::create([
            'user_id' => $user->getKey(),
            'client_id' => $client['client_id'],
            'scopes' => ['openid'],
        ]);

        // prompt=consent 强制弹窗，即使已同意
        $this->post('/login', ['email' => $user->email, 'password' => 'password']);
        $verifier = Str::random(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client['client_id'],
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => 'openid',
            'state' => 's',
            'prompt' => 'consent',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertOk()->assertSee('授权并继续');
    }

    public function test_consent_is_recorded_after_token_issuance(): void
    {
        $user = User::factory()->create();
        $client = $this->registerClient();

        $this->authorizeWithApproval($user, $client, 'openid email');

        $this->assertDatabaseHas('user_consents', [
            'user_id' => $user->getKey(),
            'client_id' => $client['client_id'],
        ]);
    }

    /** 走完整授权 + 同意，拿到 token（触发 consent 记录）。 */
    private function authorizeWithApproval(User $user, array $client, string $scope): void
    {
        $this->post('/login', ['email' => $user->email, 'password' => 'password']);
        $verifier = Str::random(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $authorize = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client['client_id'],
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => $scope,
            'state' => 's',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));

        preg_match('/name="transaction" value="([^"]+)"/', $authorize->getContent(), $tx);
        preg_match('/name="auth_token" value="([^"]+)"/', $authorize->getContent(), $at);

        $approve = $this->post('/oauth/authorize', ['transaction' => $tx[1], 'auth_token' => $at[1]]);
        parse_str(parse_url($approve->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client['client_id'],
            'client_secret' => $client['client_secret'],
            'redirect_uri' => 'https://app.example.com/callback',
            'code' => $query['code'],
            'code_verifier' => $verifier,
        ])->assertOk();
    }
}
