<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Client;
use Tests\TestCase;

class ConnectedAppsTest extends TestCase
{
    use RefreshDatabase;

    private function makeClient(string $name = 'Test App'): Client
    {
        return Client::create([
            'name' => $name,
            'secret' => 'secret',
            'redirect_uris' => ['https://x/cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'revoked' => false,
        ]);
    }

    private function makeToken(User $user, Client $client, string $scopes = 'openid profile'): string
    {
        $id = hash('sha256', uniqid('', true));
        DB::table('oauth_access_tokens')->insert([
            'id' => $id,
            'user_id' => $user->getKey(),
            'client_id' => $client->getKey(),
            'scopes' => $scopes,
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    public function test_guest_is_redirected(): void
    {
        $this->get('/settings/apps')->assertRedirect('/login');
    }

    public function test_lists_authorized_apps_with_scopes(): void
    {
        $user = User::factory()->create();
        $client = $this->makeClient('My App');
        $this->makeToken($user, $client);

        $this->actingAs($user)->get('/settings/apps')
            ->assertOk()
            ->assertSee('My App')
            ->assertSee('查看你的基本资料'); // profile 的中文描述
    }

    public function test_revoking_app_revokes_its_tokens(): void
    {
        $user = User::factory()->create();
        $client = $this->makeClient('Revokable');
        $tokenId = $this->makeToken($user, $client);

        $this->actingAs($user)->delete('/settings/apps/'.$client->getKey())
            ->assertRedirect();

        $this->assertSame(
            1,
            (int) DB::table('oauth_access_tokens')->where('id', $tokenId)->value('revoked'),
            '撤销后 access token 应被吊销'
        );
        $this->assertDatabaseHas('audit_logs', ['action' => 'apps.revoked']);
    }

    public function test_revoke_all_revokes_every_app(): void
    {
        $user = User::factory()->create();
        $a = $this->makeClient('App A');
        $b = $this->makeClient('App B');
        $tokenA = $this->makeToken($user, $a);
        $tokenB = $this->makeToken($user, $b);

        $this->actingAs($user)->delete('/settings/apps')->assertRedirect();

        $this->assertSame(1, (int) DB::table('oauth_access_tokens')->where('id', $tokenA)->value('revoked'));
        $this->assertSame(1, (int) DB::table('oauth_access_tokens')->where('id', $tokenB)->value('revoked'));
        $this->assertDatabaseHas('audit_logs', ['action' => 'apps.revoked_all']);
    }

    public function test_revoking_does_not_affect_other_users(): void
    {
        $user = User::factory()->create();
        $other = User::factory()->create();
        $client = $this->makeClient('Shared');
        $this->makeToken($user, $client);
        $otherToken = $this->makeToken($other, $client);

        $this->actingAs($user)->delete('/settings/apps/'.$client->getKey());

        $this->assertSame(
            0,
            (int) DB::table('oauth_access_tokens')->where('id', $otherToken)->value('revoked'),
            '不应影响其他用户的授权'
        );
    }
}
