<?php

namespace Tests\Feature\Oidc;

use App\Models\Project;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class DcrTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Config::set('oidc.dcr_initial_token', 'test-initial-token');
        Project::factory()->create();
    }

    public function test_register_requires_initial_token(): void
    {
        $this->postJson('/api/register', ['client_name' => 'X', 'redirect_uris' => ['https://x/cb']])
            ->assertUnauthorized();
    }

    public function test_register_creates_client_and_returns_management_token(): void
    {
        $response = $this->postJson('/api/register', [
            'client_name' => 'My App',
            'redirect_uris' => ['https://app.example.com/callback'],
        ], ['Authorization' => 'Bearer test-initial-token']);

        $response->assertCreated()
            ->assertJsonStructure(['client_id', 'client_secret', 'registration_access_token', 'redirect_uris']);

        $this->assertDatabaseHas('oauth_clients', ['name' => 'My App']);
    }

    public function test_register_filters_unsupported_grant_types(): void
    {
        $response = $this->postJson('/api/register', [
            'client_name' => 'Evil App',
            'redirect_uris' => ['https://evil.example.com/cb'],
            'grant_types' => ['client_credentials', 'authorization_code'],
        ], ['Authorization' => 'Bearer test-initial-token']);

        $this->assertSame(['authorization_code'], $response->json('grant_types'));
    }

    public function test_registered_client_can_be_managed_with_its_token(): void
    {
        $data = $this->postJson('/api/register', [
            'client_name' => 'Managed',
            'redirect_uris' => ['https://m.example.com/cb'],
        ], ['Authorization' => 'Bearer test-initial-token'])->json();

        $headers = ['Authorization' => "Bearer {$data['registration_access_token']}"];

        $this->getJson("/api/register/{$data['client_id']}", $headers)
            ->assertOk()
            ->assertJsonPath('client_name', 'Managed');

        $this->putJson("/api/register/{$data['client_id']}", ['client_name' => 'Renamed'], $headers)
            ->assertOk()
            ->assertJsonPath('client_name', 'Renamed');

        $this->deleteJson("/api/register/{$data['client_id']}", [], $headers)->assertNoContent();
        $this->getJson("/api/register/{$data['client_id']}", $headers)->assertUnauthorized();
    }

    public function test_wrong_management_token_is_rejected(): void
    {
        $data = $this->postJson('/api/register', [
            'client_name' => 'Guarded',
            'redirect_uris' => ['https://g.example.com/cb'],
        ], ['Authorization' => 'Bearer test-initial-token'])->json();

        $this->getJson("/api/register/{$data['client_id']}", ['Authorization' => 'Bearer wrong'])
            ->assertUnauthorized();
    }
}
