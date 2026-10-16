<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class LoginTest extends TestCase
{
    use RefreshDatabase;

    public function test_guest_sees_login_page(): void
    {
        $this->get('/login')->assertOk();
    }

    public function test_user_can_login_with_password(): void
    {
        $user = User::factory()->create(['password' => 'secret-password']);

        $this->post('/login', ['email' => $user->email, 'password' => 'secret-password'])
            ->assertRedirect('/');
        $this->assertAuthenticatedAs($user);
    }

    public function test_wrong_password_is_rejected_and_audited(): void
    {
        $user = User::factory()->create(['password' => 'secret-password']);

        $this->from('/login')
            ->post('/login', ['email' => $user->email, 'password' => 'wrong'])
            ->assertRedirect('/login');
        $this->assertGuest();
        $this->assertDatabaseHas('audit_logs', ['action' => 'login.failed']);
    }

    public function test_two_factor_user_is_challenged_and_can_verify_with_totp(): void
    {
        $user = User::factory()->create(['password' => 'secret-password']);
        $user->createTwoFactorAuth();
        $user->twoFactorAuth->forceFill(['enabled_at' => now()])->save();

        $this->post('/login', ['email' => $user->email, 'password' => 'secret-password'])
            ->assertRedirect('/two-factor');
        $this->assertGuest();

        $this->post('/two-factor', ['code' => $user->makeTwoFactorCode()])
            ->assertRedirect('/');
        $this->assertAuthenticatedAs($user);
    }

    public function test_two_factor_wrong_code_is_rejected(): void
    {
        $user = User::factory()->create(['password' => 'secret-password']);
        $user->createTwoFactorAuth();
        $user->twoFactorAuth->forceFill(['enabled_at' => now()])->save();

        $this->post('/login', ['email' => $user->email, 'password' => 'secret-password']);
        $this->post('/two-factor', ['code' => '000000'])->assertSessionHasErrors('code');
        $this->assertGuest();
    }

    public function test_login_creates_device_record(): void
    {
        $user = User::factory()->create(['password' => 'secret-password']);

        $this->post('/login', ['email' => $user->email, 'password' => 'secret-password']);

        $this->assertDatabaseHas('login_sessions', ['user_id' => $user->id]);
    }
}
