<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use App\Notifications\PasswordResetNotification;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Tests\TestCase;

class AccountTest extends TestCase
{
    use RefreshDatabase;

    public function test_registration_disabled_returns_404(): void
    {
        Config::set('oidc.registration_enabled', false);

        $this->get('/register')->assertNotFound();
    }

    public function test_user_can_register_when_enabled(): void
    {
        Config::set('oidc.registration_enabled', true);

        $this->post('/register', [
            'name' => '新用户',
            'email' => 'new@example.com',
            'password' => 'password-123',
            'password_confirmation' => 'password-123',
        ])->assertRedirect('/');

        $this->assertAuthenticated();
        $this->assertDatabaseHas('users', ['email' => 'new@example.com']);
        $this->assertDatabaseHas('audit_logs', ['action' => 'user.registered']);
    }

    public function test_duplicate_email_is_rejected(): void
    {
        Config::set('oidc.registration_enabled', true);
        User::factory()->create(['email' => 'taken@example.com']);

        $this->post('/register', [
            'name' => 'X', 'email' => 'taken@example.com',
            'password' => 'password-123', 'password_confirmation' => 'password-123',
        ])->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_forgot_password_sends_reset_link(): void
    {
        Notification::fake();
        $user = User::factory()->create();

        $this->post('/forgot-password', ['email' => $user->email])
            ->assertSessionHas('status');

        Notification::assertSentTo($user, PasswordResetNotification::class);
        $this->assertDatabaseHas('audit_logs', ['action' => 'password.reset_requested']);
    }

    public function test_forgot_password_does_not_leak_account_existence(): void
    {
        Notification::fake();

        // 不存在的邮箱返回与存在时相同的提示，且不发信
        $this->post('/forgot-password', ['email' => 'ghost@example.com'])
            ->assertSessionHas('status');
        Notification::assertNothingSent();
    }

    public function test_user_can_reset_password_with_token(): void
    {
        $user = User::factory()->create();
        $token = Password::createToken($user);

        $this->post('/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'new-password-123',
            'password_confirmation' => 'new-password-123',
        ])->assertRedirect(route('login'));

        $user->refresh();
        $this->assertTrue(Hash::check('new-password-123', $user->password));
        $this->assertDatabaseHas('audit_logs', ['action' => 'password.reset']);
    }

    public function test_invalid_reset_token_is_rejected(): void
    {
        $user = User::factory()->create(['password' => 'original-password']);

        $this->post('/reset-password', [
            'token' => 'bogus-token',
            'email' => $user->email,
            'password' => 'new-password-123',
            'password_confirmation' => 'new-password-123',
        ])->assertSessionHasErrors('email');

        $this->assertTrue(Hash::check('original-password', $user->fresh()->password));
    }

    public function test_user_can_change_password_when_authenticated(): void
    {
        $user = User::factory()->create(['password' => 'current-password']);

        $this->actingAs($user)
            ->put('/settings/security/password', [
                'current_password' => 'current-password',
                'password' => 'brand-new-password',
                'password_confirmation' => 'brand-new-password',
            ])->assertRedirect(route('security.show'));

        $this->assertTrue(Hash::check('brand-new-password', $user->fresh()->password));
        $this->assertDatabaseHas('audit_logs', ['action' => 'password.changed']);
    }

    public function test_wrong_current_password_is_rejected(): void
    {
        $user = User::factory()->create(['password' => 'current-password']);

        $this->actingAs($user)
            ->put('/settings/security/password', [
                'current_password' => 'wrong',
                'password' => 'brand-new-password',
                'password_confirmation' => 'brand-new-password',
            ])->assertSessionHasErrors('current_password');

        $this->assertTrue(Hash::check('current-password', $user->fresh()->password));
    }
}
