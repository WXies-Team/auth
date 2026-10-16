<?php

namespace App\Http\Controllers\Auth;

use Admin9\OidcServer\Contracts\ReauthenticationService;
use App\Http\Controllers\Controller;
use App\Models\Identity;
use App\Models\User;
use App\Services\LoginFinalizer;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

/**
 * 社交登录（GitHub / Google）。
 *
 * 账户链接策略：第三方返回的邮箱与网关已有用户邮箱一致时，把外部身份显式
 * 链接到该用户（两家提供商的主邮箱都经过验证）；否则 JIT 创建新用户。
 * 网关只存第三方的身份标识 + 基础资料（姓名/头像/邮箱），不存业务数据。
 */
class SocialAuthController extends Controller
{
    private const PROVIDERS = ['github', 'google'];

    public function redirectTo(string $provider): RedirectResponse
    {
        abort_unless(in_array($provider, self::PROVIDERS, true), 404);

        return Socialite::driver($provider)->redirect();
    }

    public function callback(string $provider, Request $request): RedirectResponse
    {
        abort_unless(in_array($provider, self::PROVIDERS, true), 404);

        $socialUser = Socialite::driver($provider)->user();

        $identity = Identity::where('provider', $provider)
            ->where('provider_user_id', (string) $socialUser->getId())
            ->first();

        $user = $identity?->user;

        if (! $user && $socialUser->getEmail()) {
            $user = User::where('email', $socialUser->getEmail())->first();

            if ($user) {
                $user->identities()->create([
                    'provider' => $provider,
                    'provider_user_id' => (string) $socialUser->getId(),
                    'provider_email' => $socialUser->getEmail(),
                ]);
            }
        }

        if (! $user) {
            $user = User::create([
                'name' => $socialUser->getName() ?: Str::limit($socialUser->getNickname() ?: 'User', 50),
                'email' => $socialUser->getEmail() ?: sprintf('%s-%s@%s.social.invalid', $provider, $socialUser->getId(), $provider),
                'avatar_url' => $socialUser->getAvatar(),
                'password' => Str::password(40),
            ]);

            $user->forceFill(['email_verified_at' => now()])->save();

            $user->identities()->create([
                'provider' => $provider,
                'provider_user_id' => (string) $socialUser->getId(),
                'provider_email' => $socialUser->getEmail(),
            ]);
        }

        // 续跳 OIDC 事务（从登录页经社交登录绕行的场景）
        $pending = $request->session()->get('auth.pending_oidc');
        $challenge = null;

        if (is_array($pending) && ! empty($pending['transaction']) && ! empty($pending['challenge'])) {
            $challenge = app(ReauthenticationService::class)->challenge(
                $request,
                $pending['transaction'],
                $pending['challenge'],
            );
        }

        return app(LoginFinalizer::class)->finalize(
            $request,
            'web',
            $user,
            challenge: $challenge,
            method: "social.{$provider}",
            remember: true,
        );
    }
}
