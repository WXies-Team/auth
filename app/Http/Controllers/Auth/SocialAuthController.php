<?php

namespace App\Http\Controllers\Auth;

use Admin9\OidcServer\Authentication\ReauthenticationChallenge;
use Admin9\OidcServer\Contracts\ReauthenticationService;
use App\Http\Controllers\Controller;
use App\Models\Identity;
use App\Models\User;
use App\Services\AuditLogger;
use App\Services\LoginFinalizer;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

/**
 * 社交登录（GitHub / Google）。
 *
 * 账户链接策略（显式、不自动合并）：
 * - 已绑定该外部身份 → 直接登录；
 * - 登录状态下带 intent=link → 绑定到当前账户（登录已证明网关账户所有权，
 *   OAuth 回调证明外部账号所有权）；
 * - 未登录且外部邮箱命中已有账户 → **不自动链接**，引导先登录原账户，
 *   登录成功后由 LoginFinalizer 完成绑定；
 * - 邮箱无命中 → JIT 创建新用户。
 * 网关只存第三方身份标识 + 基础资料（姓名/头像/邮箱）。
 */
class SocialAuthController extends Controller
{
    private const PROVIDERS = ['github', 'google'];

    public function redirectTo(Request $request, string $provider): RedirectResponse
    {
        abort_unless(in_array($provider, self::PROVIDERS, true), 404);

        if ($request->query('intent') === 'link' && Auth::check()) {
            $request->session()->put('social_intent', 'link');
        }

        return Socialite::driver($provider)->redirect();
    }

    public function callback(string $provider, Request $request): RedirectResponse
    {
        abort_unless(in_array($provider, self::PROVIDERS, true), 404);

        $socialUser = Socialite::driver($provider)->user();

        $identity = Identity::where('provider', $provider)
            ->where('provider_user_id', (string) $socialUser->getId())
            ->first();

        // 1) 已绑定 → 直接走标准登录收尾
        if ($identity?->user) {
            return app(LoginFinalizer::class)->finalize(
                $request,
                'web',
                $identity->user,
                challenge: $this->resumeChallenge($request),
                method: "social.{$provider}",
                remember: true,
            );
        }

        // 2) 登录态下显式绑定到当前账户
        if ($request->session()->pull('social_intent') === 'link' && Auth::check()) {
            return $this->linkToUser($request, Auth::user(), $provider, $socialUser);
        }

        $existing = $socialUser->getEmail()
            ? User::where('email', $socialUser->getEmail())->first()
            : null;

        // 3) 外部邮箱命中已有账户：不自动合并，引导先登录原账户再绑定
        if ($existing) {
            $request->session()->put('pending_social_link', [
                'provider' => $provider,
                'provider_user_id' => (string) $socialUser->getId(),
                'provider_email' => $socialUser->getEmail(),
                'name' => $socialUser->getName(),
                'avatar' => $socialUser->getAvatar(),
                'user_id' => $existing->getKey(),
            ]);

            return redirect()->route('login')
                ->with('status', '该邮箱已注册网关账户，请先登录原账户以完成社交账号绑定');
        }

        // 4) 新用户 JIT 创建（Google 主邮箱已验证；GitHub 不保证，占位邮箱一律不标已验证）
        $verified = $provider === 'google' && $socialUser->getEmail() !== null;

        $user = User::create([
            'name' => $socialUser->getName() ?: Str::limit($socialUser->getNickname() ?: 'User', 50),
            'email' => $socialUser->getEmail() ?: sprintf('%s-%s@%s.invalid', $provider, $socialUser->getId(), $provider),
            'avatar_url' => $socialUser->getAvatar(),
            'password' => Str::password(40),
        ]);

        if ($verified) {
            $user->forceFill(['email_verified_at' => now()])->save();
        }

        $user->identities()->create([
            'provider' => $provider,
            'provider_user_id' => (string) $socialUser->getId(),
            'provider_email' => $socialUser->getEmail(),
        ]);

        app(AuditLogger::class)->record('user.jit_created', $user->getKey(), metadata: ['provider' => $provider]);

        return app(LoginFinalizer::class)->finalize(
            $request,
            'web',
            $user,
            challenge: $this->resumeChallenge($request),
            method: "social.{$provider}",
            remember: true,
        );
    }

    private function linkToUser(Request $request, User $user, string $provider, $socialUser): RedirectResponse
    {
        $user->identities()->create([
            'provider' => $provider,
            'provider_user_id' => (string) $socialUser->getId(),
            'provider_email' => $socialUser->getEmail(),
        ]);

        app(AuditLogger::class)->record('security.identity_linked', $user->getKey(), metadata: [
            'provider' => $provider,
        ]);

        return redirect()->route('security.show')->with('status', ucfirst($provider).' 账号已绑定');
    }

    /**
     * 从登录页绕行社交登录时续接 OIDC 事务。
     */
    private function resumeChallenge(Request $request): ?ReauthenticationChallenge
    {
        $pending = $request->session()->pull('auth.pending_oidc');

        if (! is_array($pending) || empty($pending['transaction']) || empty($pending['challenge'])) {
            return null;
        }

        return app(ReauthenticationService::class)->challenge(
            $request,
            $pending['transaction'],
            $pending['challenge'],
        );
    }
}
