<?php

namespace App\Services;

use Admin9\OidcServer\Authentication\ReauthenticationChallenge;
use Admin9\OidcServer\Contracts\AuthenticationRecorder;
use Admin9\OidcServer\Contracts\ReauthenticationService;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * 登录成功后的统一收尾（唯一实现，供密码/2FA/社交等路径共用）：
 * guard 登录 → 轮换会话 → 记录认证时间（oidc-server 契约）→ 记录设备与审计
 * → 有 OIDC 事务则续跳 RP，否则回落地页。
 */
class LoginFinalizer
{
    public function finalize(
        Request $request,
        string $guard,
        User $user,
        ?ReauthenticationChallenge $challenge = null,
        string $method = 'password',
        bool $remember = false,
    ): RedirectResponse {
        Auth::guard($guard)->login($user, $remember);
        $request->session()->regenerate(true);
        $request->session()->forget('auth.pending_oidc');

        app(AuthenticationRecorder::class)->markAuthenticated($guard, $user, challenge: $challenge);

        app(SessionTracker::class)->track($request, $user);
        app(AuditLogger::class)->record("login.{$method}", $user->getKey());

        if ($challenge) {
            return app(ReauthenticationService::class)->complete($request, $challenge);
        }

        return redirect()->intended(route('home'));
    }
}
