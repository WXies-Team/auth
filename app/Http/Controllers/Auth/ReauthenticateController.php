<?php

namespace App\Http\Controllers\Auth;

use Admin9\OidcServer\Contracts\ReauthenticationService;
use App\Http\Controllers\Controller;
use App\Services\AuditLogger;
use App\Services\LoginFinalizer;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

/**
 * OIDC 授权流程内的宿主重认证。
 *
 * 完成顺序严格遵循 admin9/laravel-oidc-server 2.0 契约：
 * challenge → 核验凭证（后续因子在此叠加，验完前不登录）→ guard 登录
 * → 轮换会话 → markAuthenticated → complete（消费一次性凭证，返回 RP 续跳）。
 */
class ReauthenticateController extends Controller
{
    public function show(Request $request): Response
    {
        $challenge = app(ReauthenticationService::class)->challenge(
            $request,
            $request->query('transaction', ''),
            $request->query('challenge', ''),
        );

        // 供 Passkey / 社交登录等旁路方式在回调后继续本 OIDC 事务。
        $request->session()->put('auth.pending_oidc', [
            'transaction' => $challenge->transactionId,
            'challenge' => $challenge->token,
            'guard' => $challenge->guard,
        ]);

        return response()->view('auth.login', ['challenge' => $challenge])
            ->header('Cache-Control', 'no-store')
            ->header('Referrer-Policy', 'no-referrer');
    }

    public function store(Request $request): RedirectResponse
    {
        $service = app(ReauthenticationService::class);
        $challenge = $service->challenge(
            $request,
            $request->input('transaction', ''),
            $request->input('challenge', ''),
        );

        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $provider = Auth::guard($challenge->guard)->getProvider();
        $user = $provider->retrieveByCredentials($credentials);

        if (! $user || ! $provider->validateCredentials($user, $credentials)) {
            app(AuditLogger::class)->record('login.failed', null, metadata: [
                'email' => $credentials['email'],
            ]);

            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }

        // 启用 2FA 的用户：暂存 pending，验完第二因子才登录。
        if ($user->hasTwoFactorEnabled()) {
            $request->session()->put('auth.pending_2fa', [
                'user_id' => $user->getKey(),
                'guard' => $challenge->guard,
                'transaction' => $challenge->transactionId,
                'challenge' => $challenge->token,
            ]);

            return redirect()->route('two-factor.show');
        }

        return app(LoginFinalizer::class)->finalize(
            $request,
            $challenge->guard,
            $user,
            challenge: $challenge,
            method: 'password',
        );
    }
}
