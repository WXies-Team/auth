<?php

namespace App\Http\Responses;

use Admin9\OidcServer\Contracts\AuthenticationRecorder;
use Admin9\OidcServer\Contracts\ReauthenticationService;
use App\Services\AuditLogger;
use App\Services\SessionTracker;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Symfony\Component\HttpFoundation\Response;

/**
 * Passkey 登录成功后的响应（替换 laravel/passkeys 默认实现）。
 *
 * 包的控制器只负责验证断言 + guard 登录，这里补齐 oidc-server 2.0 契约要求的
 * 认证时间记录，并在存在 OIDC 授权事务时继续 RP 续跳（JSON 客户端跟随 redirect）。
 */
class PasskeyLoginResponse implements \Laravel\Passkeys\Contracts\PasskeyLoginResponse
{
    public function toResponse($request): Response
    {
        $user = Auth::guard(Config::string('passkeys.guard'))->user();

        $pending = $request->session()->pull('auth.pending_oidc');
        $challenge = null;

        if (is_array($pending) && ! empty($pending['transaction']) && ! empty($pending['challenge'])) {
            $challenge = app(ReauthenticationService::class)->challenge(
                $request,
                $pending['transaction'],
                $pending['challenge'],
            );
        }

        app(AuthenticationRecorder::class)->markAuthenticated('web', $user, challenge: $challenge);

        app(SessionTracker::class)->track($request, $user);
        app(AuditLogger::class)->record('login.passkey', $user->getKey());

        if ($challenge) {
            $url = app(ReauthenticationService::class)->complete($request, $challenge)->getTargetUrl();

            return new JsonResponse(['redirect' => $url], 200);
        }

        if ($request->wantsJson()) {
            return new JsonResponse(['redirect' => redirect()->intended(route('home'))->getTargetUrl()], 200);
        }

        return redirect()->intended(route('home'));
    }
}
