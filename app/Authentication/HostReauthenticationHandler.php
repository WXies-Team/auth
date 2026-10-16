<?php

namespace App\Authentication;

use Admin9\OidcServer\Authentication\ReauthenticationChallenge;
use Admin9\OidcServer\Contracts\ReauthenticationHandler;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * 把 OIDC 授权流程中的“需要重新认证”重定向到宿主自己的登录页。
 * 表单只携带不透明的 transaction/challenge 令牌，RP 回调参数不进宿主表单。
 */
final class HostReauthenticationHandler implements ReauthenticationHandler
{
    public function redirect(Request $request, ReauthenticationChallenge $challenge): RedirectResponse
    {
        return redirect()->route('auth.reauthenticate', [
            'transaction' => $challenge->transactionId,
            'challenge' => $challenge->token,
        ]);
    }
}
