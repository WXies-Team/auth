<?php

namespace App\Http\Controllers\Auth;

use Admin9\OidcServer\Contracts\ReauthenticationService;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use App\Services\LoginFinalizer;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

/**
 * 第二因子（TOTP / 恢复码）挑战页。
 *
 * 密码校验通过且用户启用 2FA 后，登录暂存于 session 的 pending 状态，
 * 此处完成第二因子核验后才执行 guard 登录（符合 oidc-server“验完所有因子
 * 之前不登录”的契约）。pending 里携带 OIDC 事务时，完成后继续 RP 续跳。
 */
class TwoFactorChallengeController extends Controller
{
    public function show(Request $request): View|RedirectResponse
    {
        $pending = $request->session()->get('auth.pending_2fa');

        if (! is_array($pending)) {
            return redirect()->route('login');
        }

        return view('auth.two-factor', [
            'useRecoveryCode' => (bool) $request->query('recovery'),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $pending = $request->session()->get('auth.pending_2fa');

        if (! is_array($pending)) {
            return redirect()->route('login');
        }

        $data = $request->validate([
            'code' => ['required', 'string'],
        ]);

        $user = User::find($pending['user_id']);

        if (! $user || ! $user->validateTwoFactorCode($data['code'])) {
            app(AuditLogger::class)->record('login.failed', $pending['user_id'] ?? null, metadata: [
                'reason' => 'invalid_two_factor_code',
            ]);

            throw ValidationException::withMessages([
                'code' => __('two-factor::validation.failed'),
            ]);
        }

        $guard = $pending['guard'];

        $challenge = null;
        if (! empty($pending['transaction']) && ! empty($pending['challenge'])) {
            $challenge = app(ReauthenticationService::class)->challenge(
                $request,
                $pending['transaction'],
                $pending['challenge'],
            );
        }

        $request->session()->forget('auth.pending_2fa');

        return app(LoginFinalizer::class)->finalize(
            $request,
            $guard,
            $user,
            challenge: $challenge,
            method: 'two_factor',
        );
    }
}
