<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\AuditLogger;
use App\Services\SessionTracker;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

/**
 * 账户安全设置：TOTP 绑定、恢复码、（后续）Passkey 管理入口。
 * 恢复码仅在确认绑定与重新生成时展示一次，库里只存哈希。
 */
class SecurityController extends Controller
{
    public function show(Request $request): View
    {
        $user = Auth::user();
        $pendingSecret = null;

        $twoFactorAuth = $user->twoFactorAuth;

        if (! $user->hasTwoFactorEnabled() && $twoFactorAuth?->exists) {
            $pendingSecret = [
                'qr' => $twoFactorAuth->toQr(),
                'uri' => $twoFactorAuth->toUri(),
                'string' => (string) $twoFactorAuth->shared_secret,
            ];
        }

        return view('settings.security', [
            'user' => $user,
            'enabled' => $user->hasTwoFactorEnabled(),
            'pendingSecret' => $pendingSecret,
            'recoveryCodes' => $request->session()->get('recovery_codes'),
        ]);
    }

    public function enable(Request $request): RedirectResponse
    {
        $user = Auth::user();

        if (! $user->hasTwoFactorEnabled()) {
            $user->createTwoFactorAuth();
            app(AuditLogger::class)->record('security.2fa.setup_started', $user->getKey());
        }

        return redirect()->route('security.show');
    }

    public function confirm(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'code' => ['required', 'string'],
        ]);

        $user = Auth::user();

        if (! $user->confirmTwoFactorAuth($data['code'])) {
            throw ValidationException::withMessages([
                'code' => '验证码不正确，请重试。',
            ]);
        }

        // 确认后配置会自动生成恢复码；一次性明文展示，库里仅存哈希。
        $request->session()->flash('recovery_codes', $user->fresh()->getRecoveryCodes()->all());
        app(AuditLogger::class)->record('security.2fa.enabled', $user->getKey());
        // 2FA 启用后强制其他设备重新登录
        app(SessionTracker::class)->revokeAllExcept($user);

        return redirect()->route('security.show');
    }

    public function disable(Request $request): RedirectResponse
    {
        Auth::user()->disableTwoFactorAuth();
        $request->session()->forget('recovery_codes');
        app(AuditLogger::class)->record('security.2fa.disabled', Auth::id());
        app(SessionTracker::class)->revokeAllExcept(Auth::user());

        return redirect()->route('security.show');
    }

    public function regenerateRecoveryCodes(Request $request): RedirectResponse
    {
        $user = Auth::user();

        abort_unless($user->hasTwoFactorEnabled(), 403);

        $request->session()->flash('recovery_codes', $user->generateRecoveryCodes()->all());
        app(AuditLogger::class)->record('security.recovery_codes.regenerated', $user->getKey());

        return redirect()->route('security.show');
    }
}
