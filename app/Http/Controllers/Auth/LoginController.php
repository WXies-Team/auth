<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\LoginSession;
use App\Services\AuditLogger;
use App\Services\BackchannelLogoutService;
use App\Services\LoginFinalizer;
use App\Services\SessionTracker;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

class LoginController extends Controller
{
    public function show(): View
    {
        return view('auth.login');
    }

    public function store(Request $request): RedirectResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $provider = Auth::guard('web')->getProvider();
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
                'guard' => 'web',
                'transaction' => null,
                'challenge' => null,
            ]);

            return redirect()->route('two-factor.show');
        }

        return app(LoginFinalizer::class)->finalize(
            $request,
            'web',
            $user,
            method: 'password',
            remember: $request->boolean('remember'),
        );
    }

    public function destroy(Request $request): RedirectResponse
    {
        $user = Auth::user();

        if ($user) {
            // 撤销当前设备记录（会话立即失效），并按 Back-Channel Logout 通知各 Client。
            LoginSession::where('user_id', $user->getKey())
                ->where('session_id', $request->session()->getId())
                ->get()
                ->each(fn (LoginSession $session) => app(SessionTracker::class)->revoke($session));

            app(BackchannelLogoutService::class)->notifyForUser($user);
            app(AuditLogger::class)->record('logout', $user->getKey());
        }

        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('home');
    }
}
