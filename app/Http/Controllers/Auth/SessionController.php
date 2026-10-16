<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\LoginSession;
use App\Services\AuditLogger;
use App\Services\SessionTracker;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

/**
 * "已登录设备"自助管理：列出网关登录会话，支持单个下线与全部下线。
 */
class SessionController extends Controller
{
    public function index(Request $request): View
    {
        return view('settings.sessions', [
            'sessions' => LoginSession::where('user_id', Auth::id())
                ->orderByDesc('last_active_at')
                ->get(),
            'currentId' => LoginSession::where('user_id', Auth::id())
                ->where('session_id', $request->session()->getId())
                ->value('id'),
        ]);
    }

    public function destroy(Request $request, LoginSession $session): RedirectResponse
    {
        abort_unless($session->user_id === Auth::id(), 404);

        app(SessionTracker::class)->revoke($session);
        app(AuditLogger::class)->record('session.revoked', Auth::id(), 'login_session', $session->id);

        // 下线的是当前设备本身 → 直接登出
        if ($session->session_id === $request->session()->getId()) {
            Auth::guard('web')->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return redirect()->route('home');
        }

        return back()->with('status', '设备已下线');
    }

    public function destroyOthers(Request $request): RedirectResponse
    {
        $user = Auth::user();

        app(SessionTracker::class)->revokeAllExcept(
            $user,
            LoginSession::where('user_id', $user->getKey())
                ->where('session_id', $request->session()->getId())
                ->value('id'),
        );
        app(AuditLogger::class)->record('session.revoked_all_others', $user->getKey());

        return back()->with('status', '其他设备已全部下线');
    }
}
