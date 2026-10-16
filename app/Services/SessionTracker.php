<?php

namespace App\Services;

use App\Models\LoginSession;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * "已登录设备"跟踪：登录时建档，活跃时节流刷新，下线时双删
 * （login_sessions 行 + Laravel sessions 行，会话立即失效）。
 */
class SessionTracker
{
    public function track(Request $request, User $user): LoginSession
    {
        return LoginSession::create([
            'user_id' => $user->getKey(),
            'session_id' => $request->session()->getId(),
            'ip' => $request->ip(),
            'user_agent' => Str::limit($request->userAgent() ?? '', 500, ''),
            'last_active_at' => now(),
            'created_at' => now(),
        ]);
    }

    public function touch(Request $request): void
    {
        $sessionId = $request->session()->getId();
        $userId = Auth::id();

        // 每会话每分钟最多刷一次，避免每个请求都写库
        if (! $userId || ! Cache::add("session-touch:{$sessionId}", 1, 60)) {
            return;
        }

        LoginSession::where('user_id', $userId)
            ->where('session_id', $sessionId)
            ->update(['last_active_at' => now()]);
    }

    public function revoke(LoginSession $session): void
    {
        DB::table('sessions')->where('id', $session->session_id)->delete();
        $session->delete();
    }

    public function revokeAllExcept(User $user, ?int $keepLoginSessionId = null): void
    {
        LoginSession::where('user_id', $user->getKey())
            ->when($keepLoginSessionId, fn ($query) => $query->where('id', '!=', $keepLoginSessionId))
            ->get()
            ->each(fn (LoginSession $session) => $this->revoke($session));
    }
}
