<?php

namespace App\Http\Middleware;

use App\Services\SessionTracker;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 已登录用户的活跃度跟踪（写入节流在 SessionTracker 内）。
 */
class TrackSessionActivity
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if ($request->user() && $request->hasSession()) {
            app(SessionTracker::class)->touch($request);
        }

        return $response;
    }
}
