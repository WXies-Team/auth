<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.1：所有客户端必须使用 PKCE（S256）。
 *
 * 包内仅在"提供了 code_challenge"时强制 S256，机密客户端可无 PKCE 走完流程，
 * 与 OAuth 2.1 / RFC 9700 不符。此中间件在授权端点前置拦截：缺 code_challenge
 * 或方法非 S256 一律拒绝。挂在 oidc-server.routes.authorization_middleware。
 */
class EnforcePkce
{
    public function handle(Request $request, Closure $next): Response
    {
        // 仅拦授权端点的精确 GET（POST 是同意提交；GET .../continue 是重认证后续跳，
        // 不携带 code_challenge，不能拦——否则 2FA/prompt=login/max_age 流程全断）。
        if ($request->isMethod('GET') && $request->is('oauth/authorize')) {
            $challenge = $request->query('code_challenge');
            $method = $request->query('code_challenge_method');

            if (! is_string($challenge) || $challenge === '' || $method !== 'S256') {
                return response()->json([
                    'error' => 'invalid_request',
                    'error_description' => 'PKCE (S256) is required for all clients.',
                ], 400);
            }
        }

        return $next($request);
    }
}
