<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\UserConsent;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * 已授权应用（对标 GitHub「已授权的 OAuth 应用」/ Google「第三方应用权限」）。
 *
 * 用户此前在此网关授权过的应用集中列在此处，可单个或全部撤销。
 * 撤销即吊销该应用名下所有 access + refresh token，应用需重新授权。
 */
class ConnectedAppsController extends Controller
{
    public function index(): View
    {
        $user = Auth::user();

        // 以 refresh token（7 天）为持久授权信号——access token 仅 15 分钟，
        // 只按 access 列会在过期后让应用从页面消失，用户无从撤销仍在生效的 refresh。
        // 同时纳入未过期的 access token（覆盖无 refresh 的边界情形）。
        $tokens = DB::table('oauth_access_tokens as at')
            ->join('oauth_clients as c', 'c.id', '=', 'at.client_id')
            ->leftJoin('oauth_refresh_tokens as rt', 'rt.access_token_id', '=', 'at.id')
            ->where('at.user_id', $user->getKey())
            ->where(function ($query): void {
                $query->where(function ($q): void {
                    $q->where('at.revoked', false)
                        ->where(function ($q2): void {
                            $q2->whereNull('at.expires_at')->orWhere('at.expires_at', '>', now());
                        });
                })->orWhere(function ($q): void {
                    $q->where('rt.revoked', false)
                        ->where(function ($q2): void {
                            $q2->whereNull('rt.expires_at')->orWhere('rt.expires_at', '>', now());
                        });
                });
            })
            ->select('c.id as client_id', 'c.name as client_name', 'at.scopes', 'at.created_at', 'at.updated_at')
            ->distinct()
            ->orderByDesc('at.created_at')
            ->get();

        $apps = $tokens->groupBy('client_id')->map(function ($group) {
            $scopes = [];
            foreach ($group as $token) {
                foreach (explode(' ', (string) $token->scopes) as $scope) {
                    if ($scope !== '') {
                        $scopes[$scope] = $scope;
                    }
                }
            }

            /** @var array{client_id: string, client_name: string, scopes: array<int,string>, created_at: string, updated_at: string} $first */
            $first = $group->first();

            return [
                'client_id' => $first->client_id,
                'client_name' => $first->client_name,
                'scopes' => array_values($scopes),
                'authorized_at' => $group->min('created_at'),
                'last_used_at' => $group->max('updated_at'),
            ];
        })->values();

        return view('settings.connected-apps', ['apps' => $apps]);
    }

    public function revoke(Request $request, string $clientId): RedirectResponse
    {
        $user = Auth::user();

        $revoked = DB::table('oauth_access_tokens')
            ->where('user_id', $user->getKey())
            ->where('client_id', $clientId)
            ->update(['revoked' => true]);

        // 同步吊销 refresh token，防止 access 过期后仍能续期。
        DB::table('oauth_refresh_tokens')
            ->whereIn('access_token_id', function ($query) use ($user, $clientId): void {
                $query->select('id')->from('oauth_access_tokens')
                    ->where('user_id', $user->getKey())
                    ->where('client_id', $clientId);
            })
            ->update(['revoked' => true]);

        // 删除「记住授权」记录，下次该应用再请求授权时重新弹同意屏。
        UserConsent::query()
            ->where('user_id', $user->getKey())
            ->where('client_id', $clientId)
            ->delete();

        app(AuditLogger::class)->record('apps.revoked', $user->getKey(), 'oauth_client', null, [
            'client_id' => $clientId,
            'tokens_revoked' => $revoked,
        ]);

        return back()->with('status', '已撤销该应用的访问权限');
    }

    public function revokeAll(Request $request): RedirectResponse
    {
        $user = Auth::user();

        $revoked = DB::table('oauth_access_tokens')
            ->where('user_id', $user->getKey())
            ->update(['revoked' => true]);

        DB::table('oauth_refresh_tokens')
            ->whereIn('access_token_id', function ($query) use ($user): void {
                $query->select('id')->from('oauth_access_tokens')->where('user_id', $user->getKey());
            })
            ->update(['revoked' => true]);

        // 删除所有「记住授权」记录。
        UserConsent::query()->where('user_id', $user->getKey())->delete();

        app(AuditLogger::class)->record('apps.revoked_all', $user->getKey(), metadata: [
            'tokens_revoked' => $revoked,
        ]);

        return back()->with('status', '已撤销所有应用的访问权限');
    }
}
