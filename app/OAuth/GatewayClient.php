<?php

namespace App\OAuth;

use Admin9\OidcServer\Models\OidcClient;
use App\Models\UserConsent;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Scope;

/**
 * 网关 Client 模型：在包的"永远弹同意屏"默认之上实现「记住授权」。
 *
 * 同一 client 再次授权、且请求 scope 为用户已同意集合的子集时，静默跳过同意屏
 * （GitHub 模式）。prompt=consent 仍由 AuthorizationFlow 强制弹窗（短路了此方法）。
 * scope 扩大时返回 false，重新征求同意。
 */
class GatewayClient extends OidcClient
{
    /**
     * @param  array<int, Scope>  $scopes
     */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        $requested = array_map(fn (Scope $scope) => $scope->id, $scopes);

        if ($requested === []) {
            return false;
        }

        $consent = UserConsent::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('client_id', $this->getKey())
            ->first();

        return $consent !== null && $consent->covers($requested);
    }
}
