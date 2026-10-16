<?php

namespace App\Services;

use App\Jobs\SendBackchannelLogoutJob;
use App\Models\User;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Laravel\Passport\Client;

/**
 * OIDC Back-Channel Logout 1.0：会话结束时向各 Client 的
 * backchannel_logout_uri POST 一个一次性 logout_token（RS256）。
 * 仅通知持有该用户有效令牌的 Client；网络失败由队列重试兜底。
 */
class BackchannelLogoutService
{
    /**
     * @return list<Client> 收到通知的 Client 列表
     */
    public function notifyForUser(User $user): array
    {
        $clients = Client::query()
            ->whereNotNull('backchannel_logout_uri')
            ->where('revoked', false)
            ->whereHas('tokens', fn ($query) => $query
                ->where('user_id', $user->getKey())
                ->where('revoked', false)
                ->where('expires_at', '>', now()))
            ->get();

        foreach ($clients as $client) {
            SendBackchannelLogoutJob::dispatch($client->getKey(), $user->getKey());
        }

        return $clients->all();
    }

    public function makeLogoutToken(Client $client, User $user): string
    {
        $now = now()->getTimestamp();

        return JWT::encode([
            'iss' => config('oidc-server.issuer') ?? config('app.url'),
            'aud' => $client->getKey(),
            'sub' => (string) $user->getKey(),
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => (string) Str::uuid(),
            'events' => ['http://openid.net/specs/connect-1.0-event:logout_token' => new \stdClass],
        ], file_get_contents(storage_path('oauth-private.key')), 'RS256');
    }

    public function send(Client $client, User $user): void
    {
        Http::timeout(5)
            ->asForm()
            ->post($client->backchannel_logout_uri, [
                'logout_token' => $this->makeLogoutToken($client, $user),
            ])
            ->throw();
    }
}
