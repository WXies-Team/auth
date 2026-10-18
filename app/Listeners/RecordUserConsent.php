<?php

namespace App\Listeners;

use Admin9\OidcServer\Events\OidcTokenIssued;
use App\Models\UserConsent;

/**
 * 记录「记住授权」：token 换发成功即视为用户对该 client 授了权。
 *
 * scope 取并集——refresh 时 scope 可能收窄，但用户此前同意过更大的集合，
 * 不应因此在下次授权时重新弹窗。用户在「已授权应用」撤销时删除记录。
 */
class RecordUserConsent
{
    public function handle(OidcTokenIssued $event): void
    {
        // client_credentials 等无用户流不记录授权。
        if ($event->userId === '' || $event->userId === null) {
            return;
        }

        try {
            $consent = UserConsent::query()->firstOrNew([
                'user_id' => $event->userId,
                'client_id' => $event->clientId,
            ]);

            $consent->scopes = array_values(array_unique(array_merge($consent->scopes ?? [], $event->scopes)));
            $consent->save();
        } catch (\Throwable $e) {
            // 记录授权失败不得让令牌端点 500——降级为下次重新弹同意屏。
            report($e);
        }
    }
}
