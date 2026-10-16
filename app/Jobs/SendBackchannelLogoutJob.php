<?php

namespace App\Jobs;

use App\Models\User;
use App\Services\BackchannelLogoutService;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Laravel\Passport\Client;

class SendBackchannelLogoutJob implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    /** @var list<int> */
    public array $backoff = [10, 60, 300];

    public function __construct(
        public string $clientId,
        public int $userId,
    ) {}

    public function handle(BackchannelLogoutService $service): void
    {
        $client = Client::find($this->clientId);
        $user = User::find($this->userId);

        if (! $client || ! $user || ! $client->backchannel_logout_uri) {
            return;
        }

        // 通知失败绝不打断宿主登出（RP 侧最终靠 token 吊销兜底）。
        try {
            $service->send($client, $user);
        } catch (\Throwable $e) {
            report($e);
        }
    }
}
