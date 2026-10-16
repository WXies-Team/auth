<?php

namespace App\Services;

use App\Models\AuditLog;
use Illuminate\Support\Facades\Auth;

/**
 * 统一审计入口。所有敏感操作经此落库，永不抛错打断业务请求。
 */
class AuditLogger
{
    /**
     * @param  array<string, mixed>  $metadata
     */
    public function record(string $action, ?int $userId = null, ?string $targetType = null, ?int $targetId = null, array $metadata = []): void
    {
        AuditLog::create([
            'user_id' => $userId ?? Auth::id(),
            'action' => $action,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'ip' => request()?->ip(),
            'metadata' => $metadata ?: null,
            'created_at' => now(),
        ]);
    }
}
