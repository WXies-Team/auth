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
        try {
            AuditLog::create([
                'user_id' => $userId ?? Auth::id(),
                'action' => $action,
                'target_type' => $targetType,
                'target_id' => $targetId,
                'ip' => request()?->ip(),
                'metadata' => $metadata ?: null,
                'created_at' => now(),
            ]);
        } catch (\Throwable $e) {
            // 审计写入失败不得打断主流程（登录/授权/换 token）。
            // 降级为日志，保留可追查性——注释曾承诺"永不抛错"，此前未兑现。
            report($e);
        }
    }
}
