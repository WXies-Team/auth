<x-layout title="审计日志">
    <x-top-nav active="admin" />
    <div class="max-w-5xl mx-auto py-12 px-4">
        <h1 class="text-[28px] font-semibold tracking-tight mt-2 mb-8">审计日志</h1>

        <div class="card overflow-x-auto" style="border-color: var(--color-separator)">
            <table class="w-full text-[15px]">
                <thead class="text-left text-[13px] label-tertiary uppercase">
                    <tr class="border-b separator">
                        <th class="px-4 py-3">时间</th>
                        <th class="px-4 py-3">操作</th>
                        <th class="px-4 py-3">用户</th>
                        <th class="px-4 py-3">目标</th>
                        <th class="px-4 py-3">IP</th>
                    </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--color-separator)">
                    @forelse ($logs as $log)
                        <tr>
                            <td class="px-4 py-2.5 label-secondary whitespace-nowrap">{{ $log->created_at->format('Y-m-d H:i:s') }}</td>
                            <td class="px-4 py-2.5 font-mono text-[13px]">{{ $log->action }}</td>
                            <td class="px-4 py-2.5">{{ $log->user?->email ?? '—' }}</td>
                            <td class="px-4 py-2.5 text-[13px] label-secondary">
                                @if ($log->target_type)
                                    <span class="font-mono">{{ $log->target_type }}#{{ $log->target_id }}</span>
                                @elseif ($log->metadata)
                                    <span class="font-mono">{{ \Illuminate\Support\Str::limit(json_encode($log->metadata, JSON_UNESCAPED_UNICODE), 80) }}</span>
                                @else
                                    —
                                @endif
                            </td>
                            <td class="px-4 py-2.5 label-secondary">{{ $log->ip ?: '—' }}</td>
                        </tr>
                    @empty
                        <tr><td colspan="5" class="p-10 text-center label-tertiary">暂无日志</td></tr>
                    @endforelse
                </tbody>
            </table>
        </div>

        <div class="mt-4">{{ $logs->links() }}</div>
    </div>
</x-layout>
