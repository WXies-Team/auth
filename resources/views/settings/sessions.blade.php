<x-layout title="已登录设备">
    <x-top-nav active="sessions" />
    <div class="max-w-xl mx-auto py-10 px-4">
        <div class="flex items-center justify-between mb-6">
            <h1 class="text-[28px] font-semibold tracking-tight">已登录设备</h1>
            <form method="POST" action="{{ route('sessions.destroy-others') }}"
                  onsubmit="return confirm('将下线除当前设备外的所有登录会话，确定？')">
                @csrf @method('DELETE')
                <button class="btn-secondary text-[15px]" style="color: var(--color-red)">下线其他全部</button>
            </form>
        </div>

        @if (session('status'))
            <div class="mb-4 rounded-xl p-3 text-[15px]"
                 style="background: color-mix(in srgb, var(--color-green) 12%, transparent); color: var(--color-green)">
                {{ session('status') }}
            </div>
        @endif

        <div class="card divide-y" style="border-color: var(--color-separator)">
            @forelse ($sessions as $session)
                <div class="flex items-center justify-between p-4">
                    <div class="text-[15px] min-w-0">
                        <div class="font-medium">
                            {{ \Illuminate\Support\Str::limit($session->user_agent ?: '未知设备', 60) }}
                            @if ($session->id === $currentId)
                                <span class="ml-2 text-[13px] font-medium px-2 py-0.5 rounded-full"
                                      style="background: color-mix(in srgb, var(--color-green) 15%, transparent); color: var(--color-green)">当前设备</span>
                            @endif
                        </div>
                        <div class="text-[13px] label-tertiary mt-0.5">
                            IP {{ $session->ip ?: '未知' }} · 最后活跃 {{ $session->last_active_at->diffForHumans() }}
                        </div>
                    </div>
                    <form method="POST" action="{{ route('sessions.destroy', $session) }}">
                        @csrf @method('DELETE')
                        <button class="text-[15px] flex-shrink-0 hover:underline" style="color: var(--color-red)">下线</button>
                    </form>
                </div>
            @empty
                <div class="p-10 text-center label-tertiary text-[15px]">暂无记录</div>
            @endforelse
        </div>
    </div>
</x-layout>
