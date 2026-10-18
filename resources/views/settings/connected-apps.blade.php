<x-layout title="已授权应用">
    <x-app-shell active="apps">
    <div class="py-10 px-4">
        <div class="flex items-start justify-between mb-6 gap-4">
            <div>
                <h1 class="text-[28px] font-semibold tracking-[-0.5px]">已授权应用</h1>
                <p class="text-[15px] label-secondary mt-1">这些应用可以访问你的账号，你可以随时撤销</p>
            </div>
            @if ($apps->isNotEmpty())
                <form method="POST" action="{{ route('apps.revoke-all') }}"
                      onsubmit="return confirm('撤销后所有应用都需要重新授权，确定？')">
                    @csrf @method('DELETE')
                    <button class="btn-secondary whitespace-nowrap">全部撤销</button>
                </form>
            @endif
        </div>

        @if (session('status'))
            <div class="auth-note-ok note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                {{ session('status') }}
            </div>
        @endif

        @if ($apps->isEmpty())
            <div class="card p-10 text-center">
                <div class="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-4"
                     style="background: var(--fill-2)">
                    <i data-lucide="link-2-off" class="w-6 h-6 label-tertiary"></i>
                </div>
                <p class="text-[17px] font-medium">还没有授权任何应用</p>
                <p class="text-[15px] label-secondary mt-1">当你用其他项目登录时，会出现在这里</p>
            </div>
        @else
            <div class="space-y-3">
                @foreach ($apps as $app)
                    <section class="card p-5">
                        <div class="flex items-start justify-between gap-4">
                            <div class="min-w-0">
                                <div class="text-[17px] font-semibold truncate">{{ $app['client_name'] }}</div>
                                <div class="text-[13px] label-tertiary mt-0.5">
                                    授权于 {{ \Illuminate\Support\Carbon::parse($app['authorized_at'])->format('Y-m-d') }}
                                    · 最近使用 {{ \Illuminate\Support\Carbon::parse($app['last_used_at'])->diffForHumans() }}
                                </div>
                            </div>
                            <form method="POST" action="{{ route('apps.revoke', $app['client_id']) }}"
                                  onsubmit="return confirm('撤销后该应用将立即失去访问权限，需要重新授权才能继续使用。')">
                                @csrf @method('DELETE')
                                <button class="min-h-11 inline-flex items-center px-2 text-[15px] whitespace-nowrap hover:underline" style="color: var(--color-red)">撤销访问</button>
                            </form>
                        </div>

                        @if (count($app['scopes']) > 0)
                            <ul class="mt-4 space-y-2">
                                @foreach ($app['scopes'] as $scope)
                                    <li class="flex items-start gap-2.5 text-[15px] label-secondary">
                                        <span class="mt-0.5 w-4 h-4 rounded-full flex-shrink-0 flex items-center justify-center"
                                              style="background: color-mix(in srgb, var(--color-green) 15%, transparent)">
                                            <i data-lucide="check" class="w-2.5 h-2.5" style="color: var(--color-green)"></i>
                                        </span>
                                        <span>{{ config("scopes.$scope", $scope) }}</span>
                                    </li>
                                @endforeach
                            </ul>
                        @endif
                    </section>
                @endforeach
            </div>
        @endif
    </div>
    </x-app-shell>
</x-layout>
