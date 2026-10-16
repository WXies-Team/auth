<x-layout>
    @auth
        <x-app-shell active="home">
        <div class="py-1">
            {{-- 资料卡 --}}
            <div class="card p-6 flex items-center gap-4">
                <div class="w-14 h-14 rounded-full flex items-center justify-center text-white text-[22px] font-semibold shrink-0"
                     style="background: var(--accent)">
                    {{ mb_substr(auth()->user()->name, 0, 1) }}
                </div>
                <div class="min-w-0">
                    <div class="text-[19px] font-semibold truncate">{{ auth()->user()->name }}</div>
                    <div class="text-[15px] label-secondary truncate">{{ auth()->user()->email }}</div>
                </div>
            </div>

            {{-- 入口列表（分组行 + Lucide 图标 + chevron，iOS 设置惯例） --}}
            <div class="card mt-4 divide-y separator overflow-hidden">
                <a href="{{ route('security.show') }}" class="flex items-center gap-3.5 px-5 py-3.5 no-underline hover:bg-[var(--fill-2)] transition">
                    <i data-lucide="shield-check" class="w-5 h-5 text-[var(--accent)]"></i>
                    <span class="flex-1 text-[17px] text-[var(--ink)]">安全设置</span>
                    <span class="text-[15px] label-tertiary">{{ auth()->user()->hasTwoFactorEnabled() ? '已开启' : '未开启两步验证' }}</span>
                    <i data-lucide="chevron-right" class="w-4 h-4 label-tertiary"></i>
                </a>
                <a href="{{ route('sessions.index') }}" class="flex items-center gap-3.5 px-5 py-3.5 no-underline hover:bg-[var(--fill-2)] transition">
                    <i data-lucide="monitor" class="w-5 h-5 text-[var(--accent)]"></i>
                    <span class="flex-1 text-[17px] text-[var(--ink)]">已登录设备</span>
                    <i data-lucide="chevron-right" class="w-4 h-4 label-tertiary"></i>
                </a>
                @can('access-admin')
                    <a href="{{ route('admin.dashboard') }}" class="flex items-center gap-3.5 px-5 py-3.5 no-underline hover:bg-[var(--fill-2)] transition">
                        <i data-lucide="settings" class="w-5 h-5 text-[var(--accent)]"></i>
                        <span class="flex-1 text-[17px] text-[var(--ink)]">管理后台</span>
                        <i data-lucide="chevron-right" class="w-4 h-4 label-tertiary"></i>
                    </a>
                @endcan
            </div>

            <p class="text-center text-[13px] label-tertiary mt-8">统一登录网关 · 一次登录，通行所有项目</p>
        </div>
        </x-app-shell>
    @else
        <div class="auth-scene flex items-center justify-center px-4">
            <div class="grain"></div>
            <div class="text-center">
                <div class="auth-mark mb-6">
                    <i data-lucide="lock" class="w-7 h-7 text-white" stroke-width="1.8"></i>
                </div>
                <h1 class="text-[34px] font-semibold tracking-[-0.9px]">统一登录网关</h1>
                <p class="auth-quiet text-[15px] mt-2 mb-8">一次登录，通行所有项目</p>
                <a href="{{ route('login') }}" class="auth-primary no-underline w-[300px]">登录</a>
            </div>
        </div>
    @endauth
</x-layout>
