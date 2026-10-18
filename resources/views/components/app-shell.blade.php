@props(['active' => ''])
<div class="min-h-[100dvh]">
    {{-- 签名玻璃顶栏 --}}
    <header class="glass-bar">
        <div class="mx-auto max-w-[1100px] h-full px-4 flex items-center justify-between">
            <a href="{{ route('home') }}" class="flex items-center gap-2 no-underline">
                <span class="w-6 h-6 rounded-[6px] flex items-center justify-center" style="background: var(--accent)">
                    <i data-lucide="lock" class="w-3.5 h-3.5 text-white" stroke-width="2.2"></i>
                </span>
                <span class="text-white font-medium">统一登录网关</span>
            </a>
            <div class="flex items-center gap-4">
                <form method="POST" action="{{ route('logout') }}">
                    @csrf
                    <button class="flex items-center gap-1.5 hover:text-white/80 transition no-underline">
                        <i data-lucide="log-out" class="w-4 h-4"></i> 退出
                    </button>
                </form>
            </div>
        </div>
    </header>

    <div class="mx-auto max-w-[1100px] flex gap-6 px-4 pt-6 pb-20 md:pb-8">
        {{-- 桌面侧栏（≥md） --}}
        <aside class="hidden md:block w-48 shrink-0 sticky top-[64px] self-start space-y-1">
            <a href="{{ route('home') }}" class="side-link {{ $active === 'home' ? 'active' : '' }}">
                <i data-lucide="user" class="w-[18px] h-[18px]"></i> 账户
            </a>
            <a href="{{ route('security.show') }}" class="side-link {{ $active === 'security' ? 'active' : '' }}">
                <i data-lucide="shield-check" class="w-[18px] h-[18px]"></i> 安全设置
            </a>
            <a href="{{ route('sessions.index') }}" class="side-link {{ $active === 'sessions' ? 'active' : '' }}">
                <i data-lucide="monitor" class="w-[18px] h-[18px]"></i> 已登录设备
            </a>
            <a href="{{ route('apps.index') }}" class="side-link {{ $active === 'apps' ? 'active' : '' }}">
                <i data-lucide="link-2" class="w-[18px] h-[18px]"></i> 已授权应用
            </a>
            @can('access-admin')
                <a href="{{ route('admin.dashboard') }}" class="side-link {{ $active === 'admin' ? 'active' : '' }}">
                    <i data-lucide="settings" class="w-[18px] h-[18px]"></i> 管理后台
                </a>
            @endcan
        </aside>

        {{-- 主内容区（PC 端吃满横向空间） --}}
        <main class="flex-1 min-w-0 max-w-[760px]">{{ $slot }}</main>
    </div>

    {{-- 移动端底部标签栏（<md） --}}
    <nav class="tab-bar md:hidden flex">
        <a href="{{ route('home') }}" class="tab-link {{ $active === 'home' ? 'active' : '' }}">
            <i data-lucide="user" class="w-6 h-6"></i> 账户
        </a>
        <a href="{{ route('security.show') }}" class="tab-link {{ $active === 'security' ? 'active' : '' }}">
            <i data-lucide="shield-check" class="w-6 h-6"></i> 安全
        </a>
        <a href="{{ route('sessions.index') }}" class="tab-link {{ $active === 'sessions' ? 'active' : '' }}">
            <i data-lucide="monitor" class="w-6 h-6"></i> 设备
        </a>
        <a href="{{ route('apps.index') }}" class="tab-link {{ $active === 'apps' ? 'active' : '' }}">
            <i data-lucide="link-2" class="w-6 h-6"></i> 应用
        </a>
        @can('access-admin')
            <a href="{{ route('admin.dashboard') }}" class="tab-link {{ $active === 'admin' ? 'active' : '' }}">
                <i data-lucide="settings" class="w-6 h-6"></i> 管理
            </a>
        @endcan
    </nav>
</div>
