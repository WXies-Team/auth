@props(['active' => ''])
<header class="nav-material sticky top-0 z-40">
    <div class="max-w-3xl mx-auto px-4 h-[52px] flex items-center justify-between gap-4">
        <a href="{{ route('home') }}" class="flex items-center gap-2.5 no-underline shrink-0">
            <span class="w-7 h-7 rounded-[7px] flex items-center justify-center" style="background: var(--accent)">
                <i data-lucide="lock" class="w-4 h-4 text-white" stroke-width="2"></i>
            </span>
            <span class="text-[15px] font-semibold text-[var(--ink)]">统一登录网关</span>
        </a>
        <nav class="flex items-center gap-1 text-[15px]">
            <a href="{{ route('home') }}"
               class="px-3 py-1.5 rounded-full no-underline transition {{ $active === 'home' ? 'font-medium text-[var(--ink)]' : 'text-[var(--ink-2)] hover:text-[var(--ink)]' }}"
               @if($active === 'home') style="background: var(--fill-2)" @endif>首页</a>
            <a href="{{ route('security.show') }}"
               class="px-3 py-1.5 rounded-full no-underline transition {{ $active === 'security' ? 'font-medium text-[var(--ink)]' : 'text-[var(--ink-2)] hover:text-[var(--ink)]' }}"
               @if($active === 'security') style="background: var(--fill-2)" @endif>安全</a>
            <a href="{{ route('sessions.index') }}"
               class="px-3 py-1.5 rounded-full no-underline transition {{ $active === 'sessions' ? 'font-medium text-[var(--ink)]' : 'text-[var(--ink-2)] hover:text-[var(--ink)]' }}"
               @if($active === 'sessions') style="background: var(--fill-2)" @endif>设备</a>
            @can('access-admin')
                <a href="{{ route('admin.dashboard') }}"
                   class="px-3 py-1.5 rounded-full no-underline transition {{ $active === 'admin' ? 'font-medium text-[var(--ink)]' : 'text-[var(--ink-2)] hover:text-[var(--ink)]' }}"
                   @if($active === 'admin') style="background: var(--fill-2)" @endif>管理</a>
            @endcan
            <form method="POST" action="{{ route('logout') }}" class="ml-1.5">
                @csrf
                <button class="px-3 py-1.5 rounded-full text-[15px] no-underline transition text-[var(--ink-2)] hover:text-[var(--ink)]">退出</button>
            </form>
        </nav>
    </div>
</header>
