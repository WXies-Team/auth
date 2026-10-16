<x-layout>
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="text-center">
            <div class="mx-auto mb-5 w-16 h-16 rounded-[16px] flex items-center justify-center shadow-lg"
                 style="background: linear-gradient(135deg, #007aff, #5e5ce6);">
                <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <h1 class="text-[28px] font-semibold tracking-tight">统一登录网关</h1>

            @auth
                <p class="text-[15px] label-secondary mt-1 mb-6">已登录：{{ auth()->user()->name }}</p>

                <div class="flex flex-col gap-2.5 max-w-xs mx-auto">
                    <a href="{{ route('security.show') }}" class="btn-secondary w-full">安全设置</a>
                    <a href="{{ route('sessions.index') }}" class="btn-secondary w-full">已登录设备</a>
                    @can('access-admin')
                        <a href="{{ route('admin.dashboard') }}" class="btn-primary w-full">管理后台</a>
                    @endcan
                    <form method="POST" action="{{ route('logout') }}" class="mt-2">
                        @csrf
                        <button class="btn w-full" style="color: var(--color-red)">退出登录</button>
                    </form>
                </div>
            @else
                <p class="text-[15px] label-secondary mt-1 mb-6">一次登录，通行所有项目</p>
                <a href="{{ route('login') }}" class="btn-primary">开始登录</a>
            @endauth
        </div>
    </div>
</x-layout>
