<x-layout>
    <div class="auth-scene flex items-center justify-center px-4" x-cloak>
        <div class="grain"></div>

        <div class="text-center">
            <div class="auth-mark mb-6">
                <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2.5"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <h1 class="text-[34px] font-semibold tracking-[-0.8px]">统一登录网关</h1>

            @auth
                <p class="auth-quiet text-[15px] mt-2 mb-8">已登录：{{ auth()->user()->name }}</p>

                <div class="flex flex-col gap-2.5 w-[300px] mx-auto">
                    <a href="{{ route('security.show') }}" class="auth-ghost">安全设置</a>
                    <a href="{{ route('sessions.index') }}" class="auth-ghost">已登录设备</a>
                    @can('access-admin')
                        <a href="{{ route('admin.dashboard') }}" class="auth-primary no-underline">管理后台</a>
                    @endcan
                    <form method="POST" action="{{ route('logout') }}" class="mt-3">
                        @csrf
                        <button class="auth-ghost" style="color: #ff7b72">退出登录</button>
                    </form>
                </div>
            @else
                <p class="auth-quiet text-[15px] mt-2 mb-8">一次登录，通行所有项目</p>
                <a href="{{ route('login') }}" class="auth-primary no-underline w-[300px]">开始登录</a>
            @endauth
        </div>
    </div>
</x-layout>
