<x-layout>
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="text-center">
            <div class="mx-auto mb-5 w-16 h-16 rounded-[14px] flex items-center justify-center text-3xl text-white shadow-lg"
                 style="background: linear-gradient(135deg, #007aff, #5e5ce6);">
                ⬢
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
