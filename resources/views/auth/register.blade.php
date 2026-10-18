<x-layout title="创建账号">
    <div class="auth-scene flex items-center justify-center px-4 py-12">
        <div class="grain"></div>

        <div class="w-full max-w-[400px]">
            <div class="text-center mb-7">
                <div class="auth-mark mb-5 mx-auto">
                    <i data-lucide="user-plus" class="w-7 h-7 text-white" stroke-width="1.8"></i>
                </div>
                <h1 class="text-[34px] font-semibold tracking-[-0.9px] leading-tight">创建账号</h1>
                <p class="auth-quiet text-[15px] mt-1.5">一次注册，通行所有项目</p>
            </div>

            <div class="auth-card p-7">
                @if ($errors->any())
                    <div class="auth-note-error note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ route('register') }}" class="space-y-3">
                    @csrf

                    <input id="name" type="text" name="name" required value="{{ old('name') }}"
                           autocomplete="name" placeholder="昵称" aria-label="昵称" class="auth-input">

                    <input id="email" type="email" name="email" required value="{{ old('email') }}"
                           autocomplete="email webauthn" placeholder="邮箱" aria-label="邮箱" class="auth-input">

                    <input id="password" type="password" name="password" required
                           autocomplete="new-password" placeholder="密码（至少 8 位）" aria-label="密码"
                           class="auth-input">

                    <input id="password_confirmation" type="password" name="password_confirmation" required
                           autocomplete="new-password" placeholder="确认密码" aria-label="确认密码"
                           class="auth-input">

                    <button type="submit" class="auth-primary mt-1">创建账号</button>
                </form>

                <p class="text-center text-[15px] auth-quiet mt-6">
                    已有账号？
                    <a href="{{ route('login') }}" class="text-[var(--accent)] no-underline font-medium">去登录</a>
                </p>
            </div>
        </div>
    </div>
</x-layout>
