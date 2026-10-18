<x-layout title="找回密码">
    <div class="auth-scene flex items-center justify-center px-4 py-12">
        <div class="grain"></div>

        <div class="w-full max-w-[400px]">
            <div class="text-center mb-7">
                <div class="auth-mark mb-5 mx-auto">
                    <i data-lucide="key-round" class="w-7 h-7 text-white" stroke-width="1.8"></i>
                </div>
                <h1 class="text-[34px] font-semibold tracking-[-0.9px] leading-tight">找回密码</h1>
                <p class="auth-quiet text-[15px] mt-1.5">我们会发送重置链接到你的邮箱</p>
            </div>

            <div class="auth-card p-7">
                @if (session('status'))
                    <div class="auth-note-ok note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ session('status') }}
                    </div>
                @endif

                @if ($errors->any())
                    <div class="auth-note-error note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ route('password.email') }}" class="space-y-3">
                    @csrf

                    <input id="email" type="email" name="email" required value="{{ old('email') }}"
                           autocomplete="email" placeholder="邮箱" aria-label="邮箱" class="auth-input">

                    <button type="submit" class="auth-primary mt-1">发送重置链接</button>
                </form>

                <p class="text-center text-[15px] auth-quiet mt-6">
                    想起来了？
                    <a href="{{ route('login') }}" class="text-[var(--accent)] no-underline font-medium">返回登录</a>
                </p>
            </div>
        </div>
    </div>
</x-layout>
