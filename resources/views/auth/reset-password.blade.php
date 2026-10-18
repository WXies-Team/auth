<x-layout title="重置密码">
    <div class="auth-scene flex items-center justify-center px-4 py-12">
        <div class="grain"></div>

        <div class="w-full max-w-[400px]">
            <div class="text-center mb-7">
                <div class="auth-mark mb-5 mx-auto">
                    <i data-lucide="rotate-ccw-key" class="w-7 h-7 text-white" stroke-width="1.8"></i>
                </div>
                <h1 class="text-[34px] font-semibold tracking-[-0.9px] leading-tight">设置新密码</h1>
                <p class="auth-quiet text-[15px] mt-1.5">为 {{ $email }} 设置新密码</p>
            </div>

            <div class="auth-card p-7">
                @if ($errors->any())
                    <div class="auth-note-error note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ route('password.update') }}" class="space-y-3">
                    @csrf
                    <input type="hidden" name="token" value="{{ $token }}">
                    <input type="hidden" name="email" value="{{ $email }}">

                    <input id="password" type="password" name="password" required
                           autocomplete="new-password" placeholder="新密码（至少 8 位）" aria-label="新密码"
                           class="auth-input">

                    <input id="password_confirmation" type="password" name="password_confirmation" required
                           autocomplete="new-password" placeholder="确认新密码" aria-label="确认新密码"
                           class="auth-input">

                    <button type="submit" class="auth-primary mt-1">重置密码</button>
                </form>
            </div>
        </div>
    </div>
</x-layout>
