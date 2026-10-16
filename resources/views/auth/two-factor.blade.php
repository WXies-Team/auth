<x-layout title="两步验证">
    <div class="min-h-screen flex items-center justify-center px-4 py-10">
        <div class="w-full max-w-[380px]">
            <div class="text-center mb-8">
                <div class="mx-auto mb-4 w-14 h-14 rounded-full flex items-center justify-center text-2xl"
                     style="background: var(--color-surface-secondary)">🛡️</div>
                <h1 class="text-[22px] font-semibold tracking-tight">两步验证</h1>
                <p class="text-[15px] label-secondary mt-0.5">
                    @if ($useRecoveryCode)
                        输入一个未使用的恢复码
                    @else
                        输入验证器应用中的 6 位验证码
                    @endif
                </p>
            </div>

            <div class="card p-6">
                @if ($errors->any())
                    <div class="mb-4 rounded-xl bg-red-500/10 text-red-500 text-[15px] p-3">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ route('two-factor.store') }}" class="space-y-4">
                    @csrf
                    <input name="code" required autofocus autocomplete="one-time-code"
                           inputmode="{{ $useRecoveryCode ? 'text' : 'numeric' }}"
                           placeholder="{{ $useRecoveryCode ? 'XXXX-XXXX' : '000000' }}"
                           class="input text-center tracking-[0.4em] font-mono">
                    <button type="submit" class="btn-primary w-full">验证</button>
                </form>

                <div class="mt-4 text-center text-[15px]">
                    <a href="{{ $useRecoveryCode ? route('two-factor.show') : route('two-factor.show', ['recovery' => 1]) }}"
                       class="label-secondary hover:underline" style="color: var(--color-brand)">
                        {{ $useRecoveryCode ? '改用验证码' : '丢失设备？改用恢复码' }}
                    </a>
                </div>
            </div>
        </div>
    </div>
</x-layout>
