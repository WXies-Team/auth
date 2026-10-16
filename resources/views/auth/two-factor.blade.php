<x-layout title="两步验证">
    <div class="auth-scene flex items-center justify-center px-4 py-12" x-data="otpFlow()" x-cloak>
        <div class="grain"></div>

        <div class="w-full max-w-[400px]">
            <div class="text-center mb-7">
                <div class="auth-mark mb-5">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                </div>
                <h1 class="text-[30px] font-semibold tracking-[-0.6px] leading-tight">两步验证</h1>
                <p class="auth-quiet text-[15px] mt-1.5">
                    {{ $useRecoveryCode ? '输入一个未使用的恢复码' : '输入验证器应用中的 6 位验证码' }}
                </p>
            </div>

            <div class="auth-card rounded-[22px] p-7">


                <form method="POST" action="{{ route('two-factor.store') }}" id="otp-form">
                    @csrf

                    @if ($useRecoveryCode)
                        <input name="code" required autofocus autocomplete="one-time-code"
                               x-model="recovery" placeholder="XXXX-XXXX"
                               aria-label="恢复码"
                               class="auth-input text-center font-mono tracking-[0.2em]">
                    @else
                        <div class="flex justify-center gap-2.5" @paste="onPaste($event)">
                            <template x-for="i in 6" :key="i">
                                <input type="text" inputmode="numeric" maxlength="1" class="otp-box"
                                       :value="digits[i - 1] ?? ''"
                                       :aria-label="'验证码第 ' + i + ' 位'"
                                       @input="onInput($event, i - 1)"
                                       @keydown.backspace="onBackspace($event, i - 1)"
                                       @focus="$event.target.select()">
                            </template>
                        </div>
                        <input type="hidden" name="code" x-model="value">
                        @if ($errors->any())
                            <p class="text-[15px] text-center mt-4" style="color: #ff7b72">{{ $errors->first() }}</p>
                        @endif
                        <p class="text-center text-[13px] auth-faint mt-4">输满 6 位自动验证</p>
                    @endif

                    <button type="submit" class="auth-primary mt-6" :disabled="loading || submitting">
                        <span x-show="!submitting">验证</span>
                        <span x-show="submitting" class="inline-block w-4 h-4 rounded-full border-2 border-white/40 border-t-white animate-spin"></span>
                    </button>
                </form>

                <div class="mt-5 text-center text-[15px]">
                    <a href="{{ $useRecoveryCode ? route('two-factor.show') : route('two-factor.show', ['recovery' => 1]) }}"
                       class="text-blue-400 hover:text-blue-300 no-underline">
                        {{ $useRecoveryCode ? '改用验证码' : '丢失设备？改用恢复码' }}
                    </a>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
    <script>
        function otpFlow() {
            return {
                digits: Array(6).fill(''),
                value: '',
                recovery: '',
                submitting: false,
                get complete() {
                    return this.digits.join('').length === 6;
                },
                onInput(e, idx) {
                    const v = e.target.value.replace(/\D/g, '').slice(-1);
                    e.target.value = v;
                    this.digits[idx] = v;
                    if (v && idx < 5) {
                        e.target.parentElement.children[idx + 1]?.focus();
                    }
                    if (this.complete) this.submit();
                },
                onBackspace(e, idx) {
                    if (!e.target.value && idx > 0) {
                        this.digits[idx - 1] = '';
                        const prev = e.target.parentElement.children[idx - 1];
                        if (prev) { prev.value = ''; prev.focus(); }
                    }
                },
                onPaste(e) {
                    const pasted = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
                    if (!pasted) return;
                    e.preventDefault();
                    pasted.split('').forEach((c, i) => { this.digits[i] = c; });
                    this.value = this.digits.join('');
                    const boxes = e.currentTarget.querySelectorAll('input');
                    boxes[Math.min(pasted.length, 5)]?.focus();
                    if (this.complete) this.submit();
                },
                submit() {
                    this.value = this.digits.join('');
                    if (this.value.length !== 6) return;
                    this.submitting = true;
                    document.getElementById('otp-form').submit();
                },
                init() {
                    this.$el.querySelector('input')?.focus();
                    this.$el.querySelector('form')?.addEventListener('submit', () => { this.submitting = true; });
                },
            };
        }
    </script>
    @endpush
</x-layout>
