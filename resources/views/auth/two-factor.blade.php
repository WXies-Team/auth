<x-layout title="两步验证">
    <div class="min-h-screen flex items-center justify-center px-4 py-10"
         x-data="otpFlow()" x-cloak>
        <div class="w-full max-w-[380px]">
            <div class="text-center mb-8">
                <div class="mx-auto mb-4 w-14 h-14 rounded-full flex items-center justify-center"
                     style="background: var(--color-surface-secondary)">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--color-label-secondary)"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                </div>
                <h1 class="text-[22px] font-semibold tracking-tight">两步验证</h1>
                <p class="text-[15px] label-secondary mt-0.5">
                    {{ $useRecoveryCode ? '输入一个未使用的恢复码' : '输入验证器应用中的 6 位验证码' }}
                </p>
            </div>

            <div class="card p-6">
                @if ($errors->any())
                    <div x-data x-transition.opacity.duration.200ms
                         class="mb-4 rounded-xl p-3 text-[15px]"
                         style="background: color-mix(in srgb, var(--color-red) 10%, transparent); color: var(--color-red)">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ route('two-factor.store') }}" id="otp-form">
                    @csrf

                    @if ($useRecoveryCode)
                        <input name="code" required autofocus autocomplete="one-time-code"
                               x-model="recovery" placeholder="XXXX-XXXX"
                               class="input text-center font-mono tracking-widest">
                    @else
                        {{-- 6 位分格输入：自动前进、支持粘贴、输满自动提交 --}}
                        <div class="flex justify-center gap-2.5 mb-2" @paste="onPaste($event)">
                            <template x-for="i in 6" :key="i">
                                <input type="text" inputmode="numeric" maxlength="1"
                                       :value="digits[i - 1] ?? ''"
                                       @input="onInput($event, i - 1)"
                                       @keydown.backspace="onBackspace($event, i - 1)"
                                       @focus="$event.target.select()"
                                       class="w-11 h-13 text-center text-[22px] font-semibold rounded-xl border
                                              focus:outline-none focus:ring-2 focus:ring-[var(--color-brand)]
                                              transition"
                                       style="background: var(--color-surface); border-color: var(--color-separator); color: var(--color-label)">
                            </template>
                        </div>
                        <input type="hidden" name="code" x-model="value">
                        <p class="text-center text-[13px] label-tertiary mt-3">输满 6 位自动验证</p>
                    @endif

                    <button type="submit" class="btn-primary w-full mt-5" :disabled="loading || submitting">
                        <span x-show="!submitting">验证</span>
                        <span x-show="submitting" class="inline-block w-4 h-4 rounded-full border-2 border-white/40 border-t-white animate-spin"></span>
                    </button>
                </form>

                <div class="mt-4 text-center text-[15px]">
                    <a href="{{ $useRecoveryCode ? route('two-factor.show') : route('two-factor.show', ['recovery' => 1]) }}"
                       style="color: var(--color-brand)" class="hover:underline">
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
                        e.target.parentElement.children[idx - 1]?.focus();
                        e.target.parentElement.children[idx - 1] && (e.target.parentElement.children[idx - 1].value = '');
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
                    // 恢复码模式：回车即提交
                    this.$el.querySelector('form')?.addEventListener('submit', () => { this.submitting = true; });
                },
            };
        }
    </script>
    @endpush
</x-layout>
