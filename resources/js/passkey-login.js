import { Passkeys } from '@laravel/passkeys';

function follow(redirect) {
    if (redirect) {
        window.location.href = redirect;
    }
}

// ── 安全设置页：注册新 Passkey ──
const registerButton = document.querySelector('[data-passkey-register]');
registerButton?.addEventListener('click', async () => {
    const nameInput = document.querySelector('[data-passkey-name]');
    const errorBox = document.querySelector('[data-passkey-error]');
    const name = nameInput?.value?.trim() || 'Passkey';

    registerButton.disabled = true;
    errorBox?.classList.add('hidden');

    try {
        await Passkeys.register({ name });
        window.location.reload();
    } catch (error) {
        if (error?.name !== 'NotAllowedError' && errorBox) {
            errorBox.textContent = '添加失败：' + (error?.message || '请重试');
            errorBox.classList.remove('hidden');
        }
        registerButton.disabled = false;
    }
});

if (Passkeys.isSupported()) {
    const button = document.querySelector('[data-passkey-login]');

    button?.addEventListener('click', async () => {
        button.disabled = true;
        try {
            follow((await Passkeys.verify()).redirect);
        } catch {
            button.disabled = false; // 用户取消或错误，留在登录页
        }
    });

    // 浏览器条件式 UI（邮箱输入框锚定的 passkey 自动填充）
    Passkeys.isAutofillSupported().then((supported) => {
        if (supported) {
            Passkeys.autofill().then((response) => follow(response?.redirect)).catch(() => {});
        }
    });
}
