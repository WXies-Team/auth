import { Passkeys } from '@laravel/passkeys';

function follow(redirect) {
    if (redirect) {
        window.location.href = redirect;
    }
}

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
