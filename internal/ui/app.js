/* Auth 管理台脚本 —— 内联，零外链。
   约定：
   - 所有写请求带 X-CSRF-Token（从可读 cookie 取）+ 同源 credentials；
   - 401「需要重新验证」→ 弹重新验证框，验过自动重试原请求；401「登录已过期」→ 回登录页；
   - 动态数据一律走 textContent / 转义后才进 innerHTML（邮箱、设备名来自用户与 UA）。 */
'use strict';

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function cookie(name) {
  const hit = document.cookie.split('; ').find(c => c.startsWith(name + '='));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : '';
}

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function node(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function fmtTime(ms) {
  if (!ms) return '—';
  const d = new Date(Number(ms));
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function relTime(ms) {
  if (!ms) return '—';
  const diff = Date.now() - Number(ms);
  const min = Math.floor(diff / 60000);
  if (min < 1) return '刚刚';
  if (min < 60) return `${min} 分钟前`;
  const hour = Math.floor(min / 60);
  if (hour < 24) return `${hour} 小时前`;
  const day = Math.floor(hour / 24);
  if (day < 30) return `${day} 天前`;
  return fmtTime(ms);
}

let toastTimer = null;
function toast(msg, bad) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle('bad', !!bad);
  el.hidden = false;
  requestAnimationFrame(() => el.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => { el.hidden = true; }, 200);
  }, 2600);
}

function showErr(sel, msg) {
  const el = $(sel);
  if (!el) return;
  el.textContent = msg || '';
  el.hidden = !msg;
}

function setBusy(btn, busy) {
  if (!btn) return;
  btn.setAttribute('aria-busy', busy ? 'true' : 'false');
  btn.disabled = !!busy;
}

/* ---------- 重新验证弹框 ---------- */
let reauthResolver = null;

function promptReauth() {
  return new Promise(resolve => {
    const dlg = $('#reauth');
    if (!dlg) { resolve(false); return; }
    reauthResolver = resolve;
    showErr('#reauth-error', '');
    $('#reauth-password').value = '';
    $('#reauth-code').value = '';
    if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
    $('#reauth-password').focus();
  });
}

function closeReauth(ok) {
  const dlg = $('#reauth');
  if (dlg && dlg.open) dlg.close();
  if (reauthResolver) { reauthResolver(ok); reauthResolver = null; }
}

function wireReauth() {
  const form = $('#reauth-form');
  if (!form) return;
  $('#reauth-cancel').addEventListener('click', () => closeReauth(false));
  $('#reauth').addEventListener('cancel', e => { e.preventDefault(); closeReauth(false); });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const password = $('#reauth-password').value;
    const totpCode = $('#reauth-code').value;
    if (!password && !totpCode) { showErr('#reauth-error', '请输入密码或两步验证码'); return; }
    const btn = $('#reauth-ok');
    setBusy(btn, true);
    try {
      await api('/web/reauth', { method: 'POST', body: { password, totpCode }, noReauth: true });
      closeReauth(true);
    } catch (err) {
      showErr('#reauth-error', err.message);
    } finally {
      setBusy(btn, false);
    }
  });
}

/* ---------- 统一请求 ---------- */
async function api(path, opts) {
  const o = opts || {};
  const headers = { 'Accept': 'application/json' };
  if (o.body !== undefined) headers['Content-Type'] = 'application/json';
  const token = cookie('__Host-auth_web_csrf');
  if (token) headers['X-CSRF-Token'] = token;

  const res = await fetch(path, {
    method: o.method || 'GET',
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    body: o.body === undefined ? undefined : JSON.stringify(o.body),
  });

  let data = null;
  const text = await res.text();
  if (text) { try { data = JSON.parse(text); } catch (_) { /* 非 JSON（页面被拦截时）留空 */ } }

  if (!res.ok) {
    const msg = (data && data.message) || `请求失败（${res.status}）`;
    if (res.status === 401 && msg.indexOf('重新验证') >= 0 && !o.noReauth && !o._retried) {
      if (await promptReauth()) {
        return api(path, Object.assign({}, o, { _retried: true }));
      }
      const e0 = new Error('已取消重新验证'); e0.status = 401; e0.cancelled = true; throw e0;
    }
    if (res.status === 401 && msg.indexOf('重新验证') < 0) {
      location.href = '/web/login';
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

/* 会话里的 app 取值 → 展示名（未知值原样显示，不猜） */
const APP_LABEL = { web: '网页', 'calorie-diary': '热量日记', 'expense-diary': '开支日记' };
const appLabel = v => APP_LABEL[v] || v;

/* 管理页守卫：先确认自己真的是管理员，再让各页发起数据请求；
   角色不符直接回概览（数据层的 requireAdmin 还会逐请求再挡一次）。 */
async function initAdminGuard() {
  if (location.pathname.indexOf('/web/admin') !== 0) return;
  try {
    const me = await api('/web/session', { method: 'POST', body: {} });
    window.__meUid = me.uid;
    if (me.role !== 'admin') location.href = '/web/console';
  } catch (_) { /* 401 时 api() 已经跳登录页 */ }
}

/* ---------- 登录页 ---------- */
function initLogin() {
  if (!$('#login-card')) return;

  const tabs = { 'tab-password': 'pane-password', 'tab-code': 'pane-code', 'tab-reset': 'pane-reset' };
  Object.keys(tabs).forEach(id => {
    $('#' + id).addEventListener('click', () => {
      Object.keys(tabs).forEach(other => {
        const on = other === id;
        $('#' + other).setAttribute('aria-selected', on ? 'true' : 'false');
        $('#' + tabs[other]).classList.toggle('hidden', !on);
      });
      showErr('#login-error', ''); showErr('#code-error', ''); showErr('#reset-error', '');
    });
  });

  // ---- 密码 →（2FA）两步 ----
  let loginToken = '';
  const stepPwd = $('#step-password'), stepTotp = $('#step-totp');
  function useTotpStep(on) {
    stepPwd.classList.toggle('hidden', on);
    stepTotp.classList.toggle('hidden', !on);
    $('#login-submit').textContent = on ? '完成登录' : '登录';
    if (on) $('#login-code-2fa').focus();
  }
  $('#back-to-password').addEventListener('click', () => { loginToken = ''; useTotpStep(false); });

  $('#pane-password').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#login-error', '');
    const btn = $('#login-submit');
    setBusy(btn, true);
    try {
      if (!loginToken) {
        const res = await api('/web/login/password', {
          method: 'POST',
          body: { email: $('#login-email').value.trim(), password: $('#login-password').value },
        });
        if (res.status === '2fa_required') {
          loginToken = res.loginToken;
          useTotpStep(true);
          return;
        }
        location.href = '/web/console';
        return;
      }
      // 二选一：填了恢复码就走恢复码路，否则走 6 位码
      const recovery = $('#login-recovery').value.trim();
      const code = $('#login-code-2fa').value.trim();
      await api('/web/login/totp', {
        method: 'POST',
        body: { loginToken, code: recovery ? '' : code, recoveryCode: recovery },
      });
      location.href = '/web/console';
    } catch (err) {
      showErr('#login-error', err.message);
      if (loginToken && err.message.indexOf('过期') >= 0) { loginToken = ''; useTotpStep(false); }
    } finally {
      setBusy(btn, false);
    }
  });

  // ---- 发码（验证码登录 / 找回密码）：60 秒冷却 ----
  function cooldown(btn, seconds) {
    let left = seconds;
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = `${left} 秒后重发`;
    const t = setInterval(() => {
      left -= 1;
      if (left <= 0) { clearInterval(t); btn.disabled = false; btn.textContent = original; }
      else btn.textContent = `${left} 秒后重发`;
    }, 1000);
  }
  async function sendCode(email, purpose, errSel, btn) {
    showErr(errSel, '');
    if (!email) { showErr(errSel, '请先填写邮箱'); return; }
    try {
      await api('/auth/send-code', { method: 'POST', body: { email, purpose } });
      cooldown(btn, 60);
      toast('验证码已发送，没收到可查看垃圾箱');
    } catch (err) { showErr(errSel, err.message); }
  }
  $('#send-code').addEventListener('click', () =>
    sendCode($('#code-email').value.trim(), 'login', '#code-error', $('#send-code')));
  $('#send-reset-code').addEventListener('click', () =>
    sendCode($('#reset-email').value.trim(), 'reset', '#reset-error', $('#send-reset-code')));

  $('#pane-code').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#code-error', '');
    try {
      await api('/web/login/email-code', {
        method: 'POST',
        body: { email: $('#code-email').value.trim(), code: $('#code-code').value.trim() },
      });
      location.href = '/web/console';
    } catch (err) { showErr('#code-error', err.message); }
  });

  $('#pane-reset').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#reset-error', '');
    try {
      await api('/auth/reset-password', {
        method: 'POST',
        body: {
          email: $('#reset-email').value.trim(),
          code: $('#reset-code').value.trim(),
          password: $('#reset-password').value,
        },
      });
      toast('密码已重置，请用新密码登录');
      $('#tab-password').click();
      $('#login-email').value = $('#reset-email').value.trim();
    } catch (err) { showErr('#reset-error', err.message); }
  });

  // ---- Passkey 登录（不支持则整个入口隐藏，不摆死按钮）----
  const supportsPasskey = !!(window.PublicKeyCredential && navigator.credentials);
  $('#passkey-login').hidden = !supportsPasskey;
  $('#passkey-sep').hidden = !supportsPasskey;
  if (supportsPasskey) {
    $('#passkey-login').addEventListener('click', async () => {
      showErr('#passkey-error', '');
      const btn = $('#passkey-login');
      setBusy(btn, true);
      try {
        const opts = await api('/webauthn/login/options', { method: 'POST', body: {} });
        const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
        await api('/webauthn/login/finish', {
          method: 'POST',
          body: { ceremonyId: opts.ceremonyId, response: assertionJSON(cred) },
        });
        location.href = '/web/console';
      } catch (err) {
        if (err && err.name === 'NotAllowedError') return; // 用户取消不报错
        showErr('#passkey-error', (err && err.message) || 'Passkey 验证失败，请重试');
      } finally { setBusy(btn, false); }
    });
  }
}

/* ---------- WebAuthn：把浏览器对象转成服务端库解析的 JSON 形状 ---------- */
function b64url(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function creationJSON(cred) {
  return {
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64url(cred.response.clientDataJSON),
      attestationObject: b64url(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

function assertionJSON(cred) {
  return {
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64url(cred.response.clientDataJSON),
      authenticatorData: b64url(cred.response.authenticatorData),
      signature: b64url(cred.response.signature),
      userHandle: cred.response.userHandle ? b64url(cred.response.userHandle) : undefined,
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

/* ---------- 概览 ---------- */
async function initConsole() {
  if (!$('#me-email')) return;
  try {
    const me = await api('/web/session', { method: 'POST', body: {} });
    $('#me-email').textContent = me.email;
    if (me.role === 'admin') {
      $('#role-badge').hidden = false;
      $('#enter-admin').classList.remove('hidden');
    }
    $('#stat-password').textContent = me.passwordSet ? '已设置' : '未设置（该账号靠验证码或 Passkey 登录）';

    const totp = await api('/api/totp');
    $('#stat-totp').textContent = totp.enabled ? '已开启' : '未开启';
    const keys = await api('/api/passkeys');
    $('#stat-passkey').textContent = keys.length ? `${keys.length} 个` : '未添加';
  } catch (err) {
    if (err.status !== 401) toast(err.message, true);
    return;
  }

  $('#logout').addEventListener('click', async () => {
    try { await api('/web/logout', { method: 'POST', body: {} }); } catch (_) { /* 已登出也要跳 */ }
    location.href = '/web/login';
  });
}

/* ---------- 已登录设备 ---------- */
function initSessions() {
  const list = $('#session-list');
  if (!list) return;
  let rows = [];
  let pending = { mode: 'one', id: 0, label: '' };

  async function load() {
    try {
      rows = await api('/api/sessions');
    } catch (err) {
      list.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
      return;
    }
    if (!rows.length) {
      list.innerHTML = '<div class="empty">暂无记录</div>';
      return;
    }
    list.innerHTML = '';
    rows.forEach(it => {
      const el = node(`
        <div class="item">
          <span class="grow">
            <span class="title">${esc(it.device || '未知设备')}</span>
            ${it.current ? '<span class="badge on">本机</span>' : ''}
            <br><span class="meta">${esc(appLabel(it.app))} · ${esc(it.ip)} · 最近活跃 ${esc(relTime(it.lastSeenAt))}</span>
          </span>
          ${it.current ? '' : '<button type="button" class="btn small danger">踢出</button>'}
        </div>`);
      const kick = el.querySelector('button');
      if (kick) {
        kick.addEventListener('click', () => {
          pending = { mode: 'one', id: it.id, label: it.device };
          $('#kick-desc').textContent = `将「${it.device}」移出已登录设备，它下次请求时会退出登录。`;
          openDialog($('#kick-dialog'));
        });
      }
      list.appendChild(el);
    });
  }

  $('#revoke-others').addEventListener('click', () => {
    pending = { mode: 'others', id: 0, label: '' };
    const others = rows.filter(r => !r.current).length;
    $('#kick-desc').textContent = others
      ? `将退出除本机外的 ${others} 台设备，本机保持登录。`
      : '没有其它设备需要退出。';
    openDialog($('#kick-dialog'));
  });
  $('#kick-cancel').addEventListener('click', () => closeDialog($('#kick-dialog')));
  $('#kick-ok').addEventListener('click', async () => {
    const dlg = $('#kick-dialog');
    try {
      if (pending.mode === 'one') {
        await api('/api/sessions/' + pending.id, { method: 'DELETE' });
        const kickedSelf = rows.some(r => r.id === pending.id && r.current);
        closeDialog(dlg);
        if (kickedSelf) { location.href = '/web/login'; return; }
        toast('已踢出该设备');
      } else {
        await api('/api/sessions/revoke-others', { method: 'POST', body: {} });
        closeDialog(dlg);
        toast('已退出其它设备');
      }
      await load();
    } catch (err) {
      closeDialog(dlg);
      toast(err.message, true);
    }
  });

  load();
}

/* ---------- Passkey 管理 ---------- */
function initPasskeys() {
  const list = $('#passkey-list');
  if (!list) return;
  let pendingDel = 0;

  async function load() {
    try {
      const rows = await api('/api/passkeys');
      if (!rows.length) {
        list.innerHTML = '<div class="empty">还没有 Passkey，点击右上角「添加 Passkey」创建一个。</div>';
        return;
      }
      list.innerHTML = '';
      rows.forEach(it => {
        const el = node(`
          <div class="item" data-id="${it.id}">
            <span class="grow">
              <span class="title pk-name">${esc(it.name)}</span>
              ${it.current ? '<span class="badge on">本机登录所用</span>' : ''}
              <br><span class="meta">添加于 ${esc(fmtTime(it.createdAt))} · 最近使用 ${esc(relTime(it.lastUsedAt))}</span>
            </span>
            <span class="row" style="gap:6px">
              <button type="button" class="btn small" data-act="rename">改名</button>
              <button type="button" class="btn small danger" data-act="del">删除</button>
            </span>
          </div>`);
        el.querySelector('[data-act=rename]').addEventListener('click', () => startRename(el, it));
        el.querySelector('[data-act=del]').addEventListener('click', () => {
          pendingDel = it.id;
          $('#del-desc').textContent = `删除「${it.name}」后，这把 Passkey 立即不能再用来登录。`;
          openDialog($('#del-dialog'));
        });
        list.appendChild(el);
      });
    } catch (err) {
      list.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
    }
  }

  // 改名：就地把名字换成输入框（不弹窗，行内操作最省事）
  function startRename(el, it) {
    const nameEl = el.querySelector('.pk-name');
    if (el.querySelector('input')) return;
    const input = document.createElement('input');
    input.type = 'text';
    input.value = it.name;
    input.maxLength = 64;
    input.setAttribute('aria-label', 'Passkey 名称');
    nameEl.replaceWith(input);
    input.focus();
    const commit = async () => {
      try {
        await api('/api/passkeys/' + it.id, { method: 'PATCH', body: { name: input.value } });
        toast('已改名');
        await load();
      } catch (err) { toast(err.message, true); }
    };
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); commit(); }
      if (e.key === 'Escape') { e.preventDefault(); load(); }
    });
    input.addEventListener('blur', commit);
  }

  $('#add-passkey').addEventListener('click', async () => {
    showErr('#passkey-error', '');
    const btn = $('#add-passkey');
    if (!(window.PublicKeyCredential && navigator.credentials)) {
      showErr('#passkey-error', '当前浏览器不支持 Passkey，请换用 Chrome、Safari 或 Edge 的新版本');
      return;
    }
    setBusy(btn, true);
    try {
      const opts = await api('/webauthn/register/options', { method: 'POST', body: {} });
      const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
      if (!cred) return; // 用户取消
      await api('/webauthn/register/finish', {
        method: 'POST',
        body: { ceremonyId: opts.ceremonyId, response: creationJSON(cred) },
      });
      toast('Passkey 已添加');
      await load();
    } catch (err) {
      if (err && err.name === 'NotAllowedError') return;
      showErr('#passkey-error', (err && err.message) || '添加失败，请重试');
    } finally { setBusy(btn, false); }
  });

  $('#del-cancel').addEventListener('click', () => closeDialog($('#del-dialog')));
  $('#del-ok').addEventListener('click', async () => {
    try {
      await api('/api/passkeys/' + pendingDel, { method: 'DELETE' });
      toast('已删除');
      closeDialog($('#del-dialog'));
      await load();
    } catch (err) {
      closeDialog($('#del-dialog'));
      toast(err.message, true);
    }
  });

  load();
}

/* ---------- 两步验证 ---------- */
function initSecurity() {
  if (!$('#totp-badge')) return;
  let codes = [];

  async function refresh() {
    const st = await api('/api/totp');
    $('#totp-badge').textContent = st.enabled ? '已开启' : '未开启';
    $('#totp-badge').classList.toggle('on', st.enabled);
    $('#totp-off').hidden = st.enabled;
    $('#totp-on').hidden = !st.enabled;
    if (st.enabled) $('#totp-since').textContent = '开启时间：' + fmtTime(st.createdAt);
  }

  function showCodes(list) {
    codes = list;
    const box = $('#codes-list');
    box.innerHTML = '';
    list.forEach(c => {
      const el = document.createElement('span');
      el.textContent = c;
      box.appendChild(el);
    });
    $('#setup-panel').classList.add('hidden');
    $('#codes-panel').classList.remove('hidden');
  }

  $('#start-setup').addEventListener('click', async () => {
    showErr('#setup-error', '');
    try {
      const setup = await api('/api/totp/setup', { method: 'POST', body: {} });
      $('#qr-img').src = setup.qrPng;
      $('#setup-secret').textContent = setup.secret;
      $('#setup-code').value = '';
      $('#setup-panel').classList.remove('hidden');
      $('#setup-code').focus();
    } catch (err) { toast(err.message, true); }
  });
  $('#cancel-setup').addEventListener('click', () => $('#setup-panel').classList.add('hidden'));
  $('#copy-secret').addEventListener('click', async () => {
    await copyText($('#setup-secret').textContent);
    toast('密钥已复制');
  });
  $('#confirm-setup').addEventListener('click', async () => {
    showErr('#setup-error', '');
    const btn = $('#confirm-setup');
    setBusy(btn, true);
    try {
      const res = await api('/api/totp/enable', { method: 'POST', body: { code: $('#setup-code').value.trim() } });
      showCodes(res.recoveryCodes);
      await refresh();
    } catch (err) { showErr('#setup-error', err.message); } finally { setBusy(btn, false); }
  });

  $('#copy-codes').addEventListener('click', async () => {
    await copyText(codes.join('\n'));
    toast('恢复码已复制');
  });
  $('#download-codes').addEventListener('click', () => {
    const blob = new Blob([codes.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'auth-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $('#saved-codes').addEventListener('click', () => {
    $('#codes-panel').classList.add('hidden');
    codes = [];
    toast('恢复码已保存到本页，离开后无法再查看');
  });

  // 通用「要一个码」弹框
  let codeResolver = null;
  function askCode(title, desc) {
    $('#code-title').textContent = title;
    $('#code-desc').textContent = desc;
    $('#code-input').value = '';
    showErr('#code-error', '');
    openDialog($('#code-dialog'));
    $('#code-input').focus();
    return new Promise(resolve => { codeResolver = resolve; });
  }
  $('#code-cancel').addEventListener('click', () => {
    closeDialog($('#code-dialog'));
    if (codeResolver) { codeResolver(''); codeResolver = null; }
  });
  $('#code-form').addEventListener('submit', async e => {
    e.preventDefault();
    const value = $('#code-input').value.trim();
    if (!value) { showErr('#code-error', '请输入验证码'); return; }
    if (codeResolver) { codeResolver(value); codeResolver = null; }
    closeDialog($('#code-dialog'));
  });

  $('#regen-codes').addEventListener('click', async () => {
    const code = await askCode('重生成恢复码', '输入当前验证码或一个恢复码，旧的 10 个会全部作废。');
    if (!code) return;
    try {
      const res = await api('/api/totp/regenerate-recovery-codes', { method: 'POST', body: { code } });
      showCodes(res.recoveryCodes);
      toast('已换发，旧恢复码全部作废');
    } catch (err) { toast(err.message, true); }
  });
  $('#disable-totp').addEventListener('click', async () => {
    const code = await askCode('关闭两步验证', '输入当前验证码或一个恢复码；关闭后其它设备会退出登录。');
    if (!code) return;
    try {
      await api('/api/totp/disable', { method: 'POST', body: { code } });
      toast('两步验证已关闭');
      await refresh();
    } catch (err) { toast(err.message, true); }
  });

  refresh().catch(err => toast(err.message, true));
}

/* ---------- 账号：改密 / 改邮箱 / 注销 ---------- */
function initAccount() {
  if (!$('#pane-pw-old')) return;

  const tabs = { 'tab-pw-old': 'pane-pw-old', 'tab-pw-code': 'pane-pw-code' };
  Object.keys(tabs).forEach(id => $('#' + id).addEventListener('click', () => {
    Object.keys(tabs).forEach(other => {
      const on = other === id;
      $('#' + other).setAttribute('aria-selected', on ? 'true' : 'false');
      $('#' + tabs[other]).classList.toggle('hidden', !on);
    });
  }));

  function cooldown(btn, seconds) {
    let left = seconds;
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = `${left} 秒后重发`;
    const t = setInterval(() => {
      left -= 1;
      if (left <= 0) { clearInterval(t); btn.disabled = false; btn.textContent = original; }
      else btn.textContent = `${left} 秒后重发`;
    }, 1000);
  }

  $('#pane-pw-old').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#pw-old-error', '');
    try {
      await api('/auth/change-password', {
        method: 'POST',
        body: { oldPassword: $('#pw-old').value, newPassword: $('#pw-new').value },
      });
      $('#pw-old').value = ''; $('#pw-new').value = '';
      toast('密码已更新，其它设备已退出登录');
    } catch (err) { showErr('#pw-old-error', err.message); }
  });

  $('#send-pw-code').addEventListener('click', async () => {
    showErr('#pw-code-error', '');
    try {
      await api('/auth/send-change-code', { method: 'POST', body: {} });
      cooldown($('#send-pw-code'), 60);
      toast('验证码已发送到绑定邮箱');
    } catch (err) { showErr('#pw-code-error', err.message); }
  });

  $('#pane-pw-code').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#pw-code-error', '');
    try {
      await api('/auth/change-password-code', {
        method: 'POST',
        body: { code: $('#pw-code').value.trim(), password: $('#pw-code-new').value },
      });
      $('#pw-code').value = ''; $('#pw-code-new').value = '';
      toast('密码已更新，其它设备已退出登录');
    } catch (err) { showErr('#pw-code-error', err.message); }
  });

  $('#send-email-code').addEventListener('click', async () => {
    showErr('#email-error', '');
    const email = $('#email-new').value.trim();
    if (!email) { showErr('#email-error', '请先填写新邮箱'); return; }
    try {
      await api('/auth/send-change-email-code', { method: 'POST', body: { email } });
      cooldown($('#send-email-code'), 60);
      toast('验证码已发送到新邮箱');
    } catch (err) { showErr('#email-error', err.message); }
  });

  $('#change-email').addEventListener('click', async () => {
    showErr('#email-error', '');
    try {
      await api('/auth/change-email', {
        method: 'POST',
        body: {
          password: $('#email-password').value,
          email: $('#email-new').value.trim(),
          code: $('#email-code').value.trim(),
        },
      });
      $('#email-code').value = ''; $('#email-password').value = '';
      toast('邮箱已更新，新旧邮箱都收到了通知');
    } catch (err) { showErr('#email-error', err.message); }
  });

  $('#start-delete').addEventListener('click', () => {
    $('#delete-password').value = '';
    showErr('#delete-error', '');
    openDialog($('#delete-dialog'));
    $('#delete-password').focus();
  });
  $('#delete-cancel').addEventListener('click', () => closeDialog($('#delete-dialog')));
  $('#delete-form').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#delete-error', '');
    const btn = $('#delete-form').querySelector('.btn.danger');
    setBusy(btn, true);
    try {
      await api('/auth/delete', { method: 'POST', body: { password: $('#delete-password').value } });
      closeDialog($('#delete-dialog'));
      location.href = '/web/login';
    } catch (err) { showErr('#delete-error', err.message); setBusy(btn, false); }
  });
}

/* ---------- 后台：用户 ---------- */
function initAdminUsers() {
  const body = $('#users-body');
  if (!body) return;
  const state = { query: '', offset: 0, limit: 20, total: 0 };

  async function load() {
    showErr('#users-error', '');
    try {
      const res = await api(`/admin/users?query=${encodeURIComponent(state.query)}&limit=${state.limit}&offset=${state.offset}`);
      state.total = res.total;
      $('#users-total').textContent = `共 ${res.total} 个账号`;
      $('#users-page').textContent = `${state.offset + 1}–${state.offset + res.items.length} / ${res.total}`;
      $('#users-prev').disabled = state.offset <= 0;
      $('#users-next').disabled = state.offset + res.items.length >= res.total;
      body.innerHTML = '';
      if (!res.items.length) {
        body.innerHTML = '<tr><td colspan="7" class="empty">暂无记录</td></tr>';
        return;
      }
      res.items.forEach(u => {
        const tr = node(`
          <tr>
            <td class="wrap-cell">${esc(u.email)}</td>
            <td class="mono">${esc(u.uid)}</td>
            <td>${u.role === 'admin' ? '<span class="badge on">admin</span>' : '<span class="badge">user</span>'}</td>
            <td>${u.totpEnabled ? '已开启' : '未开启'}</td>
            <td>${u.passkeyCount}</td>
            <td>${esc(fmtTime(u.createdAt))}</td>
            <td><button type="button" class="btn small">查看</button></td>
          </tr>`);
        tr.querySelector('button').addEventListener('click', () => openDetail(u.uid, u.email));
        body.appendChild(tr);
      });
    } catch (err) {
      showErr('#users-error', err.message);
      body.innerHTML = '<tr><td colspan="7" class="empty">读取失败</td></tr>';
    }
  }

  async function openDetail(uid, email) {
    const panel = $('#user-detail');
    panel.classList.remove('hidden');
    $('#ud-title').textContent = email;
    $('#ud-body').innerHTML = '<div class="empty">读取中…</div>';
    panel.scrollIntoView({ block: 'nearest' });
    try {
      const d = await api('/admin/users/' + uid);
      const sessions = (d.sessions || []).map(s => `
        <div class="item">
          <span class="grow"><span class="title">${esc(s.device)}</span><br>
          <span class="meta">${esc(s.app)} · ${esc(s.ip)} · 最近活跃 ${esc(relTime(s.lastSeenAt))}</span></span>
          <button type="button" class="btn small danger" data-kick="${s.id}">踢出</button>
        </div>`).join('') || '<div class="empty">暂无活跃会话</div>';
      const passkeys = (d.passkeys || []).map(p =>
        `<li>${esc(p.name)} · ${esc(fmtTime(p.createdAt))}</li>`).join('') || '<li>未添加</li>';
      $('#ud-body').innerHTML = `
        <div class="grid2">
          <div><span class="dim">uid</span><br><span class="mono">${esc(d.uid)}</span></div>
          <div><span class="dim">注册时间</span><br>${esc(fmtTime(d.createdAt))}</div>
          <div><span class="dim">密码</span><br>${d.hasPassword ? '已设置' : '未设置'}</div>
          <div><span class="dim">两步验证</span><br>${d.totpEnabled ? '已开启' : '未开启'}</div>
        </div>
        <h3>Passkey</h3><ul>${passkeys}</ul>
        <h3>活跃会话</h3><div class="list">${sessions}</div>
        <div class="detail row">
          <label class="row" style="gap:8px"><span class="dim">角色</span>
            <select id="ud-role" ${d.uid === window.__meUid ? 'disabled title="不能修改自己的角色"' : ''}>
              <option value="user"${d.role === 'user' ? ' selected' : ''}>user</option>
              <option value="admin"${d.role === 'admin' ? ' selected' : ''}>admin</option>
            </select>
          </label>
          <button type="button" class="btn small primary" id="ud-save-role" ${d.uid === window.__meUid ? 'disabled' : ''}>保存角色</button>
          <button type="button" class="btn small danger" id="ud-kick-all">退出该用户全部会话</button>
        </div>`;
      $$('#ud-body [data-kick]').forEach(btn => btn.addEventListener('click', async () => {
        try {
          await api('/admin/sessions/' + btn.dataset.kick, { method: 'DELETE' });
          toast('已踢出会话');
          openDetail(uid, email);
        } catch (err) { toast(err.message, true); }
      }));
      $('#ud-save-role').addEventListener('click', async () => {
        try {
          await api('/admin/users/' + uid, { method: 'PATCH', body: { role: $('#ud-role').value } });
          toast('角色已更新');
          await load();
          openDetail(uid, email);
        } catch (err) { toast(err.message, true); }
      });
      $('#ud-kick-all').addEventListener('click', async () => {
        try {
          await api(`/admin/users/${uid}/revoke-sessions`, { method: 'POST', body: {} });
          toast('已退出该用户全部会话');
          openDetail(uid, email);
        } catch (err) { toast(err.message, true); }
      });
    } catch (err) {
      $('#ud-body').innerHTML = `<p class="err">${esc(err.message)}</p>`;
    }
  }

  $('#ud-close').addEventListener('click', () => $('#user-detail').classList.add('hidden'));
  $('#user-search-form').addEventListener('submit', e => {
    e.preventDefault();
    state.query = $('#user-query').value.trim();
    state.offset = 0;
    load();
  });
  $('#users-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); load(); });
  $('#users-next').addEventListener('click', () => { state.offset += state.limit; load(); });
  load();
}

/* ---------- 后台：会话总览 ---------- */
function initAdminSessions() {
  const body = $('#sess-body');
  if (!body) return;
  const state = { uid: '', offset: 0, limit: 20, total: 0 };

  async function load() {
    showErr('#sess-error', '');
    try {
      const res = await api(`/admin/sessions?uid=${encodeURIComponent(state.uid)}&limit=${state.limit}&offset=${state.offset}`);
      state.total = res.total;
      $('#sess-total').textContent = `共 ${res.total} 条活跃会话`;
      $('#sess-page').textContent = `${state.offset + 1}–${state.offset + res.items.length} / ${res.total}`;
      $('#sess-prev').disabled = state.offset <= 0;
      $('#sess-next').disabled = state.offset + res.items.length >= res.total;
      body.innerHTML = '';
      if (!res.items.length) {
        body.innerHTML = '<tr><td colspan="7" class="empty">暂无记录</td></tr>';
        return;
      }
      res.items.forEach(s => {
        const tr = node(`
          <tr>
            <td class="wrap-cell">${esc(s.email)}</td>
            <td class="mono">${esc(s.uid)}</td>
            <td>${esc(appLabel(s.app))}</td>
            <td class="wrap-cell">${esc(s.device)}</td>
            <td class="mono">${esc(s.ip)}</td>
            <td>${esc(relTime(s.lastSeenAt))}</td>
            <td><button type="button" class="btn small danger">吊销</button></td>
          </tr>`);
        tr.querySelector('button').addEventListener('click', async () => {
          try {
            await api('/admin/sessions/' + s.id, { method: 'DELETE' });
            toast('已吊销该会话');
            await load();
          } catch (err) { toast(err.message, true); }
        });
        body.appendChild(tr);
      });
    } catch (err) {
      showErr('#sess-error', err.message);
      body.innerHTML = '<tr><td colspan="7" class="empty">读取失败</td></tr>';
    }
  }

  $('#sess-filter-form').addEventListener('submit', e => {
    e.preventDefault();
    state.uid = $('#sess-uid').value.trim();
    state.offset = 0;
    load();
  });
  $('#sess-reset').addEventListener('click', () => { $('#sess-uid').value = ''; state.uid = ''; state.offset = 0; load(); });
  $('#sess-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); load(); });
  $('#sess-next').addEventListener('click', () => { state.offset += state.limit; load(); });
  load();
}

/* ---------- 后台：审计 ---------- */
function initAdminAudit() {
  const body = $('#audit-body');
  if (!body) return;
  const state = { offset: 0, limit: 50, total: 0 };

  function filters() {
    const p = new URLSearchParams();
    const action = $('#audit-action').value;
    if (action) p.set('action', action);
    const actor = $('#audit-actor').value.trim();
    if (actor) p.set('actor', actor);
    const target = $('#audit-target').value.trim();
    if (target) p.set('target', target);
    const from = $('#audit-from').value;
    if (from) p.set('from', String(new Date(from + 'T00:00:00').getTime()));
    const to = $('#audit-to').value;
    if (to) p.set('to', String(new Date(to + 'T23:59:59').getTime()));
    p.set('limit', String(state.limit));
    p.set('offset', String(state.offset));
    return p.toString();
  }

  async function load() {
    showErr('#audit-error', '');
    try {
      const res = await api('/admin/audit?' + filters());
      state.total = res.total;
      $('#audit-total').textContent = `共 ${res.total} 条`;
      $('#audit-page').textContent = state.total
        ? `${state.offset + 1}–${state.offset + res.items.length} / ${state.total}` : '—';
      $('#audit-prev').disabled = state.offset <= 0;
      $('#audit-next').disabled = state.offset + res.items.length >= state.total;
      body.innerHTML = '';
      if (!res.items.length) {
        body.innerHTML = '<tr><td colspan="7" class="empty">暂无记录</td></tr>';
        return;
      }
      res.items.forEach(it => {
        const who = it.actorUid ? `${it.actorUid} ${it.actorEmail || ''}` : (it.actorEmail || '匿名');
        body.appendChild(node(`
          <tr>
            <td>${esc(fmtTime(it.ts))}</td>
            <td class="mono">${esc(it.action)}</td>
            <td>${it.result === 'ok' ? '<span class="badge on">ok</span>' : '<span class="badge warn">fail</span>'}</td>
            <td class="wrap-cell">${esc(who)}</td>
            <td class="mono">${it.targetUid ? esc(it.targetUid) : '—'}</td>
            <td class="mono">${esc(it.ip || '—')}</td>
            <td class="wrap-cell mono">${esc(it.detail ? JSON.stringify(it.detail) : '—')}</td>
          </tr>`));
      });
    } catch (err) {
      showErr('#audit-error', err.message);
      body.innerHTML = '<tr><td colspan="7" class="empty">读取失败</td></tr>';
    }
  }

  $('#audit-filter-form').addEventListener('submit', e => { e.preventDefault(); state.offset = 0; load(); });
  $('#audit-reset').addEventListener('click', () => {
    $('#audit-action').value = ''; $('#audit-actor').value = ''; $('#audit-target').value = '';
    $('#audit-from').value = ''; $('#audit-to').value = '';
    state.offset = 0; load();
  });
  $('#audit-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); load(); });
  $('#audit-next').addEventListener('click', () => { state.offset += state.limit; load(); });
  load();
}

/* ---------- 后台：配置中心 ---------- */
function initAdminConfig() {
  const wrap = $('#cfg-groups');
  if (!wrap) return;
  const GROUPS = [
    { prefix: 'mail_', title: '邮件' },
    { prefix: 'hook_', title: '注销钩子' },
    { prefix: 'llm_', title: 'LLM' },
    { prefix: 'fcm', title: 'FCM 推送' },
    { prefix: 'ai_', title: 'AI 限额' },
  ];
  const LABELS = {
    mail_tenant_id: '租户 ID', mail_client_id: '客户端 ID', mail_client_secret: '客户端密钥',
    hook_token: '共享令牌', hook_calorie_diary: '热量日记注销地址', hook_expense_diary: '开支日记注销地址',
    ai_rate_per_minute: '每用户每分钟', ai_concurrency: '全站并发',
    ai_daily_per_user: '每用户每日', ai_daily_global: '全站每日',
  };
  let pendingClear = '';

  async function load() {
    showErr('#cfg-error', '');
    try {
      const items = await api('/admin/config');
      wrap.innerHTML = '';
      if (!items.length) {
        wrap.innerHTML = '<div class="empty">暂无记录</div>';
        return;
      }
      GROUPS.forEach(g => {
        const mine = items.filter(it => it.key.indexOf(g.prefix) === 0);
        if (!mine.length) return;
        const card = node(`<section class="card"><h2>${esc(g.title)}</h2><div class="stack" style="margin-top:8px"></div></section>`);
        const stack = card.querySelector('.stack');
        mine.forEach(it => {
          const stateText = it.configured
            ? (it.secret ? `已配置 · 末 4 位 ${esc(it.hint || '')}` : `已配置：<code class="mono">${esc(it.value)}</code>`)
            : '未配置';
          const row = node(`
            <div class="item" data-key="${esc(it.key)}">
              <span class="grow">
                <span class="title">${esc(LABELS[it.key] || it.key)}</span>
                <span class="badge">${esc(it.key)}</span>
                ${it.secret ? '<span class="badge">凭据</span>' : ''}
                <br><span class="meta">${stateText}</span>
              </span>
              <span class="row" style="gap:6px">
                <input type="text" style="min-width:200px" aria-label="新的值" placeholder="${it.secret ? '输入新值替换' : '留空则不修改'}">
                <button type="button" class="btn small primary" data-act="save">保存</button>
                ${it.configured ? '<button type="button" class="btn small danger" data-act="clear">清除</button>' : ''}
              </span>
            </div>`);
          row.querySelector('[data-act=save]').addEventListener('click', async () => {
            const input = row.querySelector('input');
            const value = input.value;
            if (!value) { toast('留空表示不修改', true); return; }
            try {
              await api('/admin/config/' + encodeURIComponent(it.key), { method: 'PUT', body: { value } });
              input.value = '';
              toast('已保存，≤10 秒生效');
              await load();
            } catch (err) { showErr('#cfg-error', err.message); }
          });
          const clearBtn = row.querySelector('[data-act=clear]');
          if (clearBtn) {
            clearBtn.addEventListener('click', () => {
              pendingClear = it.key;
              $('#cfg-desc').textContent = `将清除配置键 ${it.key}（值会从库里删除）。`;
              showErr('#cfg-dialog-error', '');
              openDialog($('#cfg-dialog'));
            });
          }
          stack.appendChild(row);
        });
        wrap.appendChild(card);
      });
    } catch (err) { showErr('#cfg-error', err.message); }
  }

  $('#cfg-cancel').addEventListener('click', () => closeDialog($('#cfg-dialog')));
  $('#cfg-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api('/admin/config/' + encodeURIComponent(pendingClear), { method: 'PUT', body: { value: '' } });
      closeDialog($('#cfg-dialog'));
      toast('已清除，≤10 秒生效');
      await load();
    } catch (err) {
      closeDialog($('#cfg-dialog'));
      showErr('#cfg-error', err.message);
    }
  });

  load();
}

/* ---------- 后台：AI 用量 ---------- */
function initAdminAI() {
  const bars = $('#ai-bars');
  if (!bars) return;

  async function load() {
    showErr('#ai-error', '');
    const days = $('#ai-days').value;
    try {
      const rep = await api('/admin/ai-usage?days=' + encodeURIComponent(days));
      const q = rep.quota;
      $('#q-rate').textContent = q.perMinute + ' 次';
      $('#q-conc').textContent = q.concurrency + ' 路';
      $('#q-user').textContent = q.dailyPerUser + ' 次';
      $('#q-global').textContent = q.dailyGlobal + ' 次';
      $('#q-source').textContent = q.configured
        ? '当前值来自 app_config 配置。'
        : '限额键尚未配齐，显示的是默认值（20 / 8 / 500 / 5000）。';

      const list = rep.days || [];
      if (!list.length) {
        bars.innerHTML = '';
        $('#ai-empty').classList.remove('hidden');
        $('#ai-today').textContent = '';
        return;
      }
      $('#ai-empty').classList.add('hidden');
      const today = list[0];
      const max = Math.max.apply(null, list.map(d => d.total));
      $('#ai-today').textContent = `今日（${today.day}）合计 ${today.total} 次`;
      bars.innerHTML = '';
      list.forEach(d => {
        const pct = max > 0 ? Math.max(2, Math.round(d.total / max * 100)) : 0;
        bars.appendChild(node(`
          <div class="bar-row">
            <span class="dim">${esc(d.day)}</span>
            <span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>
            <span class="bar-num">${d.total}</span>
          </div>`));
      });
    } catch (err) { showErr('#ai-error', err.message); }
  }

  $('#ai-days').addEventListener('change', load);
  load();
}

/* ---------- 小工具 ---------- */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    // 剪贴板 API 在非安全上下文不可用：退回临时 textarea + execCommand
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

function openDialog(dlg) {
  if (!dlg) return;
  if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
}

function closeDialog(dlg) {
  if (!dlg) return;
  if (dlg.open && typeof dlg.close === 'function') dlg.close(); else dlg.removeAttribute('open');
}

/* tablist 的键盘行为：左右键与 Home/End 在同组标签间移动焦点并切换，
   否则 role=tab 只能用 Tab 一个个跳，读屏/键盘用户拿不到「一组控件」的语义。 */
function wireTabs() {
  $$('.tabs[role="tablist"]').forEach(list => {
    const tabs = $$('[role="tab"]', list);
    tabs.forEach((tab, i) => tab.addEventListener('keydown', e => {
      let j = -1;
      if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = tabs.length - 1;
      if (j < 0) return;
      e.preventDefault();
      tabs[j].focus();
      tabs[j].click();
    }));
  });
}

/* ---------- 入口 ---------- */
document.addEventListener('DOMContentLoaded', () => {
  wireReauth();
  wireTabs();
  initAdminGuard();
  initLogin();
  initConsole();
  initSessions();
  initPasskeys();
  initSecurity();
  initAccount();
  initAdminUsers();
  initAdminSessions();
  initAdminAudit();
  initAdminConfig();
  initAdminAI();
});
