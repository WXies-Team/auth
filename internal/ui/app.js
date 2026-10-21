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

/* ---------- 动效（与 style.css 的动效系统同一套 easing/时长）----------
   约定：
   - 只用 transform / opacity（WAAPI 也不许碰 width/height/top 这类 layout 属性）；
   - 用户开了「减弱动态效果」就全部不播——交互反馈只留颜色/透明度；
   - 动画绝不拦截交互：不 await 播完再响应点击/焦点，纯装饰。 */
const MOTION_EASE = 'cubic-bezier(.2, 0, 0, 1)';
const reducedMotion = () =>
  !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

/* 区块切换：crossfade + 4px 上浮，180ms（页内 tab 换面板、详情面板展开都走它）。
   传入的元素必须此刻可见；播放失败静默忽略——动画是装饰，不是流程。 */
function swapIn(el) {
  if (!el || reducedMotion() || typeof el.animate !== 'function') return;
  try {
    el.animate(
      [{ opacity: 0, transform: 'translateY(4px)' }, { opacity: 1, transform: 'translateY(0)' }],
      { duration: 180, easing: MOTION_EASE });
  } catch (_) { /* 浏览器不支持就静默 */ }
}

/* 页内钻取：16px 右侧滑入 + 淡入，200ms（后台详情面板、AI 明细面板的进场）。
   与 swapIn 同一套 easing/时长梯度，只多一段横移——层级感来自方向，不来自节奏。 */
function slideIn(el) {
  if (!el || reducedMotion() || typeof el.animate !== 'function') return;
  try {
    el.animate(
      [{ opacity: 0, transform: 'translateX(16px)' }, { opacity: 1, transform: 'translateX(0)' }],
      { duration: 200, easing: MOTION_EASE });
  } catch (_) { /* 同上 */ }
}

/* 状态浮现：徽标/提示轻缩放进场，200ms（保存成功、角色徽标亮起一类） */
function popIn(el) {
  if (!el || reducedMotion() || typeof el.animate !== 'function') return;
  try {
    el.animate(
      [{ opacity: 0, transform: 'scale(.94)' }, { opacity: 1, transform: 'scale(1)' }],
      { duration: 200, easing: MOTION_EASE });
  } catch (_) { /* 同上 */ }
}

/* 行退场：挂 .leaving（CSS 用同一套 easing 做淡出 + 下沉），等它播完再回调。
   服务端已确认成功才走到这里，所以等 180ms 不拖慢任何交互；reduced-motion 直接回调。 */
function fadeOutRow(el, done) {
  if (!el || reducedMotion()) { done(); return; }
  el.classList.add('leaving');
  setTimeout(done, 180);
}

function fmtTime(ms) {
  if (!ms) return '—';
  const d = new Date(Number(ms));
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function todayStr() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
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
  if (day === 1) return '昨天';
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

/* ---------- 发码冷却（登录页两处 + 账号页两处共用一份） ----------
   60 秒倒计时：按钮禁用 + 「N 秒后重发」，归零还原文案重新可用。 */
function cooldown(btn, seconds) {
  let left = seconds;
  btn.disabled = true;
  const original = btn.dataset.cooldownLabel || btn.textContent;
  btn.dataset.cooldownLabel = original;
  btn.textContent = `${left} 秒后重发`;
  const t = setInterval(() => {
    left -= 1;
    if (left <= 0) { clearInterval(t); btn.disabled = false; btn.textContent = original; }
    else btn.textContent = `${left} 秒后重发`;
  }, 1000);
}

/* ---------- 分页（用户/审计/后台会话三页共用一份） ---------- */
function makePager(opts) {
  const st = { offset: 0, limit: opts.limit || 20, total: 0 };
  const prev = $(opts.prev), next = $(opts.next), label = $(opts.label);
  return {
    state: st,
    /* set(总数, 本页条数)：刷新页码文案与两端按钮的可用态 */
    set(total, shown) {
      st.total = total;
      if (label) {
        label.textContent = total
          ? `${st.offset + 1}–${st.offset + shown} / ${total}` : '—';
      }
      if (prev) prev.disabled = st.offset <= 0;
      if (next) next.disabled = st.offset + shown >= total;
    },
    wire(reload) {
      if (prev) prev.addEventListener('click', () => { st.offset = Math.max(0, st.offset - st.limit); reload(); });
      if (next) next.addEventListener('click', () => { st.offset += st.limit; reload(); });
    },
  };
}

/* ---------- 单输入原地换语义的 N 态工厂（GitHub 式，重新验证框、安全页「要一个码」
   弹框、登录第二步三处共用） ----------
   二态弹框（两步验证码 ↔ 恢复码）与三态登录步（验证器码 / 邮箱码 / 恢复码）的
   差异全在配置：每态一组 label/placeholder/形态（numeric 收 6 位、否则自由输入）、
   本态下各切换按钮的文案与显隐、可选的 intro 提示。apply(mode) 统一收口：
   同步属性 → 值清空（防上一态输的半截被当另一种码提交）→ 刷新按钮/提示 →
   清掉上一态的报错（换形态即换语义，旧错不再适用）→ crossfade（silent=false）→
   聚焦（focus 默认取 cfg.autoFocus）。 */
function makeCodeToggle(input, labelEl, cfg) {
  let mode = cfg.initial;
  function apply(opts) {
    const o = opts || {};
    const m = cfg.modes[mode];
    labelEl.textContent = m.label;
    input.placeholder = m.placeholder;
    if (m.numeric) {
      input.setAttribute('inputmode', 'numeric');
      input.setAttribute('maxlength', '6');
      input.setAttribute('autocomplete', 'one-time-code');
    } else {
      input.removeAttribute('inputmode');
      input.removeAttribute('maxlength');
      input.setAttribute('autocomplete', 'off');
    }
    Object.keys(m.buttons || {}).forEach(sel => {
      const el = $(sel);
      if (el) el.textContent = m.buttons[sel];
    });
    (m.hide || []).forEach(sel => { const el = $(sel); if (el) el.classList.add('hidden'); });
    (m.show || []).forEach(sel => { const el = $(sel); if (el) el.classList.remove('hidden'); });
    if (cfg.introSel && m.intro != null) $(cfg.introSel).textContent = m.intro;
    // 「已发送到你的邮箱」一类只在本态成立的提示，换态即收起
    (cfg.hideAlways || []).forEach(sel => { const el = $(sel); if (el) el.hidden = true; });
    input.value = '';
    if (cfg.errSel) showErr(cfg.errSel, '');
    if (!o.silent) swapIn((cfg.fadeSel && $(cfg.fadeSel)) || labelEl.closest('.field') || input);
    if (o.focus === undefined ? cfg.autoFocus : o.focus) input.focus();
  }
  return {
    mode: () => mode,
    set(next, opts) { mode = next; apply(opts); },
    reset(opts) {
      if (mode !== cfg.initial) { mode = cfg.initial; apply(opts); } else { input.value = ''; }
    },
  };
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
    if (window.__reauthToggle) window.__reauthToggle.reset();
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
  window.__reauthToggle = makeCodeToggle($('#reauth-code'), $('#reauth-code-label'), {
    initial: 'code',
    errSel: '#reauth-error',
    modes: {
      code: {
        label: '两步验证码（6 位）', placeholder: '输入验证器上的 6 位验证码', numeric: true,
        buttons: { '#reauth-toggle-recovery': '使用恢复码' },
      },
      recovery: {
        label: '恢复码', placeholder: 'XXXX-XXXX-XXXX-XXXX', numeric: false,
        buttons: { '#reauth-toggle-recovery': '改用两步验证码' },
      },
    },
  });
  $('#reauth-toggle-recovery').addEventListener('click', () =>
    window.__reauthToggle.set(window.__reauthToggle.mode() === 'recovery' ? 'code' : 'recovery', { focus: true }));
  $('#reauth-cancel').addEventListener('click', () => closeReauth(false));
  $('#reauth').addEventListener('cancel', e => { e.preventDefault(); closeReauth(false); });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const password = $('#reauth-password').value;
    const useRecovery = window.__reauthToggle.mode() === 'recovery';
    const totpCode = useRecovery ? '' : $('#reauth-code').value;
    const recoveryCode = useRecovery ? $('#reauth-code').value : '';
    if (!password && !totpCode && !recoveryCode) {
      showErr('#reauth-error', '请输入密码、两步验证码或恢复码'); return;
    }
    const btn = $('#reauth-ok');
    setBusy(btn, true);
    try {
      await api('/web/reauth', {
        method: 'POST', body: { password, totpCode, recoveryCode }, noReauth: true,
      });
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
    if (res.status === 401 && msg.indexOf('重新验证') < 0 && !location.pathname.startsWith('/web/login')) {
      location.href = '/web/login';
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

/* ---------- 应用注册表（服务端注入，唯一清单来源） ----------
   layout 里的 <script type="application/json" id="known-apps"> 承载 internal/ui 的
   knownApps 序列化结果；这里读出来建 appLabel 与应用授权开关的选项。
   JS 侧不再硬编码 app 清单——新应用只改 Go 注册表一处。 */
function knownApps() {
  try {
    const el = document.getElementById('known-apps');
    const list = JSON.parse(el ? el.textContent : '[]');
    return Array.isArray(list) ? list : [];
  } catch (_) { return []; }
}

const APP_LABEL = (() => {
  const map = { web: '网页' };   // 会话里的 app=web 是控制台自身，不是业务应用
  knownApps().forEach(a => { map[a.key] = a.label; });
  return map;
})();
const appLabel = v => APP_LABEL[v] || v;

/* 管理页守卫：先确认自己真的是管理员，再让各页发起数据请求；
   角色不符直接回概览（数据层的 requireAdmin 还会逐请求再挡一次）。
   W2：admin 与 super 都放行（与 ui.IsAdminRole 同口径），super 标记供角色页等
   专属 UI 判定。 */
async function initAdminGuard() {
  if (location.pathname.indexOf('/web/admin') !== 0) return;
  try {
    const me = await api('/web/session', { method: 'POST', body: {} });
    window.__meUid = me.uid;
    if (me.role !== 'admin' && me.role !== 'super') location.href = '/web/console';
  } catch (_) { /* 401 时 api() 已经跳登录页 */ }
}

/* 当前数据页的 app 过滤器：?app= 空 = 全部（super）/ 全部授权（app-admin）。
   服务端已把越权 ?app= 挡成 403 页，这里只管把合法取值带上 API。 */
function appFilter() {
  const v = new URLSearchParams(location.search).get('app');
  return v ? '&app=' + encodeURIComponent(v) : '';
}

/* 项目切换器：选中写入 ?app=（刷新保持），切换时用 W1 的 popIn 徽标动效 +
   swapIn 数据区（不整页刷新——数据页本就走 fetch，重取数据比重新加载壳轻）。
   未选中项是同页链接，点击即走这里；无 JS 时退化为 ?app= 链接跳转，同样成立。 */
function initAppSwitch() {
  const wrap = $('#app-switch');
  if (!wrap) return;
  $$('.app-chip', wrap).forEach(chip => chip.addEventListener('click', e => {
    e.preventDefault();
    const app = chip.dataset.app || '';
    const url = new URL(location.href);
    if (app) url.searchParams.set('app', app); else url.searchParams.delete('app');
    history.replaceState(null, '', url);
    $$('.app-chip', wrap).forEach(c => {
      const on = c === chip;
      c.classList.toggle('on', on);
      if (on) { c.setAttribute('aria-current', 'true'); popIn(c); }
      else c.removeAttribute('aria-current');
    });
    // 通知当前数据页重取：监听方（会话/审计/AI 三页）preventDefault 即
    // 「我处理了，别整页刷新」。切换器只在这三页渲染，无人监听时兜底 reload。
    const ev = new CustomEvent('appscopechange', { cancelable: true });
    if (document.dispatchEvent(ev)) location.reload();
  }));
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
        const pane = $('#' + tabs[other]);
        pane.classList.toggle('hidden', !on);
        if (on) swapIn(pane);   // 换面板：crossfade + 4px 上浮
      });
      showErr('#login-error', ''); showErr('#code-error', ''); showErr('#reset-error', '');
    });
  });

  // ---- 密码 →（2FA）三模式：验证器码 / 邮箱码 / 恢复码（GitHub 式单输入原地换语义）----
  // 与两个弹框同一个 makeCodeToggle：三态与二态的差别只是配置（多一组邮箱码态、
  // 多两个切换按钮、每态一段 intro），apply 收口的属性同步/清值/清旧报错/聚焦一处不变。
  let loginToken = '';
  const stepPwd = $('#step-password'), stepTotp = $('#step-totp');
  const f2 = makeCodeToggle($('#login-code-2fa'), $('#totp-label'), {
    initial: 'totp',
    autoFocus: true,
    errSel: '#login-error',
    fadeSel: '#step-totp',
    introSel: '#totp-intro',
    hideAlways: ['#totp-email-hint'],   // 已发送提示只在真发出一封后亮，切模式即收起
    modes: {
      totp: {
        label: '两步验证码（6 位）', placeholder: '输入验证器上的 6 位验证码', numeric: true,
        hide: ['#send-2fa-row'], show: ['#toggle-email'],
        buttons: {
          '#toggle-email': '没有验证器？获取邮箱验证码',
          '#toggle-recovery': '使用恢复码',
        },
        intro: '该账号已开启两步验证：请输入验证器上的 6 位验证码完成登录。',
      },
      email: {
        label: '邮箱验证码（6 位）', placeholder: '输入邮箱里收到的 6 位验证码', numeric: true,
        show: ['#send-2fa-row', '#toggle-email'],
        buttons: {
          '#toggle-email': '换回验证器验证码',
          '#toggle-recovery': '使用恢复码',
        },
        intro: '该账号已开启两步验证：请输入邮箱里的 6 位验证码完成登录。',
      },
      recovery: {
        label: '恢复码', placeholder: 'XXXX-XXXX-XXXX-XXXX', numeric: false,
        // 邮箱码专属的发码行收起；toggle-email 藏起来，免得摆一个点了没反应的按钮
        hide: ['#send-2fa-row', '#toggle-email'],
        buttons: { '#toggle-recovery': '改用两步验证码' },
        intro: '该账号已开启两步验证：请输入一个恢复码完成登录。',
      },
    },
  });
  function useTotpStep(on) {
    stepPwd.classList.toggle('hidden', on);
    stepTotp.classList.toggle('hidden', !on);
    $('#login-submit').textContent = on ? '完成登录' : '登录';
    f2.set('totp', { silent: true, focus: false });   // 回验证器形态，防上次切到邮箱码/恢复码的残留
    swapIn(on ? stepTotp : stepPwd);   // 步骤切换同样是区块切换动效
    if (on) $('#login-code-2fa').focus();
  }
  $('#back-to-password').addEventListener('click', () => { loginToken = ''; useTotpStep(false); });
  $('#toggle-email').addEventListener('click', () => f2.set(f2.mode() === 'email' ? 'totp' : 'email'));
  $('#toggle-recovery').addEventListener('click', () => f2.set(f2.mode() === 'recovery' ? 'totp' : 'recovery'));
  // 邮箱码模式发码：purpose=login_2fa（与邮箱验证码登录的 login 码分键），60 秒冷却复用
  $('#send-2fa-code').addEventListener('click', async () => {
    const sent = await sendCode($('#login-email').value.trim(), 'login_2fa', '#login-error', $('#send-2fa-code'));
    if (sent) $('#totp-email-hint').hidden = false;
  });

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
      // 单输入三选一：按当前模式决定字段（邮箱码 → emailCode，恢复码 → recoveryCode，
      // 否则 code）；空输入在前端就挡下，免得邮箱码模式吃一句「两步验证码错误」
      const v = $('#login-code-2fa').value.trim();
      const fm = f2.mode();
      if (!v) {
        showErr('#login-error', fm === 'email' ? '请输入邮箱验证码'
          : fm === 'recovery' ? '请输入恢复码' : '请输入两步验证码');
        return;
      }
      const body = { loginToken, code: '', recoveryCode: '', emailCode: '' };
      if (fm === 'email') body.emailCode = v;
      else if (fm === 'recovery') body.recoveryCode = v;
      else body.code = v;
      await api('/web/login/totp', { method: 'POST', body });
      location.href = '/web/console';
    } catch (err) {
      showErr('#login-error', err.message);
      // 只有**登录中间态**过期才退回第一步——邮箱码自己的「验证码已过期」不能触发，
      // 否则用户要重输密码（中间态其实还活着）
      if (loginToken && err.message.indexOf('登录请求已过期') >= 0) { loginToken = ''; useTotpStep(false); }
    } finally {
      setBusy(btn, false);
    }
  });

  // ---- 发码（验证码登录 / 找回密码 / 两步邮箱码）：共享冷却 ----
  // 回 true = 信已发出（两步邮箱码模式据此亮「已发送到你的邮箱」提示）
  async function sendCode(email, purpose, errSel, btn) {
    showErr(errSel, '');
    if (!email) { showErr(errSel, '请先填写邮箱'); return false; }
    try {
      await api('/auth/send-code', { method: 'POST', body: { email, purpose } });
      cooldown(btn, 60);
      toast('验证码已发送，没收到可查看垃圾箱');
      return true;
    } catch (err) { showErr(errSel, err.message); return false; }
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
  // 显隐统一走 .hidden 类：.btn 是 author 级 display:inline-flex，hidden **属性**会被
  // 它盖掉；分隔线与按钮同一套开关，别一处用类一处用属性
  const supportsPasskey = !!(window.PublicKeyCredential && navigator.credentials);
  $('#passkey-login').classList.toggle('hidden', !supportsPasskey);
  $('#passkey-sep').classList.toggle('hidden', !supportsPasskey);
  if (supportsPasskey) {
    $('#passkey-login').addEventListener('click', async () => {
      showErr('#passkey-error', '');
      const btn = $('#passkey-login');
      setBusy(btn, true);
      try {
        const opts = await api('/webauthn/login/options', { method: 'POST', body: {} });
        const cred = await navigator.credentials.get({ publicKey: decodePKOptions(opts.publicKey) });
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
/* 服务端 JSON 里 challenge/user.id/allowCredentials[].id 是 base64url 字符串，
   浏览器 WebAuthn 只收 ArrayBuffer/视图——进 create/get 前统一解码（App 端把整个
   JSON 交给 Credential Manager 自行解析，故两端形态不同）。 */
function b64urlToBytes(s) {
  const b = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = b.length % 4 ? '='.repeat(4 - (b.length % 4)) : '';
  const bin = atob(b + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function decodePKOptions(pk) {
  if (!pk) return pk;
  if (typeof pk.challenge === 'string') pk.challenge = b64urlToBytes(pk.challenge);
  if (pk.user && typeof pk.user.id === 'string') pk.user.id = b64urlToBytes(pk.user.id);
  ['allowCredentials', 'excludeCredentials'].forEach(k => {
    if (Array.isArray(pk[k])) pk[k].forEach(c => { if (typeof c.id === 'string') c.id = b64urlToBytes(c.id); });
  });
  return pk;
}
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
    if (me.role === 'admin' || me.role === 'super') {
      const badge = $('#role-badge');
      badge.textContent = me.role === 'super' ? '平台管理员' : '项目管理员';
      badge.classList.remove('hidden');   // 徽标 display:inline-flex，hidden 属性盖不住——走 .hidden 类
      popIn(badge);   // 徽标浮现
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

/* ---------- 登录会话（按设备分组） ---------- */
/* 设备类型图标（lucide 同款路径，内联进 app.js 是因为列表行由 JS 拼）：
   按服务端 UA 解析出的设备标签映射——移动系统出 smartphone、桌面系统出 laptop、
   认不出的（脚本/残缺 UA）退回通用设备图标，不猜。 */
const DEVICE_ICONS = {
  smartphone: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect width="14" height="20" x="5" y="2" rx="2" ry="2" /><path d="M12 18h.01" /></svg>',
  laptop: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16" /></svg>',
  monitor: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect width="20" height="14" x="2" y="3" rx="2" /><line x1="8" x2="16" y1="21" y2="21" /><line x1="12" x2="12" y1="17" y2="21" /></svg>',
  device: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M18 8V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h8" /><path d="M10 19v-3.96 3.15" /><path d="M7 19h5" /><rect width="6" height="10" x="16" y="12" rx="2" /></svg>',
};

function deviceIcon(device) {
  const d = String(device || '');
  if (/Android|iPhone|iPad|iOS|Mobile/i.test(d)) return DEVICE_ICONS.smartphone;
  if (/Windows|macOS|Mac OS X|Linux|ChromeOS|Ubuntu/i.test(d)) return DEVICE_ICONS.laptop;
  return DEVICE_ICONS.device;
}

/* 会话条目的短标识：session + id 末 4 位（id 一律按字符串处理，雪花 id 的
   JS 精度陷阱不踩第二次）。 */
const sessTag = id => 'session' + String(id).slice(-4);

function initSessions() {
  const list = $('#session-list');
  if (!list) return;
  let rows = [];
  let pending = null;   // {mode:'one'|'many'|'others', ids:[], label, count}

  /* 按设备名分组：本设备组置顶；组内按最近活跃倒序 */
  function groups() {
    const map = new Map();
    rows.forEach(r => {
      const key = r.device || '未知设备';
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(r);
    });
    const out = [];
    map.forEach((items, device) => {
      items.sort((a, b) => Number(b.lastSeenAt || 0) - Number(a.lastSeenAt || 0));
      out.push({ device, items, current: items.some(i => i.current) });
    });
    out.sort((a, b) => (b.current ? 1 : 0) - (a.current ? 1 : 0));
    return out;
  }

  async function load() {
    try {
      const res = await api('/api/sessions');
      // 契约是 {sessions:[...]}
      rows = res.sessions || [];
    } catch (err) {
      list.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
      return;
    }
    if (!rows.length) {
      list.innerHTML = '<div class="empty">只有当前设备处于登录状态。</div>';
      return;
    }
    list.innerHTML = '';
    groups().forEach(g => {
      const others = g.items.filter(i => !i.current);
      const el = node(`
        <div class="item device-group${g.current ? ' current' : ''}" data-device="${esc(g.device)}">
          <span class="ico-wrap">${deviceIcon(g.device)}</span>
          <span class="grow">
            <span class="title">${esc(g.device)}</span>
            <span class="badge">${g.items.length} 条会话</span>
            ${g.current ? '<span class="badge on">本设备</span>' : ''}
          </span>
          ${others.length ? '<button type="button" class="btn small danger" data-act="group-kick">退出该设备全部会话</button>' : ''}
          <div class="sub-list">
            ${g.items.map(it => `
              <div class="session-row${it.current ? ' current' : ''}" data-id="${esc(it.id)}">
                <span class="grow">
                  <span class="mono sess-tag">${esc(appLabel(it.app))} · ${esc(sessTag(it.id))}</span>
                  ${it.current ? '<span class="badge on">本设备</span>' : ''}
                  <br><span class="meta">${esc(it.ip)} · 最近活跃 ${esc(relTime(it.lastSeenAt))}</span>
                </span>
                ${it.current ? '' : '<button type="button" class="btn small danger">退出</button>'}
              </div>`).join('')}
          </div>
        </div>`);
      const groupKick = el.querySelector('[data-act=group-kick]');
      if (groupKick) {
        groupKick.addEventListener('click', () => {
          pending = {
            mode: 'many', ids: others.map(i => String(i.id)),
            label: g.device, count: others.length,
          };
          $('#kick-title').textContent = '退出该设备全部会话';
          $('#kick-desc').textContent = `将退出「${g.device}」上的 ${others.length} 条会话，该设备下次请求时会退出登录。`;
          $('#kick-ok').textContent = '全部退出';
          openDialog($('#kick-dialog'));
        });
      }
      $$('.session-row', el).forEach(row => {
        const kick = row.querySelector('button');
        if (!kick) return;
        const it = g.items.find(i => String(i.id) === row.dataset.id);
        kick.addEventListener('click', () => {
          pending = { mode: 'one', ids: [row.dataset.id], label: it ? sessTag(it.id) : '', count: 1 };
          $('#kick-title').textContent = '退出这条会话';
          $('#kick-desc').textContent = `将退出「${g.device}」上的 ${pending.label}，它下次请求时会退出登录。`;
          $('#kick-ok').textContent = '退出会话';
          openDialog($('#kick-dialog'));
        });
      });
      list.appendChild(el);
    });
  }

  $('#revoke-others').addEventListener('click', () => {
    const others = rows.filter(r => !r.current).length;
    pending = { mode: 'others', ids: [], label: '', count: others };
    $('#kick-title').textContent = '退出其它所有会话';
    $('#kick-desc').textContent = others
      ? `将退出除「本设备」外的 ${others} 条会话，本机保持登录。`
      : '没有其它会话需要退出。';
    $('#kick-ok').textContent = others ? '全部退出' : '知道了';
    openDialog($('#kick-dialog'));
  });
  $('#kick-cancel').addEventListener('click', () => closeDialog($('#kick-dialog')));
  $('#kick-ok').addEventListener('click', async () => {
    const dlg = $('#kick-dialog');
    if (pending.mode === 'others' && !pending.count) { closeDialog(dlg); return; }
    const okBtn = $('#kick-ok');
    setBusy(okBtn, true);
    try {
      if (pending.mode === 'one') {
        await api('/api/sessions/' + pending.ids[0], { method: 'DELETE' });
        closeDialog(dlg);
        toast('已退出该会话');
        // 行先淡出下沉，播完再整表刷新——视觉上是「这条走了」而不是突然消失
        fadeOutRow(list.querySelector(`.session-row[data-id="${pending.ids[0]}"]`), load);
      } else if (pending.mode === 'many') {
        await api('/api/sessions/revoke-many', { method: 'POST', body: { ids: pending.ids } });
        closeDialog(dlg);
        toast(`已退出「${pending.label}」的 ${pending.count} 条会话`);
        // 设备名可能带引号，不能拼进 selector——按 data 属性逐个找元素引用
        const group = $$('#session-list .device-group').find(el => el.dataset.device === pending.label);
        fadeOutRow(group, load);
      } else {
        // 服务端强制 reauth（2 小时强认证窗 + 敏感操作滑动续期），401 会自动弹「重新验证」框再重试
        await api('/api/sessions/revoke-others', { method: 'POST', body: {} });
        closeDialog(dlg);
        toast(`已退出其它 ${pending.count} 条会话`);
        // 其余会话行一起退场，本设备行留着（随后整表刷新重绘）
        const leaving = $$('#session-list .session-row:not(.current)');
        if (!leaving.length || reducedMotion()) { await load(); return; }
        leaving.forEach(el => el.classList.add('leaving'));
        setTimeout(load, 180);
      }
    } catch (err) {
      closeDialog(dlg);
      toast(err.message, true);
    } finally {
      setBusy(okBtn, false);
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
      const cred = await navigator.credentials.create({ publicKey: decodePKOptions(opts.publicKey) });
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
    const badge = $('#totp-badge');
    const was = badge.textContent;
    badge.textContent = st.enabled ? '已开启' : '未开启';
    badge.classList.toggle('on', st.enabled);
    if (was && was !== badge.textContent) popIn(badge);   // 状态翻转：徽标轻浮现
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
    swapIn($('#codes-panel'));   // 恢复码面板浮现
  }

  $('#start-setup').addEventListener('click', async () => {
    showErr('#setup-error', '');
    try {
      const setup = await api('/api/totp/setup', { method: 'POST', body: {} });
      $('#qr-img').src = setup.qrPng;
      $('#setup-secret').textContent = setup.secret;
      $('#setup-code').value = '';
      $('#setup-panel').classList.remove('hidden');
      swapIn($('#setup-panel'));   // 绑定面板浮现
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
      $('#recovery-state').textContent = `恢复码：本次已生成 ${res.recoveryCodes.length} 个，请妥善保存。`;
      await refresh();
    } catch (err) { showErr('#setup-error', err.message); } finally { setBusy(btn, false); }
  });

  /* 恢复码下载（参考 GitHub 的 github-recovery-codes.txt 结构：服务名 + 账号 +
     生成日期 + 使用说明 + 码列表——纯码列表落进密码管理器后没人知道它是谁的）。 */
  $('#download-codes').addEventListener('click', () => {
    const email = $('#topbar-email') ? $('#topbar-email').textContent : '';
    const body = [
      'Auth 统一账号服务 —— 恢复码',
      `账号：${email}`,
      `生成日期：${todayStr()}`,
      '',
      '每个恢复码只能使用一次，用于两步验证开启后验证器不可用时登录。' +
        '使用后即失效；重生成会让全部旧码作废。请离线妥善保存。',
      '',
      ...codes,
      '',
    ].join('\n');
    const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'auth-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $('#copy-codes').addEventListener('click', async () => {
    await copyText(codes.join('\n'));
    toast('恢复码已复制到剪贴板');
  });
  $('#saved-codes').addEventListener('click', () => {
    $('#codes-panel').classList.add('hidden');
    codes = [];
    toast('恢复码已保存。离开本页后无法再查看，需要时可重生成。');
  });

  // 通用「要一个码」弹框（单输入 + 恢复码切换；返回 {value, recovery}）
  let codeResolver = null;
  const codeToggle = makeCodeToggle($('#code-input'), $('#code-input-label'), {
    initial: 'code',
    errSel: '#code-error',
    modes: {
      code: {
        label: '两步验证码（6 位）', placeholder: '输入验证器上的 6 位验证码', numeric: true,
        buttons: { '#code-toggle-recovery': '使用恢复码' },
      },
      recovery: {
        label: '恢复码', placeholder: 'XXXX-XXXX-XXXX-XXXX', numeric: false,
        buttons: { '#code-toggle-recovery': '改用两步验证码' },
      },
    },
  });
  $('#code-toggle-recovery').addEventListener('click', () =>
    codeToggle.set(codeToggle.mode() === 'recovery' ? 'code' : 'recovery', { focus: true }));
  function askCode(title, desc) {
    $('#code-title').textContent = title;
    $('#code-desc').textContent = desc;
    codeToggle.reset();
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
    if (!value) { showErr('#code-error', codeToggle.mode() === 'recovery' ? '请输入恢复码' : '请输入两步验证码'); return; }
    if (codeResolver) { codeResolver(value); codeResolver = null; }   // 服务端 code 字段两码通用
    closeDialog($('#code-dialog'));
  });

  $('#regen-codes').addEventListener('click', async () => {
    const code = await askCode('重生成恢复码', '输入当前两步验证码或一个恢复码；旧的恢复码会全部作废。');
    if (!code) return;
    try {
      const res = await api('/api/totp/regenerate-recovery-codes', { method: 'POST', body: { code } });
      showCodes(res.recoveryCodes);
      $('#recovery-state').textContent = `恢复码：本次已生成 ${res.recoveryCodes.length} 个，旧恢复码全部作废。`;
      toast('已换发新恢复码，旧码全部作废');
    } catch (err) { toast(err.message, true); }
  });
  $('#disable-totp').addEventListener('click', async () => {
    const code = await askCode('关闭两步验证', '输入当前两步验证码或一个恢复码；关闭后验证器绑定与 10 个恢复码将全部失效，登录只需密码；其它设备保持登录状态。');
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
      const pane = $('#' + tabs[other]);
      pane.classList.toggle('hidden', !on);
      if (on) swapIn(pane);   // 换面板：crossfade + 4px 上浮
    });
  }));

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

/* ---------- 后台：用户（含原角色管理，合并页） ---------- */
/* 角色徽标与授权文案的术语表：super→平台管理员、admin→项目管理员、user→普通用户；
   授权列只给计数文案，不列 app 名。 */
const ROLE_LABEL = { super: '平台管理员', admin: '项目管理员', user: '普通用户' };
function scopeSummary(u) {
  if (u.role === 'super') return '管理全部项目';
  const n = Number(u.scopeCount || 0);
  return n > 0 ? `已授权 ${n} 个项目` : '未授权任何项目';
}

function initAdminUsers() {
  const body = $('#users-body');
  if (!body) return;
  const APPS = knownApps();
  const pager = makePager({ prev: '#users-prev', next: '#users-next', label: '#users-page', limit: 20 });

  // 确认弹窗：一次挂一个待执行动作 + 它的成功提示，确认后走 reauth 闸
  //（api() 401 自动弹重验框）——提示按操作分说，不统一糊一句「已生效」
  let pending = null;
  let lastDetail = { uid: 0, email: '' };
  function confirmAction(title, desc, done, fn, danger) {
    pending = { fn, done };
    $('#ud-dlg-title').textContent = title;
    $('#ud-dlg-desc').textContent = desc;
    $('#ud-dlg-ok').classList.toggle('danger', !!danger);
    showErr('#ud-dlg-error', '');
    openDialog($('#user-dialog'));
  }
  $('#ud-dlg-cancel').addEventListener('click', () => { pending = null; closeDialog($('#user-dialog')); });
  $('#user-dlg-form').addEventListener('submit', async e => {
    e.preventDefault();
    const job = pending;
    pending = null;
    closeDialog($('#user-dialog'));
    if (!job) return;
    try {
      await job.fn();
      toast(job.done);
      await load();
      if (lastDetail.uid) openDetail(lastDetail.uid, lastDetail.email);
    } catch (err) { toast(err.message, true); }
  });

  async function load() {
    showErr('#users-error', '');
    try {
      const st = pager.state;
      const res = await api(`/admin/users?query=${encodeURIComponent(st.query || '')}&limit=${st.limit}&offset=${st.offset}`);
      st.query = st.query || '';
      $('#users-total').textContent = `共 ${res.total} 个账号`;
      pager.set(res.total, res.items.length);
      body.innerHTML = '';
      if (!res.items.length) {
        body.innerHTML = '<tr><td colspan="8" class="empty">暂无匹配的用户</td></tr>';
        return;
      }
      res.items.forEach(u => {
        const tr = node(`
          <tr>
            <td class="wrap-cell">${esc(u.email)}</td>
            <td class="mono">${esc(u.uid)}</td>
            <td>${u.role === 'user' ? `<span class="badge">${ROLE_LABEL.user}</span>` : `<span class="badge on">${esc(ROLE_LABEL[u.role] || u.role)}</span>`}</td>
            <td>${esc(scopeSummary(u))}</td>
            <td>${u.totpEnabled ? '已开启' : '未开启'}</td>
            <td>${u.passkeyCount}</td>
            <td>${esc(fmtTime(u.createdAt))}</td>
            <td><button type="button" class="btn small">管理</button></td>
          </tr>`);
        tr.querySelector('button').addEventListener('click', () => openDetail(u.uid, u.email));
        body.appendChild(tr);
      });
    } catch (err) {
      showErr('#users-error', err.message);
      body.innerHTML = '<tr><td colspan="8" class="empty">读取失败</td></tr>';
    }
  }

  async function openDetail(uid, email) {
    lastDetail = { uid, email };
    const panel = $('#user-detail');
    const wasHidden = panel.classList.contains('hidden');
    panel.classList.remove('hidden');
    if (wasHidden) slideIn(panel);   // 首次展开做钻取滑入，重绘不重复播
    $('#ud-title').textContent = email;
    $('#ud-body').innerHTML = '<div class="empty">读取中…</div>';
    panel.scrollIntoView({ block: 'nearest' });
    try {
      const d = await api('/admin/users/' + uid);
      const scopes = d.scopes || [];
      const sessions = (d.sessions || []).map(s => `
        <div class="item">
          <span class="grow"><span class="title">${esc(s.device)}</span><br>
          <span class="meta">${esc(appLabel(s.app))} · ${esc(sessTag(s.id))} · ${esc(s.ip)} · 最近活跃 ${esc(relTime(s.lastSeenAt))}</span></span>
          <button type="button" class="btn small danger" data-kick="${esc(s.id)}">退出</button>
        </div>`).join('') || '<div class="empty">暂无活跃会话</div>';
      const passkeys = (d.passkeys || []).map(p =>
        `<li>${esc(p.name)} · ${esc(fmtTime(p.createdAt))}</li>`).join('') || '<li>未添加</li>';
      const isSelf = d.uid === window.__meUid;
      const roleCtl = `
        <label class="row" style="gap:8px"><span class="dim">角色</span>
          <select id="ud-role" ${isSelf ? 'disabled title="不能修改自己的角色"' : ''}>
            <option value="user"${d.role === 'user' ? ' selected' : ''}>普通用户</option>
            <option value="admin"${d.role === 'admin' ? ' selected' : ''}>项目管理员</option>
            <option value="super"${d.role === 'super' ? ' selected' : ''}>平台管理员</option>
          </select>
        </label>
        <button type="button" class="btn small primary" id="ud-save-role" ${isSelf ? 'disabled' : ''}>保存角色</button>`;
      // 应用授权开关：选项来自服务端注册表（known-apps JSON），不再硬编码 app 清单；
      // super 无需按应用授权（平台级自带全部范围）
      const scopeList = d.role === 'super'
        ? '<div class="empty">平台管理员不受项目授权限制，管理全部项目。</div>'
        : APPS.map(app => {
            const granted = scopes.indexOf(app.key) >= 0;
            return `<div class="item">
              <span class="grow"><span class="title">${esc(app.label)}</span><br>
              <span class="meta">${granted ? '已授权' : '未授权'}</span></span>
              <button type="button" class="btn small ${granted ? 'danger' : 'primary'}" data-app="${esc(app.key)}" data-op="${granted ? 'revoke' : 'grant'}">
                ${granted ? '回收' : '授予'}
              </button>
            </div>`;
          }).join('');
      $('#ud-body').innerHTML = `
        <div class="grid2">
          <div><span class="dim">uid</span><br><span class="mono">${esc(d.uid)}</span></div>
          <div><span class="dim">注册时间</span><br>${esc(fmtTime(d.createdAt))}</div>
          <div><span class="dim">密码</span><br>${d.hasPassword ? '已设置' : '未设置'}</div>
          <div><span class="dim">两步验证</span><br>${d.totpEnabled ? '已开启' : '未开启'}</div>
        </div>
        <h3>角色与项目授权</h3>
        <div class="row" style="gap:8px;flex-wrap:wrap">${roleCtl}</div>
        <p class="hint">授予项目即成为项目管理员；全部项目都回收后角色自动降回普通用户。平台管理员的授予/撤销仅平台管理员可操作。</p>
        <div class="list">${scopeList}</div>
        <h3>Passkey</h3><ul>${passkeys}</ul>
        <h3>活跃会话</h3><div class="list">${sessions}</div>
        <div class="detail row">
          <button type="button" class="btn small danger" id="ud-kick-all">退出该用户全部会话</button>
        </div>`;
      $$('#ud-body [data-kick]').forEach(btn => btn.addEventListener('click', async () => {
        try {
          await api('/admin/sessions/' + btn.dataset.kick, { method: 'DELETE' });
          toast('已退出该会话');
          openDetail(uid, email);
        } catch (err) { toast(err.message, true); }
      }));
      $$('#ud-body [data-app]').forEach(btn => btn.addEventListener('click', () => {
        const app = btn.dataset.app;
        const op = btn.dataset.op;
        confirmAction(
          op === 'grant' ? '授予项目管理员' : '回收项目管理员',
          op === 'grant'
            ? `将「${appLabel(app)}」的管理权授予该用户（角色自动提为项目管理员）。`
            : `回收「${appLabel(app)}」的管理权；全部项目都回收后，该用户的角色会降回普通用户。`,
          op === 'grant' ? `已授予「${appLabel(app)}」管理权` : `已回收「${appLabel(app)}」的管理权`,
          () => api(`/admin/roles/${uid}/scope`, { method: 'POST', body: { app, op } }),
          op === 'revoke');
      }));
      const saveRole = $('#ud-save-role');
      if (saveRole) saveRole.addEventListener('click', () => {
        const role = $('#ud-role').value;
        confirmAction(
          '调整角色',
          role === 'super'
            ? `将该用户设为平台管理员：可管理全部项目、用户目录与全局配置。`
            : role === 'admin'
              ? '将该用户设为项目管理员：需再授予至少一个项目才有实际管理范围。'
              : '将该用户降为普通用户：项目授权会一并收回。',
          role === 'super' ? '已设为平台管理员'
            : role === 'admin' ? '已设为项目管理员' : '已降为普通用户',
          () => api(`/admin/users/${uid}/role`, { method: 'POST', body: { role } }),
          role === 'user');
      });
      $('#ud-kick-all').addEventListener('click', () => {
        confirmAction(
          '退出该用户全部会话',
          '该用户的所有设备（含网页端）都会退出登录，需要重新登录。',
          '已退出该用户全部会话',
          () => api(`/admin/users/${uid}/revoke-sessions`, { method: 'POST', body: {} }),
          true);
      });
    } catch (err) {
      $('#ud-body').innerHTML = `<p class="err">${esc(err.message)}</p>`;
    }
  }

  $('#ud-close').addEventListener('click', () => $('#user-detail').classList.add('hidden'));
  $('#user-search-form').addEventListener('submit', e => {
    e.preventDefault();
    pager.state.query = $('#user-query').value.trim();
    pager.state.offset = 0;
    load();
  });
  pager.wire(load);
  load();
}

/* ---------- 后台：会话总览（uid 先行钻取） ----------
   层级一按用户聚合（邮箱/uid/会话数/最近活跃），点「查看会话」滑入层级二
   逐条管理。聚合数据来自 GET /admin/sessions 自身（super 与 app-admin 同一条路：
   /admin/users 是 super 专属端点，app-admin 调它只会 403）。 */
function initAdminSessions() {
  const ubody = $('#sess-users-body');
  if (!ubody) return;
  // 不给 makePager 传 label：页码文案按**用户**说（见 loadUsers），按钮仍按会话数分页
  const pager = makePager({ prev: '#sess-prev', next: '#sess-next', limit: 100 });

  async function loadUsers() {
    showErr('#sess-error', '');
    try {
      const st = pager.state;
      // 搜索走服务端 ?query=（邮箱片段或 uid，join users 过滤）：在本页 100 条会话上
      // 本地过滤会漏掉本页之外的用户，total/totalUsers 也不成立
      const res = await api(`/admin/sessions?query=${encodeURIComponent(st.query || '')}${appFilter()}&limit=${st.limit}&offset=${st.offset}`);
      // 按 uid 聚合成本页的用户行
      const map = new Map();
      (res.items || []).forEach(s => {
        const cur = map.get(s.uid) || { uid: s.uid, email: s.email, count: 0, last: 0 };
        cur.count += 1;
        cur.last = Math.max(cur.last, Number(s.lastSeenAt || 0));
        map.set(s.uid, cur);
      });
      const users = [...map.values()];
      $('#sess-total').textContent = `共 ${res.total} 条活跃会话`;
      pager.set(res.total, (res.items || []).length);
      $('#sess-page').textContent =
        `第 ${Math.floor(st.offset / st.limit) + 1} 页 · 共 ${res.totalUsers || 0} 位用户`;
      ubody.innerHTML = '';
      if (!users.length) {
        ubody.innerHTML = '<tr><td colspan="5" class="empty">暂无匹配的活跃会话</td></tr>';
        return;
      }
      users.sort((a, b) => b.last - a.last);
      users.forEach(u => {
        const tr = node(`
          <tr>
            <td class="wrap-cell">${esc(u.email)}</td>
            <td class="mono">${esc(u.uid)}</td>
            <td>${u.count}</td>
            <td>${esc(relTime(u.last))}</td>
            <td><button type="button" class="btn small">查看会话</button></td>
          </tr>`);
        tr.querySelector('button').addEventListener('click', () => openDetail(u.uid, u.email));
        ubody.appendChild(tr);
      });
    } catch (err) {
      showErr('#sess-error', err.message);
      ubody.innerHTML = '<tr><td colspan="5" class="empty">读取失败</td></tr>';
    }
  }

  async function openDetail(uid, email) {
    const panel = $('#sess-detail');
    const wasHidden = panel.classList.contains('hidden');
    panel.classList.remove('hidden');
    if (wasHidden) slideIn(panel);   // 页内钻取：右滑进入
    $('#sd-title').textContent = email;
    $('#sd-meta').textContent = `uid ${uid} · 点击「退出」可逐条退出会话。`;
    $('#sd-body').innerHTML = '<div class="empty">读取中…</div>';
    panel.scrollIntoView({ block: 'nearest' });
    try {
      const res = await api(`/admin/sessions?uid=${encodeURIComponent(String(uid))}${appFilter()}&limit=100`);
      const items = res.items || [];
      if (!items.length) {
        $('#sd-body').innerHTML = '<div class="empty">该用户已无活跃会话。</div>';
        return;
      }
      $('#sd-body').innerHTML = '';
      items.sort((a, b) => Number(b.lastSeenAt || 0) - Number(a.lastSeenAt || 0)).forEach(s => {
        const el = node(`
          <div class="item" data-id="${esc(s.id)}">
            <span class="ico-wrap">${deviceIcon(s.device)}</span>
            <span class="grow">
              <span class="title">${esc(s.device)}</span> <span class="mono sess-tag">${esc(sessTag(s.id))}</span>
              <br><span class="meta">${esc(appLabel(s.app))} · ${esc(s.ip)} · 最近活跃 ${esc(relTime(s.lastSeenAt))}</span>
            </span>
            <button type="button" class="btn small danger">退出</button>
          </div>`);
        el.querySelector('button').addEventListener('click', async () => {
          try {
            await api('/admin/sessions/' + s.id, { method: 'DELETE' });
            toast('已退出该会话');
            fadeOutRow(el, () => openDetail(uid, email));
          } catch (err) { toast(err.message, true); }
        });
        $('#sd-body').appendChild(el);
      });
    } catch (err) {
      $('#sd-body').innerHTML = `<p class="err">${esc(err.message)}</p>`;
    }
  }

  $('#sd-close').addEventListener('click', () => $('#sess-detail').classList.add('hidden'));
  $('#sess-user-search-form').addEventListener('submit', e => {
    e.preventDefault();
    pager.state.query = $('#sess-user-query').value.trim();
    pager.state.offset = 0;
    loadUsers();
  });
  pager.wire(loadUsers);
  document.addEventListener('appscopechange', e => {
    e.preventDefault();
    pager.state.offset = 0;
    $('#sess-detail').classList.add('hidden');
    loadUsers().then(() => swapIn($('#sess-users-view')));
  });
  loadUsers();
}

/* ---------- 后台：审计 ---------- */
/* 详情列的可读排版：{k:v, k:v} 代替裸 JSON——审计行的 detail 是小对象，
   键值平铺一眼能读，不用先在脑子里 parse。 */
function detailText(d) {
  if (d == null || d === '') return '—';
  if (typeof d !== 'object') return esc(String(d));
  const keys = Object.keys(d);
  if (!keys.length) return '—';
  return keys.map(k => {
    const v = d[k];
    const vs = (v && typeof v === 'object') ? JSON.stringify(v) : String(v);
    return `<span class="kv"><span class="dim">${esc(k)}:</span> ${esc(vs)}</span>`;
  }).join(' ');
}

function initAdminAudit() {
  const body = $('#audit-body');
  if (!body) return;
  const pager = makePager({ prev: '#audit-prev', next: '#audit-next', label: '#audit-page', limit: 50 });

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
    // 项目切换器的 app 过滤器（?app=，空 = 全部/全部授权）
    const app = new URLSearchParams(location.search).get('app');
    if (app) p.set('app', app);
    p.set('limit', String(pager.state.limit));
    p.set('offset', String(pager.state.offset));
    return p.toString();
  }

  async function load() {
    showErr('#audit-error', '');
    try {
      const res = await api('/admin/audit?' + filters());
      pager.set(res.total, res.items.length);
      body.innerHTML = '';
      if (!res.items.length) {
        body.innerHTML = '<tr><td colspan="7" class="empty">暂无匹配的审计记录</td></tr>';
        return;
      }
      res.items.forEach(it => {
        const who = it.actorUid ? `${it.actorUid} ${it.actorEmail || ''}` : (it.actorEmail || '匿名');
        body.appendChild(node(`
          <tr>
            <td>${esc(fmtTime(it.ts))}</td>
            <td class="mono">${esc(it.action)}</td>
            <td>${it.result === 'ok' ? '<span class="badge on">成功</span>' : '<span class="badge warn">失败</span>'}</td>
            <td class="wrap-cell">${esc(who)}</td>
            <td class="mono">${it.targetUid ? esc(it.targetUid) : '—'}</td>
            <td class="mono">${esc(it.ip || '—')}</td>
            <td class="wrap-cell detail-cell">${detailText(it.detail)}</td>
          </tr>`));
      });
    } catch (err) {
      showErr('#audit-error', err.message);
      body.innerHTML = '<tr><td colspan="7" class="empty">读取失败</td></tr>';
    }
  }

  $('#audit-filter-form').addEventListener('submit', e => { e.preventDefault(); pager.state.offset = 0; load(); });
  $('#audit-reset').addEventListener('click', () => {
    $('#audit-action').value = ''; $('#audit-actor').value = ''; $('#audit-target').value = '';
    $('#audit-from').value = ''; $('#audit-to').value = '';
    pager.state.offset = 0; load();
  });
  pager.wire(load);
  document.addEventListener('appscopechange', e => {
    e.preventDefault();
    pager.state.offset = 0;
    load().then(() => swapIn($('.table-wrap')));
  });
  load();
}

/* ---------- 后台：配置中心（只留 LLM 大模型卡） ----------
   邮件/注销钩子/FCM/AI 限额四组从页面隐藏（后端键一个不动；AI 限额的改动
   入口收敛到「AI 用量」页的「编辑限额」弹层）。 */
function initAdminConfig() {
  const wrap = $('#cfg-groups');
  if (!wrap) return;
  const GROUPS = [
    { prefix: 'llm_', title: 'LLM 大模型' },
  ];
  const LABELS = {
    llm_api_key: 'API 密钥', llm_base_url: '接口地址', llm_model: '模型名',
  };
  let pendingClear = '';

  async function load() {
    showErr('#cfg-error', '');
    try {
      const items = await api('/admin/config');
      wrap.innerHTML = '';
      let rendered = 0;
      GROUPS.forEach(g => {
        const mine = items.filter(it => it.key.indexOf(g.prefix) === 0);
        if (!mine.length) return;
        rendered += 1;
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
      if (!rendered) wrap.innerHTML = '<div class="empty">暂无配置项。</div>';
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

/* ---------- 后台：AI 用量（KPI + 趋势 + 用户表 + 钻取 + 编辑限额） ---------- */
/* 占比列：share 是服务端算好的 0..1 比例（区间用量 / 全站区间合计）。 */
function pctText(share) {
  return Math.round(Number(share || 0) * 100) + '%';
}

function initAdminAI() {
  const bars = $('#ai-bars');
  if (!bars) return;
  let lastDetailUID = 0;

  /* 迷你走势：近 7 根竖条（纯 div，高度按天数占比；零值给 2px 保底可见）。
     days 是日期升序（服务端铺满窗口、缺日补 0），近 7 天 = 末尾 7 项。 */
  function renderSpark(days) {
    const spark = $('#kpi-spark');
    const last7 = (days || []).slice(-7);
    const max = Math.max(1, ...last7.map(d => Number(d.count || 0)));
    spark.innerHTML = '';
    last7.forEach(d => {
      const n = Number(d.count || 0);
      const col = document.createElement('i');
      col.style.height = (n > 0 ? Math.max(8, Math.round(n / max * 100)) : 4) + '%';
      spark.appendChild(col);
    });
    $('#kpi-spark-hint').textContent = last7.length
      ? `${last7[0].date} → ${last7[last7.length - 1].date}`
      : '暂无数据';
  }

  async function load() {
    showErr('#ai-error', '');
    const days = $('#ai-days').value;
    try {
      const rep = await api('/admin/ai-usage?days=' + encodeURIComponent(days) + appFilter());
      // ---- KPI ----
      const today = Number(rep.today || 0), yday = Number(rep.yesterday || 0);
      $('#kpi-today-val').textContent = today + ' 次';
      let deltaTxt;
      if (yday > 0) {
        const diff = today - yday;
        const pct = Math.round(Math.abs(diff) / yday * 100);
        deltaTxt = diff === 0 ? '与昨日持平' : `较昨日${diff > 0 ? '↑' : '↓'} ${pct}%（${diff > 0 ? '+' : ''}${diff}）`;
      } else {
        deltaTxt = '昨日无用量';
      }
      $('#kpi-today-delta').textContent = deltaTxt;

      const g = rep.global;
      if (g) {
        const used = Number(g.used || 0), limit = Number(g.limit || 0);
        $('#kpi-global-val').textContent = limit > 0 ? `${used} / ${limit} 次` : `${used} 次`;
        $('#kpi-global-bar').style.width = (limit > 0 ? Math.min(100, Math.round(used / limit * 100)) : 0) + '%';
        $('#kpi-global-hint').textContent = rep.defaultsUsed
          ? '限额为默认值（ai_* 配置键未配齐）。'
          : '限额来自配置中心。';
      } else {
        // app-admin 视角 global 是 null（跨项目数据收权隐藏），如实显示而非「0 次」
        $('#kpi-global-val').textContent = '—';
        $('#kpi-global-bar').style.width = '0%';
        $('#kpi-global-hint').textContent = '全站余量仅平台管理员可见。';
      }

      $('#kpi-active-val').textContent = Number(rep.activeToday || 0) + ' 人';
      renderSpark(rep.days);

      // ---- 每日趋势 ----
      // 今日合计取 rep.today（今天没打点就如实显示 0），不拿 days[0] 冒充
      $('#ai-today').textContent = `今日（${todayStr()}）合计 ${today} 次`;
      const list = rep.days || [];
      if (!list.length) {
        bars.innerHTML = '';
        $('#ai-empty').classList.remove('hidden');
      } else {
        $('#ai-empty').classList.add('hidden');
        const max = Math.max(1, ...list.map(d => Number(d.count || 0)));
        bars.innerHTML = '';
        list.forEach(d => {
          const n = Number(d.count || 0);
          const pct = max > 0 ? Math.max(2, Math.round(n / max * 100)) : 0;
          bars.appendChild(node(`
            <div class="bar-row">
              <span class="dim">${esc(d.date)}</span>
              <span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>
              <span class="bar-num">${n}</span>
            </div>`));
        });
      }

      // ---- 用户表（服务端已按区间用量降序，原样渲染不再重排——提示文案与实现同口径） ----
      const ubody = $('#ai-users-body');
      const users = rep.users || [];
      ubody.innerHTML = '';
      if (!users.length) {
        ubody.innerHTML = '<tr><td colspan="5" class="empty">所选区间内暂无用户用量。</td></tr>';
        return;
      }
      users.forEach(u => {
        const uToday = Number(u.today || 0);
        const uLimit = Number(u.limitToday || 0);
        const left = uLimit > 0 ? Math.max(0, uLimit - uToday) : 0;
        const leftPct = uLimit > 0 ? Math.round(left / uLimit * 100) : 0;
        const tr = node(`
          <tr class="ai-user-row" data-uid="${esc(u.uid)}" tabindex="0" role="button" aria-label="查看 ${esc(u.email)} 的用量明细">
            <td class="wrap-cell">${esc(u.email)} <span class="mono dim">${esc(u.uid)}</span></td>
            <td>${uToday}</td>
            <td>${Number(u.range || 0)}</td>
            <td>${esc(pctText(u.share))}</td>
            <td>
              <span class="bar-track" style="min-width:120px;display:inline-block;vertical-align:middle"><span class="bar-fill" style="width:${leftPct}%"></span></span>
              <span class="dim">${uLimit > 0 ? `剩 ${left}/${uLimit}` : '—'}</span>
            </td>
          </tr>`);
        const open = () => openDetail(u.uid, u.email);
        tr.addEventListener('click', open);
        tr.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
        ubody.appendChild(tr);
      });
    } catch (err) {
      showErr('#ai-error', err.message);
      $('#ai-users-body').innerHTML = '<tr><td colspan="5" class="empty">读取失败，请刷新重试</td></tr>';
    }
  }

  async function loadDetail() {
    const uid = lastDetailUID;
    if (!uid) return;
    try {
      const d = await api(`/admin/ai-usage?days=${encodeURIComponent($('#aid-days').value)}&uid=${encodeURIComponent(String(uid))}${appFilter()}`);
      $('#aid-meta').textContent = `${d.email} · 今日 ${Number(d.today || 0)} 次`;
      const todayN = Number(d.today || 0), limit = Number(d.limitToday || 0);
      $('#aid-limit-bar').style.width = (limit > 0 ? Math.min(100, Math.round(todayN / limit * 100)) : 0) + '%';
      $('#aid-limit-hint').textContent = limit > 0
        ? `今日已用 ${todayN} / ${limit} 次（每日限额）。`
        : '未配置每日限额。';
      const list = d.days || [];
      const box = $('#aid-bars');
      if (!list.length) {
        box.innerHTML = '';
        $('#aid-empty').classList.remove('hidden');
        return;
      }
      $('#aid-empty').classList.add('hidden');
      const max = Math.max(1, ...list.map(x => Number(x.count || 0)));
      box.innerHTML = '';
      list.forEach(x => {
        const n = Number(x.count || 0);
        box.appendChild(node(`
          <div class="bar-row">
            <span class="dim">${esc(x.date)}</span>
            <span class="bar-track"><span class="bar-fill" style="width:${Math.max(2, Math.round(n / max * 100))}%"></span></span>
            <span class="bar-num">${n}</span>
          </div>`));
      });
    } catch (err) { $('#aid-meta').textContent = err.message; }
  }

  function openDetail(uid, email) {
    lastDetailUID = uid;
    const panel = $('#ai-detail');
    const wasHidden = panel.classList.contains('hidden');
    panel.classList.remove('hidden');
    if (wasHidden) slideIn(panel);   // 页内钻取：右滑进入
    $('#aid-title').textContent = email + ' 的用量';
    // 打开即重置状态：清掉上一个用户的明细（否则新数据回来前挂着旧的）
    $('#aid-meta').textContent = '读取中…';
    $('#aid-bars').innerHTML = '';
    $('#aid-empty').classList.add('hidden');
    panel.scrollIntoView({ block: 'nearest' });
    loadDetail();
  }
  $('#aid-close').addEventListener('click', () => $('#ai-detail').classList.add('hidden'));
  $('#aid-days').addEventListener('change', loadDetail);

  // ---- 编辑限额（super only，按钮在模板层由 .IsSuper 门控） ----
  // 四键一处定义：预填、校验、报错文案全部从它派生——报错说中文名，
  // 不把配置键名甩给管理员（模板里的四个 field label 与这里同名）
  const QUOTA_FIELDS = [
    { key: 'ai_rate_per_minute', sel: '#q-input-rate', label: '每用户每分钟次数' },
    { key: 'ai_concurrency', sel: '#q-input-conc', label: '全站并发' },
    { key: 'ai_daily_per_user', sel: '#q-input-user', label: '每用户每日' },
    { key: 'ai_daily_global', sel: '#q-input-global', label: '全站每日' },
  ];
  const quotaBtn = $('#ai-edit-quota');
  if (quotaBtn) {
    quotaBtn.addEventListener('click', async () => {
      showErr('#quota-error', '');
      // 预填当前配置值（未配置的键留空）
      QUOTA_FIELDS.forEach(f => { $(f.sel).value = ''; });
      try {
        const items = await api('/admin/config');
        const byKey = Object.fromEntries(QUOTA_FIELDS.map(f => [f.key, f]));
        items.filter(it => byKey[it.key] && it.configured)
          .forEach(it => { $(byKey[it.key].sel).value = it.value; });
      } catch (_) { /* 预填失败不拦打开：可直接填新值 */ }
      openDialog($('#quota-dialog'));
    });
    $('#quota-cancel').addEventListener('click', () => closeDialog($('#quota-dialog')));
    $('#quota-form').addEventListener('submit', async e => {
      e.preventDefault();
      showErr('#quota-error', '');
      const todo = [];
      for (const f of QUOTA_FIELDS) {
        const v = $(f.sel).value.trim();
        if (!v) continue;   // 留空 = 不改
        if (!/^\d+$/.test(v) || Number(v) <= 0) {
          showErr('#quota-error', `${f.label}必须是正整数`); return;
        }
        todo.push([f.key, v]);
      }
      if (!todo.length) { closeDialog($('#quota-dialog')); return; }
      const btn = $('#quota-ok');
      setBusy(btn, true);
      try {
        for (const [key, v] of todo) {
          await api('/admin/config/' + encodeURIComponent(key), { method: 'PUT', body: { value: v } });
        }
        closeDialog($('#quota-dialog'));
        toast('限额已保存，≤10 秒生效');
        await load();
      } catch (err) { showErr('#quota-error', err.message); } finally { setBusy(btn, false); }
    });
  }

  $('#ai-days').addEventListener('change', load);
  document.addEventListener('appscopechange', e => {
    e.preventDefault();
    $('#ai-detail').classList.add('hidden');
    load().then(() => swapIn($('#ai-kpis')));
  });
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
  initAppSwitch();
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
