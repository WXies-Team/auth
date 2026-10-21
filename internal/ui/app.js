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

/* 时间渲染统一做 0 值防御：0 / 负值 / 字符串 "0" / NaN 一律当「没有时间」，
   不渲染 1970-01-01 这类纪元日期（服务端对「从未使用/未记录」回 0）。 */
function fmtTime(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const d = new Date(n);
  const p = v => String(v).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function todayStr() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function relTime(ms) {
  const t = Number(ms);
  if (!Number.isFinite(t) || t <= 0) return '—';
  const diff = Date.now() - t;
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

/* remainTime 是 relTime 的未来向镜像（邀请有效期这类「还有多久」）：relTime 按
   「过去了多久」算，打在未来的毫秒上恒回「刚刚」——不能拿来显示剩余。
   同一套梯度（分钟/小时/天），向上取整且至少 1 分钟（「1 分钟内有效」比
   「不足 1 分钟」好读）；>30 天回绝对时间（与 relTime 的长跨度口径一致）。 */
function remainTime(ms) {
  const t = Number(ms);
  if (!Number.isFinite(t) || t <= 0) return '—';
  const left = Math.max(0, t - Date.now());
  const min = Math.ceil(left / 60000);
  if (min < 60) return `${min} 分钟`;
  const hour = Math.ceil(min / 60);
  if (hour < 24) return `${hour} 小时`;
  const day = Math.ceil(hour / 24);
  if (day <= 30) return `${day} 天`;
  return fmtTime(t);
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

/* 跨页提示：跳转前把提示存进 sessionStorage，目标页 DOMContentLoaded 时 drain 出来
   （注销撤销 / 强制改密成功 / 注销已提交都要「跳走之后还看得见一句 toast」）。 */
function flash(msg) {
  try { sessionStorage.setItem('auth_flash', msg); } catch (_) { /* 隐私模式等存储不可用：放弃提示，不拦流程 */ }
}
function drainFlash() {
  let msg = '';
  try {
    msg = sessionStorage.getItem('auth_flash') || '';
    if (msg) sessionStorage.removeItem('auth_flash');
  } catch (_) { return; }
  if (msg) toast(msg);
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

/* ---------- 重新验证弹框（W2 分步：先密码，开了两步验证再要一个码） ----------
   接线说明（现状是**单接口带三字段**，服务端 /web/reauth 密码/两步码/恢复码三选一）：
   这里做成前端两段、**两次都打同一个既有接口**——第一步 POST {password}（服务端
   当场验密码，错密码在这里就报），成功后按 /web/session 回执的 totpEnabled 决定
   是否进第二步；第二步 POST {totpCode|recoveryCode}（服务端验因子），成功才收口。
   无 2FA 账号第一步即完成。接口一个没加、一个没改。 */
let reauthResolver = null;
let reauthStep = 'password';   // 'password' | 'code'
let reauthTotp = null;         // 打开弹框时发起的两步验证状态查询（Promise<boolean>）

/* 步切换沿用 dlg 内既有交叉淡入（swapIn，reduced-motion 自动跳过） */
function reauthShowStep(step) {
  reauthStep = step;
  const s1 = $('#reauth-step1'), s2 = $('#reauth-step2');
  if (!s1 || !s2) return;
  const toCode = step === 'code';
  s1.classList.toggle('hidden', toCode);
  s2.classList.toggle('hidden', !toCode);
  if (!toCode) swapIn(s1); else swapIn(s2);
}

function promptReauth() {
  return new Promise(resolve => {
    const dlg = $('#reauth');
    if (!dlg) { resolve(false); return; }
    reauthResolver = resolve;
    showErr('#reauth-error', '');
    $('#reauth-password').value = '';
    $('#reauth-code').value = '';
    if (window.__reauthToggle) window.__reauthToggle.reset();
    // 每次打开都回第一步；两步验证状态同步去问一次（第一步提交后据此分流）
    reauthStep = 'password';
    $('#reauth-step1').classList.remove('hidden');
    $('#reauth-step2').classList.add('hidden');
    reauthTotp = api('/web/session', { method: 'POST', body: {}, noReauth: true })
      .then(me => !!(me && me.totpEnabled))
      .catch(() => false);   // 状态取不到按「没有 2FA」走：密码已过即收口，不卡流程
    if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
    $('#reauth-password').focus();
  });
}

function closeReauth(ok) {
  const dlg = $('#reauth');
  if (dlg && dlg.open) dlg.close();
  reauthStep = 'password';
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
    const btn = $('#reauth-ok');
    if (reauthStep === 'password') {
      const password = $('#reauth-password').value;
      if (!password) { showErr('#reauth-error', '请输入密码'); return; }
      setBusy(btn, true);
      try {
        await api('/web/reauth', { method: 'POST', body: { password }, noReauth: true });
        if (reauthTotp && await reauthTotp) {
          reauthShowStep('code');   // 账号开了两步验证：进第二步收一个码
          $('#reauth-code').focus();
        } else {
          closeReauth(true);        // 无 2FA：一步到位
        }
      } catch (err) {
        showErr('#reauth-error', err.message);
      } finally {
        setBusy(btn, false);
      }
      return;
    }
    // 第二步：按当前 N 态决定字段（恢复码 ↔ 两步验证码），空输入前端先挡
    const useRecovery = window.__reauthToggle.mode() === 'recovery';
    const totpCode = useRecovery ? '' : $('#reauth-code').value.trim();
    const recoveryCode = useRecovery ? $('#reauth-code').value.trim() : '';
    if (!totpCode && !recoveryCode) {
      showErr('#reauth-error', useRecovery ? '请输入恢复码' : '请输入两步验证码'); return;
    }
    setBusy(btn, true);
    try {
      await api('/web/reauth', {
        method: 'POST', body: { totpCode, recoveryCode }, noReauth: true,
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

/* 平台管理员标记：layout 按 Data.IsSuper 渲染 body[data-super]（与管理入口同一份
   模板层门控依据），JS 侧 super 专属控件读它，不再自查角色。 */
const IS_SUPER = document.body.hasAttribute('data-super');

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

  // ---- 登录完成回执（W1）：注销撤销提示 + 强制改密步 ----
  // 四条登录路（密码 / 两步完成 / 邮箱验证码 / Passkey）都收口到这里：
  // deletePendingCancelled=true → toast 提示（跳走时改存 flash，下一页 drain）；
  // mustChangePassword=true → 顶替整个卡片进「请设置新密码」步，oldPassword 带
  // 这次登录实际用过的密码（Passkey/验证码登录没有，传空串——契约已放宽）。
  // OAuth 续跑（B4）：?tx= 在场时登录完成回授权确认页而不是控制台（tx 是服务端
  // 一次性事务号，只回站内 /oauth/resume，无开放重定向面）。
  const oauthTx = new URLSearchParams(location.search).get('tx');
  const loginLanding = () =>
    oauthTx ? '/oauth/resume?tx=' + encodeURIComponent(oauthTx) : '/web/console';
  let forceOldPw = '';
  function finishLogin(res, pwd) {
    const cancelled = !!(res && res.deletePendingCancelled);
    if (res && res.mustChangePassword) {
      if (cancelled) toast('已撤销账号注销，账号恢复正常');
      showForcePassword(pwd);
      return;
    }
    if (cancelled) flash('已撤销账号注销，账号恢复正常');
    location.href = loginLanding();
  }
  function showForcePassword(pwd) {
    forceOldPw = pwd || '';
    // 步切换沿用既有区块动效；残留报错一并清掉（换步即换语义）
    $('#login-tabs').classList.add('hidden');
    ['#pane-password', '#pane-code', '#pane-reset', '#passkey-sep', '#passkey-login']
      .forEach(sel => { const el = $(sel); if (el) el.classList.add('hidden'); });
    const step = $('#step-force-pw');
    step.classList.remove('hidden');
    showErr('#force-pw-error', '');
    $('#force-pw-new').value = ''; $('#force-pw-confirm').value = '';
    swapIn(step);
    $('#force-pw-new').focus();
  }
  $('#step-force-pw').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#force-pw-error', '');
    const nw = $('#force-pw-new').value, cf = $('#force-pw-confirm').value;
    if (nw.length < 8) { showErr('#force-pw-error', '新密码至少 8 位'); return; }
    if (nw !== cf) { showErr('#force-pw-error', '两次输入的新密码不一致'); return; }
    const btn = $('#force-pw-submit');
    setBusy(btn, true);
    try {
      await api('/auth/change-password', {
        method: 'POST', body: { oldPassword: forceOldPw, newPassword: nw },
      });
      // 服务器已随回执刷新会话 cookie；提示跳走后在控制台 drain 出来。
      // OAuth 续跑同款：强制改密完成后也回授权确认页（?tx= 在场时）
      flash('密码已更新');
      location.href = loginLanding();
    } catch (err) { showErr('#force-pw-error', err.message); } finally { setBusy(btn, false); }
  });

  // ---- 密码 →（2FA）三模式：验证器码 / 邮箱码 / 恢复码（GitHub 式单输入原地换语义）----
  // 与两个弹框同一个 makeCodeToggle：三态与二态的差别只是配置（多一组邮箱码态、
  // 多两个切换按钮、每态一段 intro），apply 收口的属性同步/清值/清旧报错/聚焦一处不变。
  let loginToken = '';
  let enteredPw = '';   // 密码登录这一步用过的密码（服务端确认正确后才记），强制改密时作 oldPassword
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
        hide: ['#send-2fa-code'], show: ['#toggle-email'],
        buttons: {
          '#toggle-email': '没有验证器？获取邮箱验证码',
          '#toggle-recovery': '使用恢复码',
        },
        intro: '该账号已开启两步验证：请输入验证器上的 6 位验证码完成登录。',
      },
      email: {
        label: '邮箱验证码（6 位）', placeholder: '输入邮箱里收到的 6 位验证码', numeric: true,
        show: ['#send-2fa-code', '#toggle-email'],
        buttons: {
          '#toggle-email': '换回验证器验证码',
          '#toggle-recovery': '使用恢复码',
        },
        intro: '该账号已开启两步验证：请输入邮箱里的 6 位验证码完成登录。',
      },
      recovery: {
        label: '恢复码', placeholder: 'XXXX-XXXX-XXXX-XXXX', numeric: false,
        // 邮箱码专属的发码按钮收起；toggle-email 藏起来，免得摆一个点了没反应的按钮
        hide: ['#send-2fa-code', '#toggle-email'],
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
        const pwd = $('#login-password').value;
        const res = await api('/web/login/password', {
          method: 'POST',
          body: { email: $('#login-email').value.trim(), password: pwd },
        });
        if (res.status === '2fa_required') {
          loginToken = res.loginToken;
          enteredPw = pwd;   // 密码已被服务端确认正确：第二步完成后留给强制改密步
          useTotpStep(true);
          return;
        }
        finishLogin(res, pwd);
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
      const done = await api('/web/login/totp', { method: 'POST', body });
      finishLogin(done, enteredPw);   // 强制改密时把第一步确认过的密码带上
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
      const done = await api('/web/login/email-code', {
        method: 'POST',
        body: { email: $('#code-email').value.trim(), code: $('#code-code').value.trim() },
      });
      finishLogin(done);   // 验证码登录没有密码可带，强制改密时 oldPassword 传空串
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
        const done = await api('/webauthn/login/finish', {
          method: 'POST',
          body: { ceremonyId: opts.ceremonyId, response: assertionJSON(cred) },
        });
        finishLogin(done);   // Passkey 登录没有密码可带，强制改密时 oldPassword 传空串
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

/* 会话行：项目名 + 最近活跃（相对时间），行尾「详情」展开首次登录时间与 IP。
   不再显示 session 尾号短标识——行内分组已带设备名，尾号对用户没有信息量。 */

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
                  <span class="title">${esc(appLabel(it.app))} · 最近活跃 ${esc(relTime(it.lastSeenAt))}</span>
                  ${it.current ? '<span class="badge on">本设备</span>' : ''}
                </span>
                <button type="button" class="btn small ghost" data-act="more" aria-expanded="false">详情</button>
                ${it.current ? '' : '<button type="button" class="btn small danger">退出</button>'}
                <div class="sess-more hidden">首次登录 ${esc(fmtTime(it.createdAt))} · IP ${esc(it.ip)}</div>
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
          openDialog($('#kick-dialog'), '#kick-cancel');
        });
      }
      $$('.session-row', el).forEach(row => {
        const it = g.items.find(i => String(i.id) === row.dataset.id);
        // 「详情」展开首次登录时间与 IP（GitHub See-more 式）：收起态 .hidden 不占
        // 行高；展开进场复用既有 swapIn（reduced-motion 自动跳过，只换显示状态）
        const more = row.querySelector('[data-act=more]');
        more.addEventListener('click', () => {
          const detail = row.querySelector('.sess-more');
          const collapsed = detail.classList.toggle('hidden');
          more.setAttribute('aria-expanded', String(!collapsed));
          more.textContent = collapsed ? '详情' : '收起';
          if (!collapsed) swapIn(detail);
        });
        const kick = row.querySelector('button.danger');
        if (!kick) return;
        kick.addEventListener('click', () => {
          pending = { mode: 'one', ids: [row.dataset.id], label: it ? appLabel(it.app) : '', count: 1 };
          $('#kick-title').textContent = '退出这条会话';
          $('#kick-desc').textContent = `将退出「${g.device}」上的「${pending.label}」会话，它下次请求时会退出登录。`;
          $('#kick-ok').textContent = '退出会话';
          openDialog($('#kick-dialog'), '#kick-cancel');
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
    openDialog($('#kick-dialog'), '#kick-cancel');
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
        // lastUsedAt<=0/缺失 = 从未用过：只说「从未使用」，不渲染 1970 日期
        const lastUsed = Number(it.lastUsedAt || 0) > 0
          ? `最近使用 ${esc(relTime(it.lastUsedAt))}` : '从未使用';
        const el = node(`
          <div class="item" data-id="${it.id}">
            <span class="grow">
              <span class="title pk-name">${esc(it.name)}</span>
              ${it.current ? '<span class="badge on">本机登录所用</span>' : ''}
              <br><span class="meta">添加于 ${esc(fmtTime(it.createdAt))} · ${lastUsed}</span>
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
          openDialog($('#del-dialog'), '#del-cancel');
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
    input.setAttribute('autocomplete', 'off');
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
    // 账号邮箱取 title 属性（顶栏显示名已升级为昵称优先，完整邮箱在 title 里）
    const el = $('#topbar-email');
    const email = el ? (el.getAttribute('title') || el.textContent) : '';
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
      toast('密码已修改');
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
      toast('密码已修改');
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

  // ---- 注销（W2）：注册邮箱 + 邮箱验证码双确认，7 天反悔期 ----
  $('#start-delete').addEventListener('click', () => {
    $('#delete-email').value = ''; $('#delete-code').value = '';
    showErr('#delete-error', '');
    openDialog($('#delete-dialog'));
    $('#delete-email').focus();
  });
  $('#send-delete-code').addEventListener('click', async () => {
    showErr('#delete-error', '');
    const email = $('#delete-email').value.trim();
    if (!email) { showErr('#delete-error', '请先填写注册邮箱'); return; }
    try {
      await api('/auth/send-code', { method: 'POST', body: { email, purpose: 'delete' } });
      cooldown($('#send-delete-code'), 60);
      toast('验证码已发送，没收到可查看垃圾箱');
    } catch (err) { showErr('#delete-error', err.message); }
  });
  $('#delete-cancel').addEventListener('click', () => closeDialog($('#delete-dialog')));
  $('#delete-form').addEventListener('submit', async e => {
    e.preventDefault();
    showErr('#delete-error', '');
    const email = $('#delete-email').value.trim();
    const code = $('#delete-code').value.trim();
    if (!email) { showErr('#delete-error', '请先填写注册邮箱'); return; }
    if (!code) { showErr('#delete-error', '请输入邮箱验证码'); return; }
    const btn = $('#delete-form').querySelector('.btn.danger');
    setBusy(btn, true);
    try {
      await api('/auth/delete', { method: 'POST', body: { email, code } });
      closeDialog($('#delete-dialog'));
      // 登出回登录页：会话多半已随注销失效，登不成也不拦跳转
      try { await api('/web/logout', { method: 'POST', body: {} }); } catch (_) { /* 已登出也要跳 */ }
      flash('注销已提交，7 天内登录可撤销');
      location.href = '/web/login';
    } catch (err) { showErr('#delete-error', err.message); setBusy(btn, false); }
  });
}

/* ---------- 账号资料（B5）：头像 / 昵称 / 头像色 ----------
   PUT /api/profile 是**全量替换**语义（三字段每次都得提交完整），所以这里持一份
   本地档案副本，保存时整份提交；avatarImage 与两个日记 App 同口径：**裸 base64**
   （无 data: 前缀，标准字母表带 padding）——canvas toDataURL 产物剥掉前缀即是。 */
function initProfile() {
  const avatarEl = $('#pf-avatar');
  if (!avatarEl) return;
  const fileInput = $('#pf-avatar-file');
  const saveBtn = $('#pf-save');
  const email = $('#topbar-email') ? $('#topbar-email').getAttribute('title') : '';
  let pf = { nickname: '', avatarColor: 0, avatarImage: '' };
  let loaded = { nickname: '', avatarColor: 0, avatarImage: '' };
  let meUid = 0;   // W3 派生底色用（/web/session 现取，拿不到按 0 回退色板首位）

  // 色板来自服务端注入的 JSON（internal/ui avatarPalette，与两 App AvatarPalette 同值）
  const PALETTE = (() => {
    try {
      const el = document.getElementById('avatar-palette');
      const list = JSON.parse(el ? el.textContent : '[]');
      return Array.isArray(list) && list.length ? list : ['#5B8DEF'];
    } catch (_) { return ['#5B8DEF']; }
  })();

  /* W3：展示底色 = 显式色（>0）> uid%8 派生——与 Go ui.AvatarPaletteHexFor /
     app.js avatarHex 同式。色板 chips 按展示色高亮；显式值只在用户点选后落 pf
     （未设色的账号点「已高亮的那颗」不产生脏值）。 */
  function effectiveColor() {
    const i = Number(pf.avatarColor);
    if (Number.isInteger(i) && i > 0 && i < PALETTE.length) return i;
    return meUid > 0 ? meUid % PALETTE.length : 0;
  }

  // 首字回退链与服务端 initialFor 同源：昵称首字符 → 邮箱前缀首字符
  function avatarInitial() {
    const src = (pf.nickname || '').trim() || (email || '').split('@')[0] || '';
    const runes = Array.from(src);
    return runes.length ? runes[0].toUpperCase() : '?';
  }

  function renderAvatar(fade) {
    const bg = PALETTE[effectiveColor()] || PALETTE[0];
    avatarEl.style.background = bg;
    avatarEl.style.color = avatarInk(bg); // 首字墨色与底色成对（.avatar 不写死白墨）
    const wantImg = !!pf.avatarImage;
    const curImg = avatarEl.querySelector('img');
    if (wantImg) {
      const src = 'data:image/jpeg;base64,' + pf.avatarImage;
      if (curImg) {
        if (curImg.src !== src) { curImg.src = src; if (fade) crossFade(avatarEl); }
      } else {
        const img = document.createElement('img');
        img.src = src;
        img.alt = '';
        avatarEl.replaceChildren(img);
        if (fade) crossFade(avatarEl);
      }
    } else if (curImg) {
      avatarEl.textContent = avatarInitial();
      if (fade) crossFade(avatarEl);
    } else {
      avatarEl.textContent = avatarInitial();
    }
    $('#pf-clear-avatar').classList.toggle('hidden', !wantImg);
    // W7：有自定义头像时收起色板行（底色只在无图时决定首字观感）；
    // 移除头像/换回色块形态即恢复——上传与移除都经这里，两态永远同步。
    const paletteBox = $('#pf-palette');
    if (paletteBox) paletteBox.classList.toggle('hidden', wantImg);
  }

  function renderNick() {
    $('#pf-nick-view').textContent = pf.nickname || '未设置（显示邮箱前缀）';
  }

  function renderPalette() {
    const box = $('#pf-palette');
    box.innerHTML = '';
    PALETTE.forEach((hex, i) => {
      const chip = node(`<button type="button" class="pf-chip${i === effectiveColor() ? ' on' : ''}"
        style="background:${esc(hex)}" aria-pressed="${i === effectiveColor()}" aria-label="头像底色 ${i + 1}"></button>`);
      chip.addEventListener('click', () => {
        if (effectiveColor() === i) return;
        pf.avatarColor = i;
        $$('.pf-chip', box).forEach((c, j) => {
          c.classList.toggle('on', j === i);
          c.setAttribute('aria-pressed', String(j === i));
        });
        renderAvatar(false);
        refreshDirty();
      });
      box.appendChild(chip);
    });
  }

  function dirty() {
    return pf.nickname !== loaded.nickname ||
      Number(pf.avatarColor) !== Number(loaded.avatarColor) ||
      pf.avatarImage !== loaded.avatarImage;
  }
  function nickTooLong() {
    return Array.from((pf.nickname || '').trim()).length > 64;
  }
  function refreshDirty() {
    saveBtn.disabled = !dirty() || nickTooLong();
  }

  function applyProfile(p) {
    pf = {
      nickname: p.nickname || '',
      avatarColor: Number(p.avatarColor) || 0,
      avatarImage: p.avatarImage || '',
    };
    loaded = Object.assign({}, pf);
    const mailEl = $('#pf-email');
    if (mailEl) mailEl.textContent = email;
    renderNick();
    renderAvatar(false);
    renderPalette();
    refreshDirty();
  }

  async function load() {
    try {
      // W3：uid 只为「未设色按 uid 派生」服务，取不到就按 0 回退色板首位，不拦页面
      const [me, profile] = await Promise.all([
        api('/web/session', { method: 'POST', body: {} }).catch(() => null),
        api('/api/profile'),
      ]);
      meUid = Number(me && me.uid) || 0;
      applyProfile(profile);
    } catch (err) { showErr('#pf-error', err.message); }
  }

  // ---- 昵称行内编辑：≤64 字符（按字符计），超长即时提示且不可保存 ----
  $('#pf-nick-edit').addEventListener('click', () => {
    $('#pf-nick-view').classList.add('hidden');
    $('#pf-nick-edit').classList.add('hidden');
    const field = $('#pf-nick-field');
    field.classList.remove('hidden');
    $('#pf-nick-input').value = pf.nickname;
    swapIn(field);
    $('#pf-nick-input').focus();
  });
  function closeNickEdit() {
    $('#pf-nick-field').classList.add('hidden');
    $('#pf-nick-view').classList.remove('hidden');
    $('#pf-nick-edit').classList.remove('hidden');
    showErr('#pf-nick-err', '');
  }
  $('#pf-nick-input').addEventListener('input', e => {
    pf.nickname = e.target.value;
    const over = nickTooLong();
    showErr('#pf-nick-err', over ? '昵称最多 64 个字，请精简后重试' : '');
    renderNick();
    renderAvatar(false);
    refreshDirty();
  });
  $('#pf-nick-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); closeNickEdit(); }
    if (e.key === 'Escape') { e.preventDefault(); pf.nickname = loaded.nickname; $('#pf-nick-input').value = pf.nickname; renderNick(); renderAvatar(false); refreshDirty(); closeNickEdit(); }
  });

  // ---- 头像上传：方形裁剪（按短边居中裁）→ JPEG 0.85；解码后 >700KB 降质重压 ----
  $('#pf-avatar-edit').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = '';
    if (!file) return;
    showErr('#pf-error', '');
    try {
      pf.avatarImage = await cropAvatar(file);
      renderAvatar(true);
      refreshDirty();
    } catch (err) { showErr('#pf-error', err.message || '图片处理失败，请换一张试试'); }
  });
  $('#pf-clear-avatar').addEventListener('click', () => {
    if (!pf.avatarImage) return;
    pf.avatarImage = '';
    renderAvatar(true);
    refreshDirty();
  });

  saveBtn.addEventListener('click', async () => {
    showErr('#pf-error', '');
    setBusy(saveBtn, true);
    try {
      // 全量替换：三字段整份提交（漏哪个等于清哪个）
      applyProfile(await api('/api/profile', {
        method: 'PUT',
        body: { nickname: pf.nickname.trim(), avatarColor: pf.avatarColor, avatarImage: pf.avatarImage },
      }));
      toast('资料已更新');
      // 顶栏胶囊同源更新（昵称显示名 + 头像），不整页刷新
      const topName = $('#topbar-email');
      if (topName) {
        topName.textContent = (pf.nickname || '').trim() || (email || '').split('@')[0] || '';
        topName.setAttribute('title', email);
      }
      updateTopbarAvatar();
    } catch (err) { showErr('#pf-error', err.message); } finally { setBusy(saveBtn, false); }
  });

  function updateTopbarAvatar() {
    const top = $('#me-avatar');
    if (!top) return;
    const bg = PALETTE[effectiveColor()] || PALETTE[0];
    top.style.background = bg;
    top.style.color = avatarInk(bg); // 首字墨色与底色成对（.avatar 不写死白墨）
    if (pf.avatarImage) {
      const img = document.createElement('img');
      img.src = 'data:image/jpeg;base64,' + pf.avatarImage;
      img.alt = '';
      top.replaceChildren(img);
    } else {
      top.textContent = avatarInitial();
    }
  }

  load();
}

/* ---------- 新设备登录提醒开关（W1，账号页登录提醒卡） ----------
   PUT /api/profile 是全量替换语义：这里先 GET 整份档案，再带上 loginNotify 整份
   PUT——只发 {loginNotify} 会把昵称/头像清空。失败回滚勾选态并 toast 原因。 */
function initLoginNotify() {
  const box = $('#login-notify');
  if (!box) return;
  let loaded = null;
  async function load() {
    try {
      const p = await api('/api/profile');
      loaded = !!p.loginNotify;
      box.checked = loaded;
    } catch (err) { toast(err.message, true); }
  }
  box.addEventListener('change', async () => {
    const want = box.checked;
    box.disabled = true;
    try {
      const p = await api('/api/profile');
      await api('/api/profile', {
        method: 'PUT',
        body: {
          nickname: p.nickname || '', avatarColor: Number(p.avatarColor) || 0,
          avatarImage: p.avatarImage || '', loginNotify: want,
        },
      });
      loaded = want;
      toast(want ? '已开启新设备登录提醒' : '已关闭新设备登录提醒');
    } catch (err) {
      box.checked = loaded === null ? !want : loaded;
      toast(err.message, true);
    } finally { box.disabled = false; }
  });
  load();
}

/* 头像换新交叉淡入（B5）：旧内容淡出 → 换新 → 淡入，只动 opacity/transform；
   reduced-motion 直接切（与 fadeOutRow 同一套门禁）。 */
function crossFade(el) {
  if (!el || reducedMotion() || typeof el.animate !== 'function') return;
  try {
    el.animate([{ opacity: 1 }, { opacity: 0.2 }, { opacity: 1 }],
      { duration: 200, easing: 'cubic-bezier(.2, 0, 0, 1)' });
  } catch (_) { /* 浏览器不支持就静默 */ }
}

/* 方形裁剪 + JPEG 压缩：按短边居中裁成正方形（输出上限 512px），toDataURL(0.85)；
   解码后 >700KB（服务端 maxAvatarImageBytes）就逐档降质（0.85→0.35），仍超再缩画布。
   回**裸 base64**（剥 data: 前缀）——与日记客户端 Base64.NO_WRAP 的产物同形。 */
const AVATAR_MAX_DECODED = 700 * 1024;
async function cropAvatar(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((resolve, reject) => {
      const im = new Image();
      im.onload = () => resolve(im);
      im.onerror = () => reject(new Error('图片无法解码，请换一张'));
      im.src = url;
    });
    const side = Math.min(img.naturalWidth, img.naturalHeight);
    if (!side) throw new Error('图片尺寸异常，请换一张');
    let size = Math.min(side, 512);
    const sx = (img.naturalWidth - side) / 2;
    const sy = (img.naturalHeight - side) / 2;
    for (let attempt = 0; attempt < 3; attempt++) {
      const canvas = document.createElement('canvas');
      canvas.width = size; canvas.height = size;
      canvas.getContext('2d').drawImage(img, sx, sy, side, side, 0, 0, size, size);
      for (let q = 0.85; q >= 0.3; q -= 0.1) {
        const b64 = canvas.toDataURL('image/jpeg', q).split(',')[1] || '';
        // base64 长度 ≈ 解码字节数 × 4/3：直接按字符数估即可，不必真解一遍
        if (Math.floor(b64.length * 3 / 4) <= AVATAR_MAX_DECODED) return b64;
      }
      size = Math.floor(size * 0.7); // 最低档仍超：缩小画布再来一轮
    }
    throw new Error('图片过大，请换一张更小的图');
  } finally {
    URL.revokeObjectURL(url);
  }
}

/* ---------- 后台：用户（含原角色管理，合并页） ---------- */
/* 角色徽标与授权文案的术语表：super→平台管理员、admin→项目管理员、user→普通用户；
   授权列只给计数文案，不列 app 名。 */
const ROLE_LABEL = { super: '平台管理员', admin: '项目管理员', user: '普通用户' };

/* 头像渲染（B5，列表/抽屉/会话总览共用）：avatarImage 有值用图，无图回退色块+首字
   （首字取昵称首字符，再退邮箱前缀首字符；底色取 avatarColor 下标对应的色板值、
   首字墨色按 avatarInk(底色) 择黑/白——色板来自服务端注入的 JSON，与 internal/ui
   avatarPalette 及两 App 同一份值）。 */
function avatarPalette() {
  try {
    const el = document.getElementById('avatar-palette');
    const list = JSON.parse(el ? el.textContent : '[]');
    return Array.isArray(list) && list.length ? list : ['#5B8DEF'];
  } catch (_) { return ['#5B8DEF']; }
}
function avatarInitial(nickname, email) {
  const src = (nickname || '').trim() || (email || '').split('@')[0] || '';
  const runes = Array.from(src);
  return runes.length ? esc(runes[0].toUpperCase()) : '?';
}
function avatarHex(index, uid) {
  const p = avatarPalette();
  const i = Number(index);
  // W3 展示色派生：显式设过的色（>0）原样用；未设（0/越界）按 uid%8 派生——
  // 与 Go 侧 ui.AvatarPaletteHexFor 同式（改规则请同 PR 同步 Go 半边）。
  if (Number.isInteger(i) && i > 0 && i < p.length) return p[i];
  const u = Number(uid);
  return p[Number.isInteger(u) && u > 0 ? u % p.length : 0];
}
/* 首字墨色：按 WCAG 相对亮度取白墨/黑墨中对比更高的一支——与 Go 侧 ui.avatarInkFor
   及两 App AvatarPalette.inkFor 同式（.avatar 不再写死白墨：白墨对 8 色色板实测只有
   1.92~4.49:1，全数低于 4.5:1；黑墨全数 ≥4.5，实测表见 ui.go avatarInkFor 注释，
   TestAvatarInkContrast 钉住 Go 侧——改规则请同 PR 同步两处）。 */
function avatarInk(bg) {
  const m = /^#([0-9a-fA-F]{6})$/.exec(String(bg || '').trim());
  if (!m) return '#000000'; // 走不到（底色只来自常量色板），兜底黑墨 = 8 色全达标的那支
  const n = parseInt(m[1], 16);
  const lin = c => { c /= 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
  const l = 0.2126 * lin(n >> 16 & 255) + 0.7152 * lin(n >> 8 & 255) + 0.0722 * lin(n & 255);
  return 1.05 / (l + 0.05) >= (l + 0.05) / 0.05 ? '#ffffff' : '#000000';
}
function avatarHTML(u, px) {
  const size = `width:${px}px;height:${px}px;font-size:${Math.round(px * 0.42)}px`;
  const bg = avatarHex(u.avatarColor, u.uid);
  const initial = avatarInitial(u.nickname, u.email);
  // W3：真图统一走 /admin/users/{uid}/avatar（懒加载；服务端弱缓存 5 分钟 + ETag），
  // 无图 404 或加载失败时由 document 捕获阶段的 error 监听回退「色块 + 首字」——
  // 回退方向是「图 → 占位符」，占位色块是兜底不是主图。uid 缺位（打开抽屉的过场）
  // 直接渲染色块，不发注定 404 的请求。
  const img = Number(u.uid) > 0
    ? `<img class="avatar-img" loading="lazy" src="/admin/users/${esc(u.uid)}/avatar" alt="">` : '';
  return `<span class="avatar" data-initial="${initial}" style="${size};background:${esc(bg)};color:${avatarInk(bg)}" aria-hidden="true">${img || initial}</span>`;
}
/* 头像图加载失败（无图 404 / 网络错）：原地换回色块+首字。error 事件不冒泡，
   用 document 的**捕获**阶段统一接（免去每个 innerHTML 注入点各自挂 onerror）。 */
document.addEventListener('error', e => {
  const t = e.target;
  if (!t || !t.classList || !t.classList.contains('avatar-img')) return;
  const wrap = t.parentElement;
  if (wrap) wrap.textContent = wrap.dataset.initial || '?';
}, true);
/* 身份堆叠（头像+昵称+邮箱，Qualytics 形态）：列表与抽屉头部同款。 */
function userCell(u, px) {
  const name = (u.nickname || '').trim() || u.email;
  return `<span class="user-cell">${avatarHTML(u, px)}
    <span class="grow"><span class="title">${esc(name)}</span>${u.nickname ? `<br><span class="meta wrap-cell">${esc(u.email)}</span>` : ''}</span></span>`;
}
function scopeSummary(u) {
  if (u.role === 'super') return '管理全部项目';
  const n = Number(u.scopeCount || 0);
  return n > 0 ? `已授权 ${n} 个项目` : '未授权任何项目';
}

/* 封禁范围选项：平台管理员 = 全局 + 注册表全部项目；项目管理员 = 仅自己授权的
   项目（GET /admin/projects 只回自己范围内的，前端不再裁；永远没有全局项）。 */
async function banScopeOptions() {
  if (IS_SUPER) {
    return [{ key: '*', label: '全部项目（全局）' }]
      .concat(knownApps().map(a => ({ key: a.key, label: a.label })));
  }
  try {
    const res = await api('/admin/projects');
    return (res.projects || []).map(p => ({ key: p.app, label: p.name }));
  } catch (_) { return []; }
}

/* 限时封禁的最早解除时间：当前 + 5 分钟（datetime-local 的本地格式）。 */
function banMinStr() {
  const d = new Date(Date.now() + 5 * 60 * 1000);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function initAdminUsers() {
  const body = $('#users-body');
  if (!body) return;
  const APPS = knownApps();
  const pager = makePager({ prev: '#users-prev', next: '#users-next', label: '#users-page', limit: 20 });

  // 确认弹窗：一次挂一个待执行动作 + 它的成功提示，确认后走 reauth 闸
  //（api() 401 自动弹重验框）——提示按操作分说，不统一糊一句「已生效」。
  // after 可选：拿回执干收尾活（重置密码的一次性密码展示层走它）。
  let pending = null;
  let lastDetail = { uid: 0, email: '' };
  function confirmAction(title, desc, done, fn, danger, after) {
    pending = { fn, done, after };
    $('#ud-dlg-title').textContent = title;
    $('#ud-dlg-desc').textContent = desc;
    $('#ud-dlg-ok').classList.toggle('danger', !!danger);
    showErr('#ud-dlg-error', '');
    openDialog($('#user-dialog'), '#ud-dlg-cancel');
  }
  $('#ud-dlg-cancel').addEventListener('click', () => { pending = null; closeDialog($('#user-dialog')); });
  $('#user-dlg-form').addEventListener('submit', async e => {
    e.preventDefault();
    const job = pending;
    pending = null;
    closeDialog($('#user-dialog'));
    if (!job) return;
    try {
      const res = await job.fn();
      // after 可以是异步的（邀请撤销先等行淡出播完再重取列表），所以 await
      if (job.after) await job.after(res);
      toast(job.done);
      await Promise.all([load(), loadInvites()]);
      if (lastDetail.uid) openDetail(lastDetail.uid, lastDetail.email);
    } catch (err) { toast(err.message, true); }
  });

  // ---- 一次性临时密码展示层（W3）：等宽展示 + 复制，关层即清零 ----
  let tempPassword = '';
  function showTempPassword(pw, notify) {
    tempPassword = pw || '';
    $('#rp-done-pw').textContent = tempPassword;
    $('#rp-done-hint').textContent = notify
      ? '此密码仅显示一次，关闭后无法再次查看。邮件已发送给用户。'
      : '此密码仅显示一次，关闭后无法再次查看。请通过其它渠道转告用户。';
    openDialog($('#rp-done'));
  }
  $('#rp-done-copy').addEventListener('click', async () => {
    if (!tempPassword) return;
    await copyText(tempPassword);
    toast('密码已复制');
  });
  $('#rp-done-close').addEventListener('click', () => closeDialog($('#rp-done')));
  // Esc / 关闭都会落到 close 事件：变量与展示一并清零
  $('#rp-done').addEventListener('close', () => {
    tempPassword = '';
    $('#rp-done-pw').textContent = '';
  });

  // ---- 选择集与批量工具条（B9）：Map<uid,email>，跨翻页保留（批量本就要跨页选人）；
  // 清空是显式动作。N 实时刷新，工具条在 N=0 时整条收起。 ----
  const selected = new Map();
  function refreshBulkBar() {
    const n = selected.size;
    $('#bulk-bar').classList.toggle('hidden', n === 0);
    $('#bulk-count').textContent = `已选 ${n} 人`;
    const boxes = $$('#users-body .row-sel');
    $('#users-selall').checked = boxes.length > 0 && boxes.every(b => b.checked);
  }
  function syncSelection(cb) {
    const uid = Number(cb.dataset.uid);
    if (cb.checked) selected.set(uid, cb.dataset.email); else selected.delete(uid);
    refreshBulkBar();
  }

  // ---- 邀请记录（B9）：四态徽标（pending 主色 / accepted 绿 / revoked·expired 灰）、
  // 行内重发与撤销；过滤复用用户搜索框的同一查询串（少一个输入框）。 ----
  let inviteQuery = '';
  const INVITE_BADGE = {
    pending: '<span class="badge on">待接受</span>',
    accepted: '<span class="badge ok">已接受</span>',
    revoked: '<span class="badge off">已撤销</span>',
    expired: '<span class="badge off">已过期</span>',
  };
  async function loadInvites() {
    const tbody = $('#invites-body');
    if (!tbody) return;
    try {
      const res = await api('/admin/users/invites?query=' + encodeURIComponent(inviteQuery));
      const list = res.invites || [];
      $('#invites-count').textContent = list.length ? `· 共 ${list.length} 条` : '';
      if (!list.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty">${inviteQuery ? '没有匹配的邀请' : '还没有发出过邀请'}</td></tr>`;
        return;
      }
      tbody.innerHTML = '';
      list.forEach(it => {
        // 还能动手的行（待接受/已过期可重发与撤销）才渲染行内按钮；
        // 已接受/已撤销是不可逆事实，只留状态（业务层对它们的重发/撤销也一律 400）
        const live = it.state === 'pending' || it.state === 'expired';
        const validity = it.state === 'pending'
          ? `剩余 ${esc(remainTime(it.expiresAt))}` : `至 ${esc(fmtTime(it.expiresAt))}`;
        const tr = node(`
          <tr data-invite="${esc(it.id)}">
            <td class="wrap-cell">${esc(it.email)}</td>
            <td>${it.app ? esc(appLabel(it.app)) : '<span class="dim">不限项目</span>'}</td>
            <td>${INVITE_BADGE[it.state] || esc(it.state)}</td>
            <td>${validity}</td>
            <td>${live ? `<span class="row" style="gap:6px">
                <button type="button" class="btn small" data-resend>重发</button>
                <button type="button" class="btn small danger" data-revoke>撤销</button>
              </span>` : ''}</td>
          </tr>`);
        const resend = tr.querySelector('[data-resend]');
        if (resend) resend.addEventListener('click', async () => {
          setBusy(resend, true);
          try {
            // 重发 = 换新 token + 续 24h，旧链接即刻失效（文案要说清「去打开新的那封」）
            await api(`/admin/users/invite/${encodeURIComponent(it.id)}/resend`, { method: 'POST', body: {} });
            toast(`邀请已重新发送至 ${it.email}，旧链接已失效`);
            await loadInvites();
          } catch (err) { toast(err.message, true); }
          finally { setBusy(resend, false); }
        });
        const revoke = tr.querySelector('[data-revoke]');
        if (revoke) revoke.addEventListener('click', () => {
          confirmAction(
            '撤销邀请',
            `将撤销发给 ${it.email} 的邀请链接，对方再打开会看到「已被撤销」；需要时可重新发起邀请。`,
            `已撤销发给 ${it.email} 的邀请`,
            () => api(`/admin/users/invite/${encodeURIComponent(it.id)}/revoke`, { method: 'POST', body: {} }),
            true,
            // 成功后先让本行淡出（.leaving / fadeOutRow 配方），再由外层重取列表
            () => new Promise(done => fadeOutRow(tr, done)));
        });
        tbody.appendChild(tr);
      });
    } catch (err) {
      $('#invites-count').textContent = '';
      tbody.innerHTML = `<tr><td colspan="5" class="empty">读取失败：${esc(err.message)}</td></tr>`;
    }
  }

  // ---- 批量操作（B9）：确认视图 = 所选邮箱清单（可滚动）+ 后果逐条 + 一次配置；
  // N>5 手打「确认」解锁主钮；执行中 busy 禁用；结果视图逐项成败，失败项可勾选
  // 只重跑子集。临时密码**不进**结果面板（凭证只随逐用户邮件走）。 ----
  const BULK_TITLE = { password_reset: '批量重置密码', ban: '批量封禁', unban: '批量解除封禁' };
  const BULK_CONSEQUENCES = {
    password_reset: [
      '为每位所选用户生成一个 16 位临时密码，并要求其下次登录时修改',
      '新密码邮件通知到各自的登录邮箱（临时密码不进本面板，也不进日志）',
      '这些账号的现有登录会被全部吊销，已登录设备需重新登录',
    ],
    ban: [
      '所选用户在下方所选范围内无法登录，该范围内已登录的设备立即被退出',
      '重复封禁按本次配置覆盖既有记录；限时到期自动解除，永久需手动解封',
      '一次配置（范围/时长/原因）套用到全部所选用户',
    ],
    unban: [
      '解除所选用户在下方所选范围内的封禁，该范围随即恢复登录',
      '解封是幂等的：没有生效中封禁的用户同样回执成功',
      '只解除所选范围，不影响同一账号其它项目的封禁',
    ],
  };
  let bulkJob = null;    // {kind, uids}
  let bulkState = null;  // {kind, results: Map<uid,{ok,message}>}
  let bulkEmails = new Map(); // 开批时的 uid→email 快照（结果面板的称呼不随选择集漂）

  // bulkRequest 组装请求体：password_reset 只有 kind+uids；ban 带范围/时长/原因；
  // unban 只带范围（业务层 AdminUnban 只吃 app）。
  function bulkRequest(kind, uids) {
    const body = { kind, uids };
    if (kind === 'ban' || kind === 'unban') {
      body.app = $('#bulk-app').value;
      if (kind === 'ban') {
        body.until = $('#bulk-temp').checked && $('#bulk-until').value
          ? new Date($('#bulk-until').value).getTime() : 0;
        body.reason = $('#bulk-reason').value.trim();
      }
    }
    return body;
  }

  function syncBulkGate() {
    const needGate = !$('#bulk-gate').classList.contains('hidden');
    $('#bulk-ok').disabled = needGate && $('#bulk-typed').value.trim() !== '确认';
  }

  function renderBulkResults() {
    const st = bulkState;
    const items = Array.from(st.results.entries());
    const failed = items.filter(([, r]) => !r.ok);
    $('#bulk-result-summary').textContent =
      `共 ${items.length} 人：成功 ${items.length - failed.length}，失败 ${failed.length}` +
      (failed.length ? '。勾选失败项后可只重试子集。' : '。');
    const list = $('#bulk-result-list');
    list.innerHTML = items.map(([uid, r]) => {
      const email = bulkEmails.get(uid) || `uid ${uid}`;
      return `<div class="item">
        <span class="grow"><span class="title">${esc(email)}</span><br>
          <span class="meta">${r.ok ? '已完成' : esc(r.message || '操作失败')}</span></span>
        ${r.ok ? '<span class="badge ok">成功</span>' : '<span class="badge warn">失败</span>'}
        ${r.ok ? '' : `<label class="row" style="gap:6px;font-size:13px"><input type="checkbox" class="bulk-retry-sel" data-uid="${esc(uid)}" checked> 重试</label>`}
      </div>`;
    }).join('') || '<div class="empty">没有结果</div>';
    $$('#bulk-result-list .bulk-retry-sel').forEach(cb =>
      cb.addEventListener('change', syncRetryBtn));
    const retry = $('#bulk-retry-failed');
    retry.classList.toggle('hidden', !failed.length);
    syncRetryBtn();
  }
  function syncRetryBtn() {
    const any = $$('#bulk-result-list .bulk-retry-sel').some(cb => cb.checked);
    $('#bulk-retry-failed').disabled = !any;
  }

  async function openBulk(kind) {
    const uids = Array.from(selected.keys());
    if (!uids.length) return;
    bulkJob = { kind, uids };
    bulkEmails = new Map(selected);
    $('#bulk-dlg-result').classList.add('hidden');
    $('#bulk-dlg-confirm').classList.remove('hidden');
    showErr('#bulk-error', '');
    $('#bulk-typed').value = '';
    $('#bulk-dlg-title').textContent = BULK_TITLE[kind];
    $('#bulk-dlg-desc').textContent = `将对所选 ${uids.length} 位用户执行：`;
    $('#bulk-dlg-list').innerHTML = uids.map(uid => `
      <div class="item" style="padding:8px 12px">
        <span class="grow"><span class="title">${esc(bulkEmails.get(uid) || 'uid ' + uid)}</span></span>
        <span class="mono dim">${esc(uid)}</span>
      </div>`).join('');
    $('#bulk-dlg-cons').innerHTML = BULK_CONSEQUENCES[kind].map(t => `<li>${esc(t)}</li>`).join('');
    const needCfg = kind !== 'password_reset';
    $('#bulk-dlg-config').classList.toggle('hidden', !needCfg);
    if (needCfg) {
      const opts = await banScopeOptions();
      $('#bulk-app').innerHTML = opts.map(o => `<option value="${esc(o.key)}">${esc(o.label)}</option>`).join('')
        || '<option value="">无可用范围</option>';
      decorateSelect($('#bulk-app'));   // W9：同步按钮文案
      const isBan = kind === 'ban';
      $('#bulk-dur-group').classList.toggle('hidden', !isBan);
      $('#bulk-reason-field').classList.toggle('hidden', !isBan);
      $('#bulk-until-field').classList.add('hidden');
      $('#bulk-perm').checked = true;
      $('#bulk-until').value = '';
      $('#bulk-until').min = banMinStr();
      $('#bulk-reason').value = '';
    }
    $('#bulk-gate').classList.toggle('hidden', uids.length <= 5);
    syncBulkGate();
    openDialog($('#bulk-dialog'), '#bulk-cancel');
  }

  async function openInvite() {
    showErr('#invite-error', '');
    $('#invite-email').value = '';
    const sel = $('#invite-app');
    sel.innerHTML = '<option value="">加载中…</option>';
    openDialog($('#invite-dialog'), '#invite-cancel');
    // super：全部项目 +「不限项目」；项目管理员：仅其授权项目且必选
    //（用户页当前是平台管理员页，这条支路是接口口径的前端对齐，不另开页面）
    let opts;
    if (IS_SUPER) {
      opts = [{ key: '', label: '不限项目' }]
        .concat(knownApps().map(a => ({ key: a.key, label: a.label })));
    } else {
      opts = [];
      try {
        const res = await api('/admin/projects');
        opts = (res.projects || []).map(p => ({ key: p.app, label: p.name }));
      } catch (_) { /* 拿不到授权清单就空着，提交时按必选拦 */ }
    }
    sel.innerHTML = opts.map(o => `<option value="${esc(o.key)}">${esc(o.label)}</option>`).join('')
      || '<option value="">无可邀请的项目</option>';
    decorateSelect(sel);   // W9：选项是打开后才灌的，这里同步按钮文案
    $('#invite-email').focus();
  }

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
        body.innerHTML = '<tr><td colspan="9" class="empty">暂无匹配的用户</td></tr>';
        $('#users-selall').checked = false;
        return;
      }
      res.items.forEach(u => {
        const tr = node(`
          <tr>
            <td><input type="checkbox" class="row-sel" data-uid="${esc(u.uid)}" data-email="${esc(u.email)}" aria-label="选择 ${esc(u.email)}"${selected.has(Number(u.uid)) ? ' checked' : ''}></td>
            <td class="wrap-cell">${userCell(u, 32)}</td>
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
      $$('#users-body .row-sel').forEach(cb => cb.addEventListener('change', () => syncSelection(cb)));
      refreshBulkBar();
    } catch (err) {
      showErr('#users-error', err.message);
      body.innerHTML = '<tr><td colspan="9" class="empty">读取失败</td></tr>';
      refreshBulkBar();
    }
  }

  async function openDetail(uid, email) {
    lastDetail = { uid, email };
    const panel = $('#user-detail');
    const wasHidden = panel.classList.contains('hidden');
    panel.classList.remove('hidden');
    if (wasHidden) slideIn(panel);   // 首次展开做钻取滑入，重绘不重复播
    $('#ud-title').innerHTML = `<span class="user-cell">${avatarHTML({ email }, 48)}
      <span class="grow"><span class="title">${esc(email)}</span><br><span class="meta">用户详情</span></span></span>`;
    $('#ud-body').innerHTML = '<div class="empty">读取中…</div>';
    panel.scrollIntoView({ block: 'nearest' });
    try {
      const d = await api('/admin/users/' + uid);
      // 头部按全量档案重绘（48px 头像 + 昵称 + 邮箱）
      $('#ud-title').innerHTML = `<span class="user-cell">${avatarHTML(d, 48)}
        <span class="grow"><span class="title">${esc((d.nickname || '').trim() || d.email)}</span><br><span class="meta wrap-cell">${esc(d.email)}</span></span></span>`;
      const scopes = d.scopes || [];
      const sessions = (d.sessions || []).map(s => `
        <div class="item">
          <span class="grow"><span class="title">${esc(s.device)}</span><br>
          <span class="meta">${esc(appLabel(s.app))} · ${esc(s.ip)} · 最近活跃 ${esc(relTime(s.lastSeenAt))}</span></span>
          <button type="button" class="btn small danger" data-kick="${esc(s.id)}">退出</button>
        </div>`).join('') || '<div class="empty">暂无活跃会话</div>';
      const passkeys = (d.passkeys || []).map(p =>
        `<li>${esc(p.name)} · ${esc(fmtTime(p.createdAt))}</li>`).join('') || '<li>未添加</li>';
      // 封禁列表（W3）：全局/项目名 + 永久或解除时间 + 原因 + 解除按钮
      const banRows = (d.bans || []).map(b => `
        <div class="item">
          <span class="grow"><span class="title">${b.app === '*' ? '全局' : esc(appLabel(b.app))}</span>
          <br><span class="meta">${Number(b.until) > 0 ? `将于 ${esc(fmtTime(b.until))} 解除` : '永久'}${b.reason ? ` · ${esc(b.reason)}` : ''}</span></span>
          <button type="button" class="btn small danger" data-unban="${esc(b.app)}">解除</button>
        </div>`).join('') || '<div class="empty">当前没有生效中的封禁。</div>';
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
        <h3>重置密码</h3>
        <div class="row" style="gap:8px">
          <span class="app-switch" role="group" aria-label="重置密码方式">
            <button type="button" class="app-chip on" data-rp-mode="generate" aria-pressed="true">自动生成</button>
            <button type="button" class="app-chip" data-rp-mode="manual" aria-pressed="false">手动输入</button>
          </span>
        </div>
        <label class="field hidden" id="ud-rp-pw-field"><span>指定的新密码（至少 8 位）</span>
          <input type="text" id="ud-rp-pw" autocomplete="off" placeholder="输入要设为登录密码的新密码">
        </label>
        <div class="row" style="gap:8px;margin-top:8px">
          <label class="row" style="gap:6px"><input type="checkbox" id="ud-rp-force" checked> 下次登录必须修改密码</label>
          <label class="row" style="gap:6px"><input type="checkbox" id="ud-rp-notify" checked> 邮件通知用户</label>
        </div>
        <label class="field"><span>原因（选填）</span>
          <input type="text" id="ud-rp-reason" placeholder="操作原因（记入审计）" autocomplete="off">
        </label>
        <p class="err" id="ud-rp-error" role="alert" hidden></p>
        <div class="row"><button type="button" class="btn danger" id="ud-rp-go">重置密码</button></div>
        <h3>更换邮箱</h3>
        <p class="hint">当前邮箱 <span class="mono">${esc(d.email)}</span>。更换后用户立即用新邮箱登录，现会话不受影响；新旧邮箱都会收到通知。</p>
        <label class="field"><span>新邮箱</span>
          <input type="email" id="ud-email-new" autocomplete="off" placeholder="输入新的登录邮箱">
        </label>
        <label class="field"><span>原因（选填）</span>
          <input type="text" id="ud-email-reason" placeholder="操作原因（记入审计）" autocomplete="off">
        </label>
        <p class="err" id="ud-email-error" role="alert" hidden></p>
        <div class="row"><button type="button" class="btn danger" id="ud-email-go">更换邮箱</button></div>
        <h3>重置资料</h3>
        <p class="hint">重置头像后回退为「色块 + 首字母」，重置昵称后显示回退为邮箱前缀。不影响登录与会话。</p>
        <div class="row" style="gap:8px">
          <button type="button" class="btn" id="ud-reset-avatar"${d.hasAvatar || d.avatarColor ? '' : ' disabled'}>重置头像</button>
          <button type="button" class="btn" id="ud-reset-nickname"${d.nickname ? '' : ' disabled'}>重置昵称</button>
        </div>
        <h3>封禁</h3>
        <div class="list">${banRows}</div>
        <div class="detail">
          <div class="row" style="gap:8px">
            <label class="row" style="gap:6px"><span class="dim">范围</span>
              <select id="ud-ban-app" aria-label="封禁范围"></select>
            </label>
            <label class="row" style="gap:6px"><input type="radio" name="ud-ban-dur" id="ud-ban-perm" checked> 永久</label>
            <label class="row" style="gap:6px"><input type="radio" name="ud-ban-dur" id="ud-ban-temp"> 限时</label>
            <label class="row hidden" id="ud-ban-until-field" style="gap:6px"><span class="dim">解除时间</span>
              <input type="datetime-local" id="ud-ban-until">
            </label>
          </div>
          <label class="field"><span>原因（选填）</span>
            <input type="text" id="ud-ban-reason" placeholder="填写封禁原因（记入审计）" autocomplete="off">
          </label>
          <p class="err" id="ud-ban-error" role="alert" hidden></p>
          <div class="row"><button type="button" class="btn danger" id="ud-ban-go">封禁</button></div>
        </div>
        <h3>Passkey</h3><ul>${passkeys}</ul>
        <h3>活跃会话</h3><div class="list">${sessions}</div>
        <div class="detail row">
          <button type="button" class="btn small danger" id="ud-kick-all">退出该用户全部会话</button>
        </div>`;
      decorateSelects($('#ud-body'));   // W9：抽屉里的角色/封禁范围下拉换站内形态
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

      // ---- 重置密码（W3）：方式切换 + 两个勾选 + 原因；确认后展示一次性密码 ----
      let rpMode = 'generate';
      $$('#ud-body [data-rp-mode]').forEach(chip => chip.addEventListener('click', () => {
        rpMode = chip.dataset.rpMode;
        $$('#ud-body [data-rp-mode]').forEach(c => {
          const on = c.dataset.rpMode === rpMode;
          c.classList.toggle('on', on);
          c.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        const field = $('#ud-rp-pw-field');
        field.classList.toggle('hidden', rpMode !== 'manual');
        if (rpMode === 'manual') { swapIn(field); $('#ud-rp-pw').focus(); }   // 分段切换：crossfade + 上浮
        showErr('#ud-rp-error', '');
      }));
      $('#ud-rp-go').addEventListener('click', () => {
        showErr('#ud-rp-error', '');
        const password = $('#ud-rp-pw').value;
        if (rpMode === 'manual' && password.length < 8) {
          showErr('#ud-rp-error', '手动输入的密码至少 8 位');
          return;
        }
        const forceChange = $('#ud-rp-force').checked;
        const notify = $('#ud-rp-notify').checked;
        const reason = $('#ud-rp-reason').value.trim();
        const body = { mode: rpMode, forceChange, notify, reason };
        if (rpMode === 'manual') body.password = password;
        confirmAction(
          '重置密码',
          `将重置 ${email} 的登录密码${forceChange ? '，并要求其下次登录时修改' : ''}${notify ? '，新密码会邮件通知该用户' : '，请通过其它渠道转告该用户'}。`,
          `已重置 ${email} 的密码`,
          () => api(`/admin/users/${uid}/password`, { method: 'POST', body }),
          true,
          res => showTempPassword(res && res.temporaryPassword, notify));
      });

      // ---- 更换邮箱（B5）：确认点名新旧邮箱，提示必达两封通知 ----
      $('#ud-email-go').addEventListener('click', () => {
        showErr('#ud-email-error', '');
        const next = $('#ud-email-new').value.trim();
        if (!next) { showErr('#ud-email-error', '请先填写新邮箱'); return; }
        if (next === d.email) { showErr('#ud-email-error', '新邮箱与当前邮箱相同'); return; }
        const reason = $('#ud-email-reason').value.trim();
        confirmAction(
          '更换邮箱',
          `将 ${d.email} 的登录邮箱改为 ${next}，新旧邮箱都会收到通知；用户立即改用新邮箱登录，现会话不受影响。`,
          `已将 ${d.email} 的邮箱改为 ${next}`,
          () => api(`/admin/users/${uid}/email`, { method: 'POST', body: { email: next, reason } }),
          true);
      });

      // ---- 重置资料（B5）：头像/昵称各自点名确认，说清回退效果 ----
      const resetAvatarBtn = $('#ud-reset-avatar');
      if (resetAvatarBtn) resetAvatarBtn.addEventListener('click', () => {
        confirmAction(
          '重置头像',
          `将清空 ${d.email} 的头像图与头像色，回退为「色块 + 首字母」显示。`,
          `已重置 ${d.email} 的头像`,
          () => api(`/admin/users/${uid}/profile-reset`, { method: 'POST', body: { avatar: true, nickname: false } }),
          true);
      });
      const resetNickBtn = $('#ud-reset-nickname');
      if (resetNickBtn) resetNickBtn.addEventListener('click', () => {
        confirmAction(
          '重置昵称',
          `将清空 ${d.email} 的昵称，显示回退为邮箱前缀。`,
          `已重置 ${d.email} 的昵称`,
          () => api(`/admin/users/${uid}/profile-reset`, { method: 'POST', body: { avatar: false, nickname: true } }),
          true);
      });

      // ---- 封禁（W3）：范围（super 见全局+全部项目，项目管理员只见授权项目）----
      const banSel = $('#ud-ban-app');
      banScopeOptions().then(opts => {
        if (banSel) {
          banSel.innerHTML = opts.map(o => `<option value="${esc(o.key)}">${esc(o.label)}</option>`).join('');
          decorateSelect(banSel);   // W9：范围选项异步灌入后同步按钮文案
        }
      });
      const untilField = $('#ud-ban-until-field');
      const untilInput = $('#ud-ban-until');
      untilInput.min = banMinStr();
      $$('#ud-body input[name=ud-ban-dur]').forEach(r => r.addEventListener('change', () => {
        const temp = $('#ud-ban-temp').checked;
        untilField.classList.toggle('hidden', !temp);
        if (temp) { untilInput.min = banMinStr(); swapIn(untilField); }
        showErr('#ud-ban-error', '');
      }));
      $('#ud-ban-go').addEventListener('click', () => {
        showErr('#ud-ban-error', '');
        const app = banSel.value;
        let until = 0;
        if ($('#ud-ban-temp').checked) {
          const v = untilInput.value;
          until = v ? new Date(v).getTime() : 0;
          if (!until || until < Date.now() + 5 * 60 * 1000) {
            showErr('#ud-ban-error', '解除时间至少要在 5 分钟之后');
            return;
          }
        }
        const reason = $('#ud-ban-reason').value.trim();
        const scopeLabel = app === '*' ? '全部项目（全局）' : appLabel(app);
        confirmAction(
          '封禁账号',
          `将封禁 ${email}：范围「${scopeLabel}」，${until > 0 ? `至 ${fmtTime(until)} 解除` : '永久'}${reason ? `；原因：${reason}` : ''}。封禁期间该账号无法登录。`,
          `已封禁 ${email}`,
          () => api(`/admin/users/${uid}/ban`, { method: 'POST', body: { app, until, reason } }),
          true);
      });
      $$('#ud-body [data-unban]').forEach(btn => btn.addEventListener('click', () => {
        const app = btn.dataset.unban;
        const scopeLabel = app === '*' ? '全局' : appLabel(app);
        confirmAction(
          '解除封禁',
          `将解除对 ${email} 的「${scopeLabel}」封禁，该范围随即恢复可登录。`,
          `已解除 ${email} 的封禁`,
          () => api(`/admin/users/${uid}/ban`, { method: 'DELETE', body: { app } }),
          false);
      }));
    } catch (err) {
      $('#ud-body').innerHTML = `<p class="err">${esc(err.message)}</p>`;
    }
  }

  $('#ud-close').addEventListener('click', () => $('#user-detail').classList.add('hidden'));
  $('#user-search-form').addEventListener('submit', e => {
    e.preventDefault();
    pager.state.query = $('#user-query').value.trim();
    pager.state.offset = 0;
    inviteQuery = pager.state.query;   // 邀请记录复用同一查询串（邮箱片段）
    load();
    loadInvites();
  });
  pager.wire(load);

  // ---- 邀请用户（B9）：弹层提交 → 成功 toast + 顺手展开邀请区 ----
  $('#invite-open').addEventListener('click', openInvite);
  $('#invite-cancel').addEventListener('click', () => closeDialog($('#invite-dialog')));
  $('#invite-form').addEventListener('submit', async e => {
    e.preventDefault();
    const email = $('#invite-email').value.trim();
    const app = $('#invite-app').value;
    if (!email) { showErr('#invite-error', '请先填写被邀请人的邮箱'); return; }
    if (!IS_SUPER && !app) { showErr('#invite-error', '请先选择要加入的项目'); return; }
    const btn = $('#invite-ok');
    setBusy(btn, true);
    try {
      const res = await api('/admin/users/invite', { method: 'POST', body: { email, app } });
      closeDialog($('#invite-dialog'));
      toast(`邀请已发送至 ${email}，链接 ${remainTime(res.expiresAt)} 内有效`);
      $('#invites-wrap').open = true;
      await Promise.all([load(), loadInvites()]);
    } catch (err) { showErr('#invite-error', err.message); }
    finally { setBusy(btn, false); }
  });

  // ---- 批量（B9）：工具条三动作 + 全选 + 清空 ----
  $('#users-selall').addEventListener('change', e => {
    $$('#users-body .row-sel').forEach(cb => { cb.checked = e.target.checked; syncSelection(cb); });
  });
  $('#bulk-clear').addEventListener('click', () => {
    selected.clear();
    $$('#users-body .row-sel').forEach(cb => { cb.checked = false; });
    refreshBulkBar();
  });
  $('#bulk-reset').addEventListener('click', () => openBulk('password_reset'));
  $('#bulk-ban').addEventListener('click', () => openBulk('ban'));
  $('#bulk-unban').addEventListener('click', () => openBulk('unban'));
  $('#bulk-cancel').addEventListener('click', () => { bulkJob = null; closeDialog($('#bulk-dialog')); });
  $('#bulk-typed').addEventListener('input', syncBulkGate);
  $$('#bulk-dialog input[name=bulk-dur]').forEach(r => r.addEventListener('change', () => {
    const temp = $('#bulk-temp').checked;
    $('#bulk-until-field').classList.toggle('hidden', !temp);
    if (temp) { $('#bulk-until').min = banMinStr(); swapIn($('#bulk-until-field')); }
    showErr('#bulk-error', '');
  }));
  $('#bulk-ok').addEventListener('click', async () => {
    const job = bulkJob;
    if (!job) return;
    showErr('#bulk-error', '');
    if ((job.kind === 'ban' || job.kind === 'unban') && !$('#bulk-app').value) {
      showErr('#bulk-error', '请先选择操作范围');
      return;
    }
    if (job.kind === 'ban' && $('#bulk-temp').checked) {
      const v = $('#bulk-until').value;
      const until = v ? new Date(v).getTime() : 0;
      if (!until || until < Date.now() + 5 * 60 * 1000) {
        showErr('#bulk-error', '解除时间至少要在 5 分钟之后');
        return;
      }
    }
    const btn = $('#bulk-ok');
    setBusy(btn, true);   // 执行中：主钮 busy 禁用（CSS 接管转圈与 pointer-events）
    try {
      const res = await api('/admin/users/bulk', { method: 'POST', body: bulkRequest(job.kind, job.uids) });
      bulkState = { kind: job.kind, results: new Map() };
      (res.items || []).forEach(it => bulkState.results.set(it.uid, { ok: !!it.ok, message: it.message }));
      // 回执缺项按失败补记：结果面板宁可多报一条「未返回结果」，不能少报
      job.uids.forEach(uid => {
        if (!bulkState.results.has(uid)) {
          bulkState.results.set(uid, { ok: false, message: '未返回结果，请刷新后重试' });
        }
      });
      $('#bulk-dlg-confirm').classList.add('hidden');
      $('#bulk-dlg-result').classList.remove('hidden');
      renderBulkResults();
      swapIn($('#bulk-dlg-result'));
      await load();
    } catch (err) {
      showErr('#bulk-error', err.message);
    } finally { setBusy(btn, false); }
  });
  $('#bulk-retry-failed').addEventListener('click', async () => {
    const job = bulkJob;
    if (!job || !bulkState) return;
    const uids = $$('#bulk-result-list .bulk-retry-sel')
      .filter(cb => cb.checked).map(cb => Number(cb.dataset.uid));
    if (!uids.length) return;
    const btn = $('#bulk-retry-failed');
    setBusy(btn, true);
    try {
      const res = await api('/admin/users/bulk', { method: 'POST', body: bulkRequest(bulkState.kind, uids) });
      (res.items || []).forEach(it => {
        bulkState.results.set(it.uid, { ok: !!it.ok, message: it.message });
      });
      renderBulkResults();
      toast('已重试勾选的失败项');
      await load();
    } catch (err) { toast(err.message, true); }
    finally { setBusy(btn, false); }
  });
  $('#bulk-result-close').addEventListener('click', () => {
    closeDialog($('#bulk-dialog'));
    if (bulkState) {
      // 全成 → 清空选择；仍有失败 → 只留失败项在选择集里（改完直接再跑一次）
      const failed = new Set(Array.from(bulkState.results.entries())
        .filter(([, r]) => !r.ok).map(([uid]) => uid));
      Array.from(selected.keys()).forEach(uid => {
        if (!failed.size || !failed.has(uid)) selected.delete(uid);
      });
      refreshBulkBar();
    }
    bulkJob = null;
  });

  refreshBulkBar();
  load();
  loadInvites();
}

/* ---------- 后台：项目访问（W4）——每项目一张卡：登录范围开关 + 登录名单 ---------- */
const EMPTY_MEMBERS_HINT = '名单为空：开启限制后将只有管理员可以登录该项目。';
function initAdminAccess() {
  const wrap = $('#access-list');
  if (!wrap) return;
  let pending = null;

  // 通用确认弹层：一次挂一个待执行动作 + 它的成功提示（与用户页 confirmAction 同构）
  function confirmAccess(title, desc, danger, done, fn) {
    pending = { done, fn };
    $('#access-dlg-title').textContent = title;
    $('#access-dlg-desc').textContent = desc;
    $('#access-dlg-ok').classList.toggle('danger', !!danger);
    openDialog($('#access-dlg'), '#access-dlg-cancel');
  }
  $('#access-dlg-cancel').addEventListener('click', () => { pending = null; closeDialog($('#access-dlg')); });
  $('#access-dlg-ok').addEventListener('click', async () => {
    const job = pending;
    pending = null;
    closeDialog($('#access-dlg'));
    if (!job) return;
    const btn = $('#access-dlg-ok');
    setBusy(btn, true);
    try {
      await job.fn();
      toast(job.done);
    } catch (err) { toast(err.message, true); } finally { setBusy(btn, false); }
  });

  // ---- Web 接入（B4 OAuth 跳转授权）已整体撤下（W4 定案：项目访问页的两个日记
  // App 不是 web 项目，OAuth 接入留给以后的 web 项目）——后端 /admin/projects 的
  // clientId 字段与 /admin/projects/{app}/oauth 端点保留休眠，这里不再渲染任何入口。
  async function load() {
    showErr('#access-error', '');
    let list = [];
    try {
      const res = await api('/admin/projects');
      list = res.projects || [];
    } catch (err) {
      showErr('#access-error', err.message);
      wrap.innerHTML = '<div class="empty">读取失败，请刷新重试。</div>';
      return;
    }
    wrap.innerHTML = '';
    if (!list.length) {
      wrap.innerHTML = '<div class="empty">当前没有可管理的项目。</div>';
      return;
    }
    list.forEach(p => {
      const card = cardOf(p);
      wrap.appendChild(card);
      swapIn(card);   // 新卡片进场沿用区块切换动效（crossfade + 上浮）
    });
  }

  function cardOf(p) {
    const name = p.name || p.app;
    let restricted = !!p.restricted;
    const members = p.members || [];
    const card = node(`
      <section class="card" data-app="${esc(p.app)}">
        <div class="row between">
          <h2>${esc(name)} <span class="badge${restricted ? ' on' : ''}" data-badge>${restricted ? '仅限受邀' : '开放登录'}</span></h2>
          <span class="app-switch" role="group" aria-label="「${esc(name)}」登录范围">
            <button type="button" class="app-chip${restricted ? '' : ' on'}" data-restrict="0" aria-pressed="${restricted ? 'false' : 'true'}">开放登录</button>
            <button type="button" class="app-chip${restricted ? ' on' : ''}" data-restrict="1" aria-pressed="${restricted ? 'true' : 'false'}">仅限受邀</button>
          </span>
        </div>
        <div class="list" data-members style="margin-top:10px"></div>
        ${members.length ? '' : `<p class="hint" data-empty>${EMPTY_MEMBERS_HINT}</p>`}
        <form class="row" data-add style="margin-top:10px">
          <label class="field grow" style="margin:0"><span class="sr-only">要加入「${esc(name)}」登录名单的邮箱</span>
            <input type="email" placeholder="输入邮箱加入登录名单" autocomplete="off"></label>
          <button type="submit" class="btn">添加</button>
        </form>
        <p class="err" data-add-err role="alert" hidden></p>
      </section>`);
    const listEl = card.querySelector('[data-members]');

    function memberRow(email) {
      const row = node(`
        <div class="item" data-email="${esc(email)}">
          <span class="grow"><span class="title mono">${esc(email)}</span></span>
          <button type="button" class="btn small danger" data-remove>移除</button>
        </div>`);
      row.querySelector('[data-remove]').addEventListener('click', () => {
        confirmAccess('移出登录名单',
          `将把「${email}」移出「${name}」的登录名单；开启限制后，该邮箱将无法登录该项目。`,
          true, `已将 ${email} 移出「${name}」登录名单`,
          async () => {
            await api(`/admin/projects/${encodeURIComponent(p.app)}/access`, { method: 'DELETE', body: { email } });
            // 行先淡出下沉，播完再摘行——视觉上是「这条走了」而不是突然消失
            fadeOutRow(row, () => {
              row.remove();
              if (!listEl.children.length && !card.querySelector('[data-empty]')) {
                listEl.insertAdjacentElement('afterend', node(`<p class="hint" data-empty>${EMPTY_MEMBERS_HINT}</p>`));
              }
            });
          });
      });
      return row;
    }
    members.forEach(m => listEl.appendChild(memberRow(m.email)));

    // 开关状态就地更新（badge + 两颗 chip），不整卡重绘
    function setState(next) {
      restricted = next;
      $$('.app-chip', card).forEach(chip => {
        const on = (chip.dataset.restrict === '1') === restricted;
        chip.classList.toggle('on', on);
        chip.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      const badge = card.querySelector('[data-badge]');
      badge.textContent = restricted ? '仅限受邀' : '开放登录';
      badge.classList.toggle('on', restricted);
      popIn(badge);   // 状态翻转：徽标轻浮现
    }
    $$('.app-chip', card).forEach(chip => chip.addEventListener('click', () => {
      const want = chip.dataset.restrict === '1';
      if (want === restricted) return;
      confirmAccess('调整登录范围',
        want
          ? '开启后，除平台管理员、该项目的管理员和名单内用户外，其他账号将无法登录该项目。'
          : '开启后所有账号都可登录该项目。',
        want,
        want ? `已开启「${name}」仅限受邀登录` : `已关闭「${name}」的登录限制`,
        async () => {
          await api(`/admin/projects/${encodeURIComponent(p.app)}/restrict`, { method: 'POST', body: { restricted: want } });
          setState(want);
        });
    }));

    card.querySelector('[data-add]').addEventListener('submit', async e => {
      e.preventDefault();
      const form = e.currentTarget;
      const input = $('input', form);
      const errEl = card.querySelector('[data-add-err]');
      errEl.textContent = ''; errEl.hidden = true;
      const email = input.value.trim();
      if (!email) { errEl.textContent = '请输入邮箱'; errEl.hidden = false; return; }
      const btn = $('button[type=submit]', form);
      setBusy(btn, true);
      try {
        await api(`/admin/projects/${encodeURIComponent(p.app)}/access`, { method: 'POST', body: { email } });
        input.value = '';
        const emptyEl = card.querySelector('[data-empty]');
        if (emptyEl) emptyEl.remove();
        const row = memberRow(email);
        listEl.appendChild(row);
        popIn(row);   // 成功行内插入：轻浮现
        toast(`已将 ${email} 加入「${name}」登录名单`);
      } catch (err) {
        errEl.textContent = err.status === 404 ? '该邮箱不存在' : err.message;
        errEl.hidden = false;
      } finally { setBusy(btn, false); }
    });

    // Web 接入（clientId / 回跳地址 / Secret）块已撤下（W4）：见上方说明。
    return card;
  }

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
        const cur = map.get(s.uid) || { uid: s.uid, email: s.email, nickname: s.nickname, avatarColor: s.avatarColor, count: 0, last: 0 };
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
            <td class="wrap-cell">${userCell(u, 32)}</td>
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
              <span class="title">${esc(s.device)}</span>
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
  // ---- W8③ 时间范围重做：快捷档位 chips（今天 / 近 7 天 / 近 30 天 / 自定义）+
  // 两枚站内样式日期输入。档位选中即填 from/to 并查询；直接改日期输入则回落到
  // 「自定义」高亮。选中环沿用 app-chip 的 primary-soft 态，无新动效面。 ----
  const p2 = n => String(n).padStart(2, '0');
  const dayStr = d => `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`;
  function rangeChipSync(active) {
    $$('#audit-filter-form [data-range]').forEach(c => {
      const on = c.dataset.range === active;
      c.classList.toggle('on', on);
      c.setAttribute('aria-pressed', String(on));
    });
  }
  function setRange(kind) {
    if (kind === 'custom') {
      $('#audit-from').value = ''; $('#audit-to').value = '';
    } else {
      const now = new Date();
      const from = new Date(now);
      if (kind === '7') from.setDate(from.getDate() - 6);
      else if (kind === '30') from.setDate(from.getDate() - 29);
      $('#audit-from').value = dayStr(from);
      $('#audit-to').value = dayStr(now);
    }
    rangeChipSync(kind);
    pager.state.offset = 0;
    load();
  }
  $$('#audit-filter-form [data-range]').forEach(c =>
    c.addEventListener('click', () => setRange(c.dataset.range)));
  ['#audit-from', '#audit-to'].forEach(sel =>
    $(sel).addEventListener('change', () => rangeChipSync('custom')));
  $('#audit-reset').addEventListener('click', () => {
    $('#audit-action').value = ''; $('#audit-actor').value = ''; $('#audit-target').value = '';
    $('#audit-from').value = ''; $('#audit-to').value = '';
    rangeChipSync('custom');
    decorateSelect($('#audit-action'));   // 值被重置，同步下拉按钮文案
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
                <input type="text" style="min-width:200px" aria-label="新的值" autocomplete="off" placeholder="${it.secret ? '输入新值替换' : '留空则不修改'}">
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
              openDialog($('#cfg-dialog'), '#cfg-cancel');
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
      openDialog($('#quota-dialog'), '#q-input-rate');
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

/* openDialog 打开弹层并把初始焦点钉在**安全侧控件**（WAI-ARIA APG：破坏性对话框
   的初始焦点不得落在危险提交钮上）。focusSel 缺省时靠 DOM 顺序（取消钮在危险钮前）
   兜底——显式传参把这件事从「恰好如此」变成「规定如此」。原生 showModal 的模态性
   同时保证 Tab 循环留在弹层内。 */
function openDialog(dlg, focusSel) {
  if (!dlg) return;
  if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
  if (focusSel) { const el = typeof focusSel === 'string' ? $(focusSel) : focusSel; if (el) el.focus(); }
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

/* W9 下拉（站内 miuix 风）：把原生 <select> 装成「按钮 + 浮层菜单」（fade-scale
   进场走既有 swapIn）。原 select 保留为**值载体**（.hidden）：表单逻辑读
   .value / 改 .innerHTML 的代码一字不动；菜单每次打开按 当前 option 重建，
   openInvite/openBulk 这类后填选项的场景天然成立。
   键盘与无障碍：按钮 aria-haspopup=listbox + aria-expanded；Enter/空格/↓ 打开，
   ↑/↓ 移动高亮，Enter/空格 选中，Esc 关闭回焦；点外部关闭。 */
function decorateSelect(sel) {
  if (!sel) return null;
  if (sel.__dropSync) { sel.__dropSync(); return sel; }   // 已装饰：只同步按钮文案
  const wrap = document.createElement('span');
  wrap.className = 'select-drop';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'select-btn';
  btn.setAttribute('aria-haspopup', 'listbox');
  btn.setAttribute('aria-expanded', 'false');
  const label = document.createElement('span');
  btn.appendChild(label);
  // 展开箭头：与站内图标同 viewBox/线宽（ico 类），旋转动效由 CSS 接管
  const chev = node('<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="m6 9 6 6 6-6"/></svg>');
  btn.appendChild(chev);
  const menu = document.createElement('ul');
  menu.className = 'select-menu';
  menu.setAttribute('role', 'listbox');
  menu.hidden = true;
  sel.parentNode.insertBefore(wrap, sel);
  wrap.appendChild(btn);
  wrap.appendChild(menu);
  wrap.appendChild(sel);
  sel.classList.add('hidden');   // 值载体不参与视觉（.hidden !important 盖得住任何 UA display）
  let activeIdx = -1;

  function sync() {
    const opt = sel.options[sel.selectedIndex];
    label.textContent = opt ? opt.textContent : '';
    btn.disabled = sel.disabled;
  }
  function open() {
    menu.innerHTML = '';
    activeIdx = sel.selectedIndex;
    Array.from(sel.options).forEach((opt, i) => {
      const li = node('<li class="select-opt" role="option"></li>');
      li.textContent = opt.textContent;
      li.setAttribute('aria-selected', String(i === sel.selectedIndex));
      li.addEventListener('click', () => pick(i));
      menu.appendChild(li);
    });
    menu.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    swapIn(menu);   // 浮层进场：fade-scale（popIn 语义的区块动效）
    mark();
  }
  function mark() {
    $$('.select-opt', menu).forEach((li, i) => li.classList.toggle('active', i === activeIdx));
  }
  function close(focusBtn) {
    if (menu.hidden) return;
    menu.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    if (focusBtn) btn.focus();
  }
  function pick(i) {
    if (i < 0 || i >= sel.options.length) return;
    sel.selectedIndex = i;
    sel.dispatchEvent(new Event('change', { bubbles: true }));
    sync();
    close(true);
  }
  btn.addEventListener('click', () => (menu.hidden ? open() : close(false)));
  btn.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown' || e.key === 'ArrowUp') && menu.hidden) {
      e.preventDefault(); open(); return;
    }
    if (menu.hidden) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); activeIdx = Math.min(sel.options.length - 1, activeIdx + 1); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx = Math.max(0, activeIdx - 1); mark(); }
    else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(activeIdx); }
    else if (e.key === 'Escape') { e.preventDefault(); close(true); }
  });
  // 点外部关闭（弹层不拦 Tab：关闭后焦点仍在按钮，语义与原生一致）
  document.addEventListener('click', e => {
    if (!menu.hidden && !wrap.contains(e.target)) close(false);
  });
  sel.addEventListener('change', sync);
  sel.__dropSync = sync;
  sync();
  return sel;
}
function decorateSelects(root) {
  $$('select', root || document).forEach(decorateSelect);
}

/* ---------- 入口 ---------- */
document.addEventListener('DOMContentLoaded', () => {
  drainFlash();   // 跨页提示先出（注销撤销 / 强制改密成功 / 注销已提交）
  wireReauth();
  wireTabs();
  decorateSelects(document);   // W9：静态 <select> 全部换站内下拉（值载体保留）
  initAdminGuard();
  initAppSwitch();
  initLogin();
  initConsole();
  initSessions();
  initPasskeys();
  initSecurity();
  initAccount();
  initProfile();
  initLoginNotify();
  initAdminUsers();
  initAdminAccess();
  initAdminSessions();
  initAdminAudit();
  initAdminConfig();
  initAdminAI();
});
