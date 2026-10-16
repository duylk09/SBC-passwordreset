// Student Password Validator. Client-only: nothing is stored or sent anywhere.
const G = 'oklch(0.55 0.14 150)', R = 'oklch(0.55 0.18 25)';
const EMAIL_DOMAIN = 'southbankcolleges.ac.uk';
const COLLEGE = 'South Bank Colleges';
const COPY_SVG = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"><path d="M5.5 2.5h5.2l2.8 2.8v7.2a.5.5 0 0 1-.5.5H5.5a.5.5 0 0 1-.5-.5V3a.5.5 0 0 1 .5-.5z"/><path d="M10.5 2.5v3h3"/><path d="M3 5v8.5A1.5 1.5 0 0 0 4.5 15H10"/></svg>';

const fresh = () => ({ screen: 'lang', lang: 'en', id: '', pw: '', showPw: false, nameAns: null, copied: null });
let state = fresh();

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rnd = a => a[Math.floor(Math.random() * a.length)];

function genPw() {
  for (;;) {
    const words = rnd(W1) + rnd(W2);
    const room = 14 - words.length;
    if (room < 2) continue;
    const minD = Math.max(2, 11 - words.length);
    if (minD > room) continue;
    const nd = minD + Math.floor(Math.random() * (Math.min(room, 4) - minD + 1));
    let d = ''; for (let i = 0; i < nd; i++) d += Math.floor(Math.random() * 10);
    const pw = words + d + rnd(SPC);
    if (pw.length >= 12 && pw.length < 16 && /[a-z]/.test(pw)) return pw;
  }
}

function validate(pw) {
  const checks = [
    pw.length >= 12, /[A-Z]/.test(pw), /[a-z]/.test(pw), /[0-9]/.test(pw),
    /[!@&*#?$£\-_.\/]/.test(pw),
    /^[A-Za-z0-9!@&*#?$£\-_.\/]*$/.test(pw), // hidden charset rule: no visible row, but still blocks
  ];
  return { checks, base: checks.every(Boolean) };
}

function copyText(key, text) {
  const done = () => { state.copied = key; render(); clearTimeout(copyText.t); copyText.t = setTimeout(() => { state.copied = null; render(); }, 1500); };
  const fallback = () => {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    ta.remove(); done();
  };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
}

function go(screen) { state.screen = screen; render(); window.scrollTo(0, 0); }

function T() { const t = {}; KEYS.forEach((k, i) => t[k] = L[state.lang][2][i]); return t; }

function copyBtn(key) {
  return `<button type="button" class="copy${state.copied === key ? ' done' : ''}" data-copy="${key}" aria-label="Copy" title="Copy">${COPY_SVG}</button>`;
}
function monoRow(label, text, key, cls = '') {
  return `<span class="lbl">${esc(label)}</span><span class="val"><span dir="ltr" class="mono ${cls}">${esc(text)}</span>${copyBtn(key)}</span>`;
}

function langScreen() {
  return `<div class="stack">
    <div class="lang-head"><h1>Choose your language</h1><p>اختر لغتك · Choisissez votre langue · Elige tu idioma · 选择你的语言</p></div>
    <div class="lang-grid">${Object.keys(L).map(k => `<button class="lang-btn" data-lang="${k}"><b>${esc(L[k][0])}</b><span>${esc(L[k][1])}</span></button>`).join('')}</div>
  </div>`;
}

function formScreen(t) {
  const { checks, base } = validate(state.pw);
  const empty = state.pw.length === 0;
  const st = (ok, pending) => pending ? ['•', '#b5b7bc', '#45484d'] : ok ? ['✓', G, '#1b1c1e'] : ['✕', R, R];
  const rows = checks.slice(0, 5).map((ok, i) => [t['r' + (i + 1)], ...st(ok, empty)]);
  rows.push([t.r6, ...st(state.nameAns === 'no', state.nameAns === null)]);
  const valid = base && state.nameAns === 'no' && state.id.trim().length >= 3;
  return `<div class="stack22">
    <h1 class="title">${esc(t.title)}</h1>
    <label class="field"><span>${esc(t.idLabel)}</span>
      <input id="id" class="input" dir="ltr" value="${esc(state.id)}" inputmode="numeric" autocomplete="off" placeholder="${esc(t.idPh)}"></label>
    <label class="field"><span>${esc(t.pwLabel)}</span>
      <div class="row"><input id="pw" class="input" dir="ltr" type="${state.showPw ? 'text' : 'password'}" value="${esc(state.pw)}" autocomplete="new-password" spellcheck="false" autocapitalize="off">
      <button type="button" class="toggle" data-act="toggle">${esc(state.showPw ? t.hide : t.show)}</button></div></label>
    <button type="button" class="suggest" data-act="suggest">↻ ${esc(SUGGEST[state.lang] || SUGGEST.en)}</button>
    <div class="rules">
      <div class="rules-title">${esc(t.rulesTitle)}</div>
      ${rows.map(([text, icon, bg, color]) => `<div class="rule"><i style="background:${bg}">${icon}</i><span style="color:${color}">${esc(text)}</span></div>`).join('')}
      ${base ? `<div class="ask"><div class="ask-q">${esc(t.q6)}</div>
        <div class="yn"><button class="yes${state.nameAns === 'yes' ? ' on' : ''}" data-ans="yes">${esc(t.yes)}</button><button class="no${state.nameAns === 'no' ? ' on' : ''}" data-ans="no">${esc(t.no)}</button></div>
        ${state.nameAns === 'yes' ? `<div class="notice">${esc(t.yesMsg)}</div>` : ''}</div>` : ''}
    </div>
    <button class="primary" data-act="submit"${valid ? '' : ' disabled'}>${esc(t.showDetails)}</button>
  </div>`;
}

function detailsScreen(t) {
  const id = state.id.trim(), email = id + '@' + EMAIL_DOMAIN;
  return `<div class="details">
    <div class="card">
      <div class="card-head"><b>${esc(t.detailsTitle)}</b><span>${COLLEGE}</span></div>
      <div class="bar" style="background:linear-gradient(90deg,#0a1f9e,#2f62f0)">${esc(t.computer)}</div>
      <div class="grid">${monoRow(t.username, id, 'id')}${monoRow(t.password, state.pw, 'pw')}</div>
      <div class="bar" style="background:#3f5f90">${esc(t.wifi)}</div>
      <div class="grid">${monoRow(t.identity, id, 'id')}${monoRow(t.password, state.pw, 'pw')}
        <span class="lbl">${esc(t.ca)}</span><span dir="ltr" class="plain">Don't validate / Trust on first use</span></div>
      <div class="bar" style="background:#5b5fc7">${esc(t.teams)} · Microsoft Office</div>
      <div class="grid last">${monoRow(t.email, email, 'email', 'sm')}${monoRow(t.password, state.pw, 'pw')}</div>
    </div>
    <div class="hint">${esc(t.hint)}</div>
    <div class="actions"><button class="btn-sec" data-act="back">${esc(t.back)}</button><button class="btn-sec btn-reset" data-act="reset">${esc(RESET[state.lang] || RESET.en)}</button></div>
  </div>`;
}

function render() {
  const t = T();
  const a = document.activeElement;
  const focus = a && (a.id === 'id' || a.id === 'pw') ? { id: a.id, s: a.selectionStart, e: a.selectionEnd } : null;
  const screen = { lang: langScreen, form: formScreen, details: detailsScreen }[state.screen](t);
  const dir = state.lang === 'ar' || state.lang === 'ku' ? 'rtl' : 'ltr';
  document.documentElement.lang = state.lang;
  document.getElementById('app').innerHTML = `<div class="root" dir="${dir}"><div class="col">
    <div class="header"><div class="college">${COLLEGE}</div>${state.screen !== 'lang' ? `<button class="pill" data-act="lang">${esc(t.lang)}: ${esc(L[state.lang][0])}</button>` : ''}</div>
    ${screen}</div></div>`;
  if (focus) {
    const el = document.getElementById(focus.id);
    if (el) { el.focus(); try { el.setSelectionRange(focus.s, focus.e); } catch (e) {} }
  }
}

const app = document.getElementById('app');
app.addEventListener('input', e => {
  if (e.target.id === 'id') { state.id = e.target.value.replace(/\s/g, ''); render(); }
  else if (e.target.id === 'pw') { state.pw = e.target.value; state.nameAns = null; render(); }
});
app.addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  const d = b.dataset;
  if (d.lang) { state.lang = d.lang; go('form'); }
  else if (d.ans) { state.nameAns = d.ans; render(); }
  else if (d.copy) copyText(d.copy, d.copy === 'id' ? state.id.trim() : d.copy === 'pw' ? state.pw : state.id.trim() + '@' + EMAIL_DOMAIN);
  else if (d.act === 'lang') go('lang');
  else if (d.act === 'toggle') { state.showPw = !state.showPw; render(); }
  else if (d.act === 'suggest') { state.pw = genPw(); state.showPw = true; state.nameAns = null; render(); }
  else if (d.act === 'submit') { if (!b.disabled) go('details'); }
  else if (d.act === 'back') go('form');
  else if (d.act === 'reset') { state = fresh(); go('lang'); }
});
render();
