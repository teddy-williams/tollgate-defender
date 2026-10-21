// Tollgate UI. SECURITY: report content (filenames, strings, URLs, sandbox output) comes from hostile files.
// Everything is inserted with textContent / createTextNode, never innerHTML.
'use strict';

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const RANK = { viewer: 1, analyst: 2, admin: 3 };
const state = { user: null, csrf: null, status: null, pollToken: 0 };
const $ = (id) => document.getElementById(id);

// ---------- helpers ----------
function el(tag, attrs, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === undefined || kid === null || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

function visible(s) {          // make invisible/bidi characters visible, e.g. \u{202e}
  return Array.from(String(s ?? '')).map((ch) => {
    const c = ch.codePointAt(0);
    const hidden = c < 32 || c === 127 || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e)
      || (c >= 0x2066 && c <= 0x2069) || c === 0xfeff || c === 0xad;
    return hidden ? '\\u{' + c.toString(16) + '}' : ch;
  }).join('');
}

function defang(url) {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([\s\S]*)$/.exec(url);
  if (!m) return url;
  const scheme = { http: 'hxxp', https: 'hxxps', ftp: 'fxp' }[m[1].toLowerCase()] || m[1];
  const auth = m[2].replace(/\[\.\]/g, '.').replace(/\./g, '[.]').replace(/@/g, '[@]');
  return scheme + '://' + auth + m[3];
}
const defangHost = (v) => String(v).replace(/\[\.\]/g, '.').replace(/\./g, '[.]');
const defangText = (t) => visible(String(t ?? '')).replace(/\b(?:https?|ftp):\/\/[^\s'"<>]+/gi, defang);
const can = (min) => state.user && RANK[state.user.role] >= RANK[min];
const msg = (cls, text) => el('div', { class: 'msg ' + cls }, text);
const fmtTime = (t) => (t || '').replace('T', ' ').replace('+00:00', ' UTC');
const show = (root, ...nodes) => root.replaceChildren(...nodes.flat(Infinity).filter(Boolean));

class ApiError extends Error { constructor(message, status) { super(message); this.status = status; } }

async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  const headers = Object.assign({}, opts.headers);
  let body = opts.body;
  if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
  if (method !== 'GET' && state.csrf) headers['X-CSRF-Token'] = state.csrf;
  const resp = await fetch(path, { method, headers, body, credentials: 'same-origin' });
  let data = null;
  try { data = await resp.json(); } catch (_) { /* non-JSON body */ }
  if (!resp.ok) {
    const detail = data && data.detail ? (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)) : resp.statusText;
    if (resp.status === 401 && state.user && !opts.quiet401) { state.user = null; showLogin('Your session ended. Please sign in again.'); }
    else if (resp.status === 403 && /must change your password/.test(detail)) showForcedChange();
    throw new ApiError(detail, resp.status);
  }
  return data;
}

async function guarded(root, button, fn) {
  if (button) button.disabled = true;
  show(root, msg('info', 'Working…'));
  try { await fn(); } catch (e) { show(root, msg('err', e.message)); } finally { if (button) button.disabled = false; }
}

function modal(title, ...content) {
  const root = $('modal-root');
  const close = () => root.replaceChildren();
  root.replaceChildren(el('div', { class: 'overlay', onclick: (e) => { if (e.target.classList.contains('overlay')) close(); } },
    el('div', { class: 'modal' }, el('h3', {}, title), ...content, el('div', { class: 'row' }, el('button', { onclick: close }, 'Close')))));
  return close;
}

// ---------- views: login / forced change / app ----------
function showView(name) {
  for (const id of ['login-view', 'change-view', 'app-view']) $(id).hidden = id !== name;
}

async function showLogin(note) {
  state.pollToken++;
  state.user = null; state.csrf = null;
  $('modal-root').replaceChildren();
  showView('login-view');
  const out = $('login-msg');
  show(out, note ? msg('info', note) : null);
  try {
    const st = await api('/api/auth/status', { quiet401: true });
    if (st.setup_required) {
      show(out, msg('info', 'No accounts exist yet. On the machine running Tollgate, create the owner account with:  docker compose run --rm cli user create-master YOUR-USERNAME   (or, without Docker:  tollgate user create-master YOUR-USERNAME)'));
    }
  } catch (_) { /* leave the form usable */ }
}

function showForcedChange() { showView('change-view'); show($('chg-msg')); }

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  try {
    const r = await api('/api/auth/login', { method: 'POST', json: { username: $('login-user').value.trim(), password: $('login-pass').value }, quiet401: true });
    $('login-pass').value = '';
    state.user = r.user; state.csrf = r.csrf;
    if (r.must_change_password) { $('chg-current').value = ''; showForcedChange(); } else await bootApp();
  } catch (err) { show($('login-msg'), msg('err', err.message)); } finally { btn.disabled = false; }
});

$('change-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if ($('chg-new').value !== $('chg-new2').value) return show($('chg-msg'), msg('err', 'The two new passwords do not match.'));
  try {
    await api('/api/auth/change-password', { method: 'POST', json: { current_password: $('chg-current').value, new_password: $('chg-new').value } });
    for (const id of ['chg-current', 'chg-new', 'chg-new2']) $(id).value = '';
    const st = await api('/api/auth/status');
    state.user = st.user; state.csrf = st.csrf;
    await bootApp();
  } catch (err) { show($('chg-msg'), msg('err', err.message)); }
});

async function bootApp() {
  showView('app-view');
  state.status = await api('/api/status');
  $('user-btn').textContent = state.user.username + ' · ' + (state.user.is_master ? 'master' : state.user.role);
  document.querySelectorAll('#tabs button').forEach((b) => { b.hidden = !can(b.dataset.min); });
  $('admin-forms').hidden = !can('admin');
  $('detonate-row').hidden = !(can('analyst') && state.status.dynamic === 'cape');
  const tr = state.status.tracing;
  $('trace').disabled = tr === 'disabled';
  $('health').textContent = 'v' + state.status.version + ' · YARA ' + (state.status.yara_rules || 0) + ' rules · tracing ' + tr + ' · sandbox ' + state.status.dynamic;
  openTab(can('analyst') ? 'scan' : 'history');
}

// ---------- user menu / account ----------
$('user-btn').addEventListener('click', () => { $('user-menu').hidden = !$('user-menu').hidden; });
document.addEventListener('click', (e) => { if (!e.target.closest('.usermenu')) $('user-menu').hidden = true; });
$('menu-logout').addEventListener('click', async () => {
  $('user-menu').hidden = true;
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (_) { /* already signed out */ }
  await showLogin('You have been signed out.');
});
$('menu-account').addEventListener('click', () => { $('user-menu').hidden = true; accountModal(); });

function accountModal() {
  const out = el('div'); const tokOut = el('div'); const tokList = el('div');
  const cur = el('input', { type: 'password', placeholder: 'current password', autocomplete: 'current-password' });
  const n1 = el('input', { type: 'password', placeholder: 'new password (12+ characters)', autocomplete: 'new-password' });
  const n2 = el('input', { type: 'password', placeholder: 'repeat new password', autocomplete: 'new-password' });
  const label = el('input', { type: 'text', placeholder: 'token label, e.g. mail-gateway' });
  const days = el('input', { type: 'text', placeholder: 'expires in days (optional)' });
  async function loadTokens() {
    const rows = await api('/api/me/tokens');
    show(tokList, rows.length ? el('table', {}, el('thead', {}, el('tr', {}, ['Label', 'Prefix', 'Created', 'Last used', 'Expires', ''].map((h) => el('th', {}, h)))),
      el('tbody', {}, rows.map((r) => el('tr', {}, el('td', {}, visible(r.label)), el('td', {}, r.prefix + '…'), el('td', {}, fmtTime(r.created_at)),
        el('td', {}, fmtTime(r.last_used) || 'never'), el('td', {}, r.revoked ? 'revoked' : fmtTime(r.expires_at) || 'never'),
        el('td', {}, r.revoked ? '' : el('button', { class: 'btn-sm btn-danger', onclick: async () => { await api('/api/me/tokens/' + r.id, { method: 'DELETE' }); loadTokens(); } }, 'Revoke'))))))
      : msg('info', 'No API tokens yet.'));
  }
  modal('Account: ' + state.user.username,
    el('h4', {}, 'Change password'), cur, n1, n2,
    el('div', { class: 'row' }, el('button', { class: 'primary', onclick: async () => {
      if (n1.value !== n2.value) return show(out, msg('err', 'The two new passwords do not match.'));
      try { await api('/api/auth/change-password', { method: 'POST', json: { current_password: cur.value, new_password: n1.value } });
        cur.value = n1.value = n2.value = ''; show(out, msg('ok', 'Password changed. Other sessions were signed out.')); } catch (e) { show(out, msg('err', e.message)); }
    } }, 'Change password')), out,
    el('h4', {}, 'API tokens'), el('p', { class: 'muted' }, 'For scripts and mail gateways: send them as "Authorization: Bearer tg_…". A token has your role and can be revoked at any time.'),
    el('div', { class: 'row' }, label, days, el('button', { class: 'primary', onclick: async () => {
      try { const d = parseInt(days.value, 10);
        const r = await api('/api/me/tokens', { method: 'POST', json: { label: label.value || 'token', days: Number.isFinite(d) ? d : null } });
        show(tokOut, msg('info', r.note), el('div', { class: 'tokenbox' }, r.token)); label.value = days.value = ''; loadTokens(); } catch (e) { show(tokOut, msg('err', e.message)); }
    } }, 'Create token')), tokOut, tokList);
  loadTokens().catch((e) => show(tokList, msg('err', e.message)));
}

// ---------- rendering reports ----------
function findingList(findings) {
  const sorted = [...findings].sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
  if (!sorted.length) return msg('info', 'No findings.');
  return el('div', {}, sorted.map((f) => el('div', { class: 'finding ' + f.severity },
    el('div', { class: 't' }, el('span', { class: 'chip ' + f.severity }, f.severity), defangText(f.title), el('span', { class: 'rid' }, f.rule_id)),
    f.detail ? el('div', { class: 'd' }, defangText(f.detail)) : null)));
}

function banner(verdict, score) {
  return el('div', { class: 'banner ' + verdict.toLowerCase() },
    el('div', { class: 'verdict' }, verdict.toUpperCase()), el('div', {}, 'score ' + score + '/100'),
    el('div', { class: 'bar' }, el('i', { style: 'width:' + Math.max(2, score) + '%' })));
}

function table(headers, rows, onclick) {
  return el('table', {}, el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r) => el('tr', { class: onclick ? 'click' : '', onclick: onclick ? () => onclick(r) : null }, r.cells.map((c) => el('td', {}, c))))));
}
const kv = (pairs) => el('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== '').flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, String(v))]));
const sectionTitle = (t) => el('div', { class: 'section-title' }, t);

function renderLnk(m) {
  const t = m.tracker;
  return [sectionTitle('Shortcut (.lnk) structure'), kv([
    ['Target', visible(m.target || m.idlist_path || m.env_target)], ['Arguments', defangText(m.arguments)], ['Decoded command', defangText(m.decoded_command)],
    ['Working dir', m.working_dir], ['Icon', m.icon_location], ['Window', m.show_command], ['Description', m.name],
    ['Created on', t ? `${t.machine_id || '?'}${t.file_guid_mac ? ' (MAC ' + t.file_guid_mac + ')' : ''}` : null],
    ['Appended bytes', m.appended_bytes ? m.appended_bytes : null], ['Blocks', (m.extra_blocks || []).join(', ')]])];
}

function renderPdf(m) {
  const out = [sectionTitle('PDF structure'), kv([['Version', m.version], ['Pages', m.pages], ['Objects', m.objects], ['Streams', m.streams],
    ['Producer', m.info && m.info.producer], ['Creator', m.info && m.info.creator], ['Encrypted', m.encrypted ? 'yes' : null],
    ['Bytes after %%EOF', m.appended_bytes || null], ['Revisions', m.eof_count > 1 ? m.eof_count : null]])];
  const kw = Object.entries(m.keywords || {});
  if (kw.length) out.push(table(['Keyword', 'Count'], kw.map(([k, v]) => ({ cells: ['/' + k, v] }))));
  if ((m.scripts || []).length) out.push(sectionTitle('JavaScript'), table(['Origin', 'Size', 'SHA-256', 'Preview'],
    m.scripts.map((s) => ({ cells: [visible(s.origin), s.size, s.sha256.slice(0, 16) + '…', visible(s.preview).slice(0, 80)] }))));
  if ((m.uris || []).length) out.push(sectionTitle('Links (defanged)'), el('ul', {}, m.uris.slice(0, 15).map((u) => el('li', {}, defang(u)))));
  if ((m.embedded || []).length) out.push(sectionTitle('Embedded files'), table(['Name', 'Type', 'Size', 'SHA-256'],
    m.embedded.map((e) => ({ cells: [visible(e.name), e.type, e.size, e.sha256.slice(0, 16) + '…'] }))));
  return out;
}

function renderDynamic(sm, taskId) {
  const out = [el('div', { class: 'dyn' }, el('h4', {}, 'Sandbox run (CAPE)'), kv([
    ['Score', sm.malscore === null || sm.malscore === undefined ? null : sm.malscore + ' / 10'], ['Family', (sm.families || []).join(', ') || 'none named'],
    ['Duration', sm.duration ? sm.duration + ' s' : null], ['Guest', sm.machine], ['Techniques', (sm.ttps || []).join(', ')]]))];
  const box = out[0];
  if ((sm.signatures || []).length) box.append(table(['Sev', 'Behaviour'], sm.signatures.slice(0, 12).map((s) => ({ cells: [s.severity, visible(s.description || s.name)] }))));
  if ((sm.processes || []).length) box.append(sectionTitle('Processes'), table(['Process', 'PID', 'Command line'], sm.processes.slice(0, 10).map((p) => ({ cells: [visible(p.name), p.pid, defangText(p.command_line)] }))));
  const picks = [];
  const add = (type, values) => (values || []).forEach((v) => picks.push({ type, value: v }));
  add('domain', sm.network && sm.network.domains); add('url', sm.network && sm.network.urls); add('ip', sm.network && sm.network.ips);
  add('url', sm.c2_candidates); add('sha256', (sm.dropped || []).map((d) => d.sha256));
  const seen = new Set(); const uniq = picks.filter((p) => !seen.has(p.type + p.value) && seen.add(p.type + p.value));
  if (uniq.length) {
    box.append(sectionTitle('Indicators seen during the run'));
    const boxes = uniq.slice(0, 60).map((p) => ({ p, cb: el('input', { type: 'checkbox' }) }));
    boxes.forEach(({ p, cb }) => box.append(el('label', { class: 'ioc-pick' }, cb, el('span', {}, p.type + ': ' + (p.type === 'sha256' ? p.value : p.type === 'url' ? defangText(p.value) : defangHost(p.value))))));
    if (can('admin') && taskId) {
      const sev = el('select', {}, ['high', 'critical', 'medium', 'low'].map((s) => el('option', {}, s)));
      const result = el('div');
      box.append(msg('info', 'Review before adding: the sandbox also sees harmless traffic. Selected items go into the threat-intel database.'),
        el('div', { class: 'row' }, sev, el('button', { class: 'primary', onclick: async () => {
          const items = boxes.filter((b) => b.cb.checked).map((b) => ({ type: b.p.type, value: b.p.value, severity: sev.value }));
          if (!items.length) return show(result, msg('err', 'Tick at least one indicator.'));
          try { const r = await api('/api/dynamic/' + taskId + '/iocs', { method: 'POST', json: { items } }); show(result, msg('ok', r.added + ' indicator(s) added.')); }
          catch (e) { show(result, msg('err', e.message)); }
        } }, 'Add selected to threat intel')), result);
    }
  }
  return out;
}

function renderReport(r) {
  const out = [banner(r.verdict, r.score)];
  out.push(el('dl', { class: 'kv' }, el('dt', {}, 'File'), el('dd', {}, visible(r.filename)), el('dt', {}, 'Type'), el('dd', {}, r.detected_type + ' (from content)'),
    el('dt', {}, 'Size'), el('dd', {}, r.size.toLocaleString() + ' bytes'), el('dt', {}, 'SHA-256'), el('dd', {}, r.hashes.sha256), el('dt', {}, 'MD5'), el('dd', {}, r.hashes.md5),
    r.scan_id ? el('dt', {}, 'Logged') : null, r.scan_id ? el('dd', {}, 'scan #' + r.scan_id) : null));
  out.push(sectionTitle('Findings (' + r.findings.length + ')'), findingList(r.findings));
  const md = r.metadata || {};
  if (md.yara) out.push(sectionTitle('YARA'), msg('info', md.yara.rules_loaded + ' rules loaded, ' + md.yara.matches.length + ' matched' + (md.yara.matches.length ? ': ' + md.yara.matches.map((m) => m.rule).join(', ') : '')));
  if (md.lnk) out.push(...renderLnk(md.lnk));
  if (md.pdf) out.push(...renderPdf(md.pdf));
  if ((md.artifacts || []).length) out.push(sectionTitle('Extracted and examined'), table(['What', 'Type', 'Size', 'SHA-256'],
    md.artifacts.map((a) => ({ cells: [visible(a.label), a.type, a.size, a.sha256.slice(0, 16) + '…'] }))));
  const pe = md.pe;
  if (pe && pe.sections) {
    out.push(sectionTitle('PE sections'), table(['Name', 'Perms', 'Raw size', 'Entropy'], pe.sections.map((s) => ({ cells: [visible(s.name), s.perms, s.raw_size, s.entropy] }))));
    const imp = pe.imports || {};
    out.push(kv([['Imphash', imp.imphash || '-'], ['Compiled', pe.compile_time || '-'], ['Imports', imp.count ?? 0]]));
  }
  const urls = (pe && pe.urls) || (md.lnk && md.lnk.urls) || (md.pdf && md.pdf.urls) || [];
  if (urls.length) out.push(sectionTitle('Embedded URLs (defanged)'), el('ul', {}, urls.map((u) => el('li', {}, defang(u)))));
  if (md.dynamic) out.push(...renderDynamic(md.dynamic, md.dynamic.task_id));
  out.push(el('div', { class: 'row' }, el('button', { onclick: () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' }));
    const a = el('a', { href: url, download: 'tollgate-report-' + r.hashes.sha256.slice(0, 12) + '.json' });
    document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } }, 'Download JSON report')));
  return out;
}

function renderTrace(t) {
  const out = [sectionTitle('Redirect trace: ' + t.verdict + ' (score ' + t.score + ')'), msg('info', t.reason || '')];
  out.push(el('ol', { class: 'hops' }, t.hops.map((h, i) => el('li', { 'data-n': String(i + 1) },
    el('div', { class: 'u' }, defangText(h.url_defanged || h.url)),
    el('div', { class: 'm' }, [h.status ? 'HTTP ' + h.status : null, h.kind === 'meta-refresh' ? 'meta-refresh' : null, h.ip ? 'ip ' + h.ip : null, h.content_type,
      h.download ? 'DOWNLOAD' + (h.filename ? ' ' + visible(h.filename) : '') : null, h.location ? '→ ' + defangText(h.location) : null, h.note,
      h.blocked ? 'NOT FOLLOWED: ' + h.blocked : null, h.error ? 'ERROR: ' + h.error : null].filter(Boolean).join('  ·  '))))));
  out.push(findingList(t.findings));
  return out;
}

// ---------- tabs ----------
function openTab(name) {
  state.pollToken++;
  document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + name));
  if (name === 'history') loadHistory();
  if (name === 'intel') { loadStats(); loadRules(); }
  if (name === 'users') { loadUsers(); loadAudit(); }
}
document.querySelectorAll('#tabs button').forEach((b) => b.addEventListener('click', () => openTab(b.dataset.tab)));

// ---------- scan + sandbox polling ----------
async function pollDynamic(taskId, panel, reportRoot) {
  const token = ++state.pollToken;
  const started = Date.now();
  while (token === state.pollToken && Date.now() - started < 20 * 60 * 1000) {
    let t;
    try { t = await api('/api/dynamic/' + taskId); } catch (e) { show(panel, msg('err', e.message)); return; }
    if (token !== state.pollToken) return;
    if (t.status === 'reported') {
      show(panel, msg('ok', 'Sandbox run finished. The verdict above now includes what it did.'));
      if (t.scan) { try { show(reportRoot, renderReport(await api('/api/history/' + t.scan.id))); } catch (_) { /* keep static view */ } }
      return;
    }
    if (t.status === 'failed') return show(panel, msg('err', 'Sandbox run failed: ' + (t.error || 'unknown error')));
    show(panel, el('div', { class: 'msg info' }, el('span', { class: 'spinner' }), 'Sandbox task #' + taskId + ': ' + t.status + (t.warning ? ' (' + t.warning + ')' : '') + '. This can take a few minutes.'));
    await new Promise((r) => setTimeout(r, window.tollgateFastPoll ? 50 : 5000));
  }
}

async function scanFile(file) {
  const fd = new FormData();
  fd.append('file', file, file.name);
  fd.append('record', $('record').checked ? 'true' : 'false');
  const detonate = !$('detonate-row').hidden && $('detonate').checked;
  if (detonate) fd.append('detonate', 'true');
  await guarded($('scan-out'), null, async () => {
    const r = await api('/api/scan', { method: 'POST', body: fd });
    const reportRoot = el('div'); const panel = el('div');
    show($('scan-out'), panel, reportRoot);
    show(reportRoot, renderReport(r));
    if (r.dynamic && r.dynamic.error) show(panel, msg('err', 'Sandbox: ' + r.dynamic.error));
    else if (r.dynamic) pollDynamic(r.dynamic.task_id, panel, reportRoot);
  });
}
const drop = $('drop');
$('file').addEventListener('change', (e) => { if (e.target.files[0]) scanFile(e.target.files[0]); e.target.value = ''; });
['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => { if (e.dataTransfer.files[0]) scanFile(e.dataTransfer.files[0]); });
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('file').click(); } });

// ---------- url ----------
async function checkUrl(url, trace) {
  await guarded($('url-out'), $('url-form').querySelector('button'), async () => {
    const r = await api('/api/url', { method: 'POST', json: { url, trace } });
    const parts = [banner(r.verdict, r.score), kv([['URL', defangText(r.defanged)], ['Host', r.host || '-']]),
      sectionTitle('Findings (' + r.findings.length + ')'), findingList(r.findings)];
    if (r.trace) parts.push(renderTrace(r.trace));
    show($('url-out'), parts);
  });
}
$('url-form').addEventListener('submit', (e) => { e.preventDefault(); const v = $('url-input').value.trim(); if (v) checkUrl(v, $('trace').checked); });

// ---------- history ----------
async function loadHistory() {
  const q = new URLSearchParams({ limit: '100' });
  if ($('h-name').value.trim()) q.set('q', $('h-name').value.trim());
  if ($('h-verdict').value) q.set('verdict', $('h-verdict').value);
  show($('history-detail'));
  await guarded($('history-out'), $('h-refresh'), async () => {
    const rows = await api('/api/history?' + q);
    if (!rows.length) return show($('history-out'), msg('info', 'No scans logged yet.'));
    show($('history-out'), table(['#', 'When', 'File', 'Type', 'Verdict', 'Score', 'By'],
      rows.map((r) => ({ id: r.id, cells: [r.id, fmtTime(r.scanned_at), visible(r.filename).slice(0, 60), r.detected_type, el('span', { class: 'v-' + r.verdict }, r.verdict), r.score, r.scanned_by || 'cli'] })),
      async (row) => { show($('history-detail'), el('h3', {}, 'Scan #' + row.id), renderReport(await api('/api/history/' + row.id))); $('history-detail').scrollIntoView?.({ behavior: 'smooth' }); }));
  });
}
$('h-refresh').addEventListener('click', loadHistory);
$('h-urls').addEventListener('click', () => guarded($('history-out'), $('h-urls'), async () => {
  const rows = await api('/api/urls?limit=200');
  show($('history-detail'));
  show($('history-out'), rows.length ? table(['URL (defanged)', 'Seen', 'First', 'Last', 'Intel'],
    rows.map((r) => ({ cells: [defang(r.url).slice(0, 90), r.times_seen, fmtTime(r.first_seen), fmtTime(r.last_seen), r.intel ? el('span', { class: 'v-Malicious' }, 'MATCH') : ''] }))) : msg('info', 'No URLs tracked yet.'));
}));

// ---------- intel ----------
async function loadStats() {
  try {
    const s = await api('/api/intel/stats');
    const card = (n, l) => el('div', { class: 'card2' }, el('b', {}, n), el('span', {}, l));
    show($('intel-stats'), card(s.scans, 'scans logged'), card(s.tracked_urls, 'URLs tracked'), card(s.iocs_total, 'indicators'), card(s.rules, 'string rules'),
      card(s.last_update ? fmtTime(s.last_update.ts).slice(0, 16) : 'never', 'last feed update'));
  } catch (e) { show($('intel-stats'), msg('err', e.message)); }
}
async function loadRules() {
  try {
    const r = await api('/api/rules');
    const blocks = [msg('info', 'YARA: ' + r.yara.rules + ' rules from ' + (r.yara.loaded.join(', ') || 'no files') + (r.yara.available ? '' : ' (yara-python not installed)'))];
    r.yara.errors.forEach((er) => blocks.push(msg('err', visible(er.file) + ': ' + er.error)));
    if (r.regex.length) blocks.push(table(['Name', 'Severity', 'Regex', 'Description'], r.regex.map((x) => ({ cells: [x.name, x.severity, x.regex, x.description || ''] }))));
    show($('rules-out'), blocks);
  } catch (e) { show($('rules-out'), msg('err', e.message)); }
}
$('i-search-btn').addEventListener('click', () => guarded($('intel-out'), $('i-search-btn'), async () => {
  const rows = await api('/api/intel/search?q=' + encodeURIComponent($('i-search').value.trim()));
  show($('intel-out'), rows.length ? table(['Type', 'Value', 'Family', 'Source', 'Severity'], rows.map((r) => ({ cells: [r.ioc_type, defangText(r.value), r.family || '-', r.source, r.severity] }))) : msg('info', 'Not in the intel database.'));
}));
$('i-retro').addEventListener('click', () => guarded($('intel-out'), $('i-retro'), async () => {
  const rows = await api('/api/retro');
  show($('intel-out'), rows.length ? [msg('err', rows.length + ' past scan(s) now match current intel'),
    table(['Scan', 'File', 'Verdict then', 'Matched', 'Family', 'Source'], rows.map((r) => ({ cells: [r.scan_id, visible(r.filename), r.verdict_at_scan, r.ioc_type + ': ' + defangText(r.value).slice(0, 40), r.family || '-', r.source] })))]
    : msg('ok', 'No past scans match the current intel.'));
}));
async function admin(form, path, bodyFn, doneText) {
  await guarded($('admin-out'), form.querySelector('button'), async () => {
    const res = await api(path, { method: 'POST', json: bodyFn() });
    show($('admin-out'), msg('ok', doneText(res)));
    loadStats(); loadRules();
  });
}
$('ioc-form').addEventListener('submit', (e) => { e.preventDefault();
  admin(e.target, '/api/intel/ioc', () => ({ type: $('ioc-type').value, value: $('ioc-value').value, family: $('ioc-family').value || null, severity: $('ioc-sev').value, source: 'ui:' + state.user.username }),
    (r) => 'Indicator ' + r.result + '. Run a retro-hunt to see if past scans match.'); });
$('imp-form').addEventListener('submit', (e) => { e.preventDefault();
  admin(e.target, '/api/intel/import', () => ({ type: $('imp-type').value, text: $('imp-text').value, source: 'ui-import:' + state.user.username }),
    (r) => 'Imported: ' + r.added + ' added, ' + r.updated + ' updated, ' + r.invalid + ' invalid.'); });
$('rx-form').addEventListener('submit', (e) => { e.preventDefault();
  admin(e.target, '/api/rules/regex', () => ({ name: $('rx-name').value, regex: $('rx-regex').value, severity: $('rx-sev').value, description: $('rx-desc').value }), () => 'Rule saved. It applies to every new scan of PE files.'); });
$('yr-form').addEventListener('submit', (e) => { e.preventDefault();
  admin(e.target, '/api/rules/yara', () => ({ name: $('yr-name').value, text: $('yr-text').value }), (r) => 'YARA file ' + r.file + ' validated and loaded (' + r.rules + ' rules active).'); });

// ---------- users & audit (admins) ----------
function passwordPrompt(title, onSubmit) {
  const pw = el('input', { type: 'password', placeholder: 'new temporary password (12+ characters)', autocomplete: 'new-password' });
  const out = el('div');
  const force = el('input', { type: 'checkbox', checked: true });
  const close = modal(title, pw, el('label', { class: 'check' }, force, 'They must change it at next sign-in'),
    el('div', { class: 'row' }, el('button', { class: 'primary', onclick: async () => {
      try { await onSubmit(pw.value, force.checked); close(); } catch (e) { show(out, msg('err', e.message)); }
    } }, 'Set password')), out);
}

async function loadUsers() {
  const out = $('users-out');
  try {
    const users = await api('/api/users');
    const master = state.user.is_master;
    $('nu-role').querySelector('option[value=admin]').hidden = !master;
    const act = (fn) => async () => { try { await fn(); await loadUsers(); loadAudit(); } catch (e) { show($('users-msg'), msg('err', e.message)); } };
    show(out, table(['User', 'Role', 'Status', 'Last sign-in', 'Actions'], users.map((u) => {
      const self = u.id === state.user.id, locked = u.locked;
      const roleCell = u.is_master ? el('span', { class: 'role-master' }, 'master (admin)')
        : el('select', { disabled: self || (!master && u.role === 'admin'), onchange: (e) => act(() => api('/api/users/' + encodeURIComponent(u.username), { method: 'PATCH', json: { role: e.target.value } }))() },
          ['viewer', 'analyst', 'admin'].filter((r) => master || r !== 'admin' || u.role === 'admin').map((r) => el('option', { value: r, selected: r === u.role }, r)));
      const actions = u.is_master && !self ? [] : [
        !self && !u.is_master ? el('button', { class: 'btn-sm', onclick: act(() => api('/api/users/' + encodeURIComponent(u.username), { method: 'PATCH', json: { active: !u.active } })) }, u.active ? 'Disable' : 'Enable') : null,
        el('button', { class: 'btn-sm', onclick: () => passwordPrompt('Reset password for ' + u.username, async (pw, force) => { await api('/api/users/' + encodeURIComponent(u.username), { method: 'PATCH', json: { password: pw, must_change: force } }); loadAudit(); }) }, 'Reset password'),
        locked ? el('button', { class: 'btn-sm', onclick: act(() => api('/api/users/' + encodeURIComponent(u.username), { method: 'PATCH', json: { unlock: true } })) }, 'Unlock') : null,
        !self && !u.is_master ? el('button', { class: 'btn-sm btn-danger', onclick: () => { if (window.confirm('Delete ' + u.username + '? This cannot be undone.')) act(() => api('/api/users/' + encodeURIComponent(u.username), { method: 'DELETE' }))(); } }, 'Delete') : null];
      return { cells: [visible(u.username) + (self ? ' (you)' : ''), roleCell, (u.active ? 'active' : 'disabled') + (locked ? ', LOCKED' : '') + (u.must_change_password ? ', must change password' : ''), fmtTime(u.last_login) || 'never', el('div', { class: 'row' }, actions)] };
    })));
  } catch (e) { show(out, msg('err', e.message)); }
}
$('user-create-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/users', { method: 'POST', json: { username: $('nu-name').value.trim(), password: $('nu-pass').value, role: $('nu-role').value, must_change: $('nu-force').checked } });
    $('nu-name').value = ''; $('nu-pass').value = '';
    show($('users-msg'), msg('ok', 'Account created. Give them the username and temporary password through a secure channel.'));
    loadUsers(); loadAudit();
  } catch (err) { show($('users-msg'), msg('err', err.message)); }
});
async function loadAudit() {
  try {
    const rows = await api('/api/audit?limit=100');
    show($('audit-out'), table(['When', 'Who', 'Action', 'Detail', 'From'], rows.map((r) => ({ cells: [fmtTime(r.ts), r.actor || '-', r.action, visible(r.detail || '').slice(0, 90), r.ip || ''] }))));
  } catch (e) { show($('audit-out'), msg('err', e.message)); }
}

// ---------- boot ----------
(async function init() {
  try {
    const st = await api('/api/auth/status', { quiet401: true });
    if (st.authenticated) {
      state.user = st.user; state.csrf = st.csrf;
      if (st.user.must_change_password) showForcedChange(); else await bootApp();
    } else await showLogin();
  } catch (_) { await showLogin('Cannot reach the Tollgate API.'); }
})();

window.tollgate = { scanFile, checkUrl, openTab, state };   // handy for automated UI tests
