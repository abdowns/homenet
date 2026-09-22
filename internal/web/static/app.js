'use strict';

async function api(path, opts) {
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${path}: ${res.status}`);
  return body;
}
function apiGet(path) { return api(path); }
function apiPost(path, data) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data || {}) });
}

function fmtTime(ms) {
  return new Date(Number(ms)).toLocaleString();
}
function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'text') e.textContent = v; else e.setAttribute(k, v);
  }
  for (const c of children) if (c != null) e.append(c);
  return e;
}

for (const btn of document.querySelectorAll('.tab-btn')) {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-' + btn.dataset.tab));
  });
}

async function refreshSummary() {
  try {
    const st = await apiGet('/api/status');
    const rings = Object.entries(st.rings || {}).map(([k, v]) => `${k}: ${v.len}`).join('  ·  ');
    document.getElementById('summary').textContent = `zone ${st.zone}  ·  up ${st.uptime}  ·  ${rings}`;
  } catch (e) {
    document.getElementById('summary').textContent = 'labnetd unreachable: ' + e.message;
  }
}

async function loadServices() {
  const { services } = await apiGet('/api/services');
  const tbody = document.querySelector('#services-table tbody');
  tbody.innerHTML = '';
  for (const s of services || []) {
    const downBtn = el('button', { class: 'danger', text: 'down' });
    downBtn.addEventListener('click', async () => {
      if (!confirm(`Take down "${s.name}"?`)) return;
      await apiPost('/api/down', { name: s.name });
      loadServices();
    });
    tbody.append(el('tr', {},
      el('td', { text: s.name }),
      el('td', {}, el('code', { text: s.host })),
      el('td', { text: s.target }),
      el('td', {}, downBtn),
    ));
  }
}

document.getElementById('expose-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target, out = form.querySelector('.result');
  const data = Object.fromEntries(new FormData(form).entries());
  try {
    const svc = await apiPost('/api/expose', data);
    out.className = 'result ok';
    out.textContent = `${svc.name} -> https://${svc.host} -> ${svc.target}`;
    form.reset();
    loadServices();
  } catch (e) {
    out.className = 'result error';
    out.textContent = e.message;
  }
});

document.getElementById('up-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target, out = form.querySelector('.result');
  const data = Object.fromEntries(new FormData(form).entries());
  out.className = 'result';
  out.textContent = 'building…';
  try {
    const resp = await apiPost('/api/up', data);
    out.className = 'result ok';
    out.textContent = `up at https://${resp.host}`;
    form.reset();
    loadServices();
  } catch (e) {
    out.className = 'result error';
    out.textContent = e.message;
  }
});

async function loadDevices() {
  const { devices } = await apiGet('/api/devices');
  const tbody = document.querySelector('#devices-table tbody');
  tbody.innerHTML = '';
  for (const d of devices || []) {
    tbody.append(el('tr', {},
      el('td', { text: d.name }),
      el('td', { text: new Date(d.paired_at).toLocaleString() }),
    ));
  }
}

document.getElementById('pair-code-btn').addEventListener('click', async () => {
  const out = document.getElementById('pair-code-result');
  try {
    const { code, expires_at } = await apiPost('/api/devices/pair-code', {});
    out.innerHTML = '';
    out.append(
      el('div', { class: 'pair-code', text: code }),
      el('div', { class: 'muted', text: `valid until ${new Date(expires_at).toLocaleTimeString()}` }),
      el('div', { class: 'muted' }, 'on the new device: ', el('code', { text: `labnet pair ${code}` }),
        ', or open the pairing page on any *.lab address (e.g. http://<this host>:8000/_labnet/pair)'),
    );
  } catch (e) {
    out.textContent = e.message;
  }
});

function renderRows(container, rows) {
  container.innerHTML = '';
  if (!rows || rows.length === 0) {
    container.append(el('p', { class: 'muted', text: 'no rows' }));
    return;
  }
  const cols = Object.keys(rows[0]);
  const table = el('table', {},
    el('thead', {}, el('tr', {}, ...cols.map(c => el('th', { text: c })))),
    el('tbody', {}),
  );
  const tbody = table.querySelector('tbody');
  for (const row of rows) {
    tbody.append(el('tr', {}, ...cols.map(c => el('td', { text: String(row[c]) }))));
  }
  container.append(table);
}

document.getElementById('query-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target;
  const schemaName = form.schema.value;
  const predicate = form.predicate.value || 'true';
  const limit = parseInt(form.limit.value, 10) || 0;
  const statsEl = document.getElementById('query-stats');
  const resultsEl = document.getElementById('query-results');
  statsEl.textContent = 'running…';
  try {
    const resp = await apiPost('/api/query', { schema: schemaName, predicate, limit });
    statsEl.textContent = `compiled in ${resp.compile_ms.toFixed(2)}ms, scanned ${resp.scanned} in ${resp.scan_ms.toFixed(3)}ms, ${resp.matched} matched`;
    renderRows(resultsEl, resp.rows);
  } catch (e) {
    statsEl.textContent = '';
    resultsEl.innerHTML = '';
    resultsEl.append(el('p', { class: 'result error', text: e.message }));
  }
});

// live feed is separate from the ad-hoc query results above, capped at 200 rows
const liveEventTypeBySchema = { DnsQuery: 'dns', HttpRequest: 'http', AuthEvent: 'auth' };
let liveRows = [];
function renderLiveIfOn() {
  if (!document.getElementById('live-toggle').checked) return;
  renderRows(document.getElementById('query-results'), liveRows);
  document.getElementById('query-stats').textContent = `${liveRows.length} live event(s) (schema: ${document.querySelector('#query-form [name=schema]').value})`;
}
document.getElementById('live-toggle').addEventListener('change', () => { liveRows = []; renderLiveIfOn(); });
document.querySelector('#query-form [name=schema]').addEventListener('change', () => { liveRows = []; renderLiveIfOn(); });

function renderRules(container, rules) {
  container.innerHTML = '';
  for (const cat of ['deny_', 'allow_', 'public_', 'block_', 'alert_']) {
    const names = (rules || {})[cat] || [];
    if (names.length === 0) continue;
    container.append(el('div', { class: 'rule-line' }, el('span', { class: 'rule-tag', text: cat }), names.join(', ')));
  }
}

async function loadPolicy() {
  const st = await apiGet('/api/policy/status');
  document.getElementById('policy-source').value = st.source || '';
}

document.getElementById('policy-check-btn').addEventListener('click', async () => {
  const out = document.getElementById('policy-result');
  const source = document.getElementById('policy-source').value;
  try {
    const resp = await apiPost('/api/policy/check', { source });
    if (resp.ok) {
      out.className = 'ok';
      out.innerHTML = '<b>compiles ✓</b>';
      renderRules(out, resp.rules);
    } else {
      out.className = 'error';
      out.textContent = resp.error;
    }
  } catch (e) {
    out.className = 'error';
    out.textContent = e.message;
  }
});

document.getElementById('policy-test-btn').addEventListener('click', async () => {
  const out = document.getElementById('policy-result');
  const source = document.getElementById('policy-source').value;
  try {
    const resp = await apiPost('/api/policy/test', { source });
    if (!resp.ok) { out.className = 'error'; out.textContent = resp.error; return; }
    out.className = '';
    out.innerHTML = '';
    const httpLine = el('p', { text: `HTTP: would deny ${resp.http.matched || 0} of ${resp.http.total || 0} requests in the journal` });
    const dnsLine = el('p', { text: `DNS: would block ${resp.dns.matched || 0} of ${resp.dns.total || 0} queries in the journal` });
    out.append(httpLine, dnsLine);
    for (const [rule, n] of Object.entries(resp.http.by_rule || {})) out.append(el('div', { class: 'rule-line' }, `  ${rule}: ${n}`));
    for (const [rule, n] of Object.entries(resp.dns.by_rule || {})) out.append(el('div', { class: 'rule-line' }, `  ${rule}: ${n}`));
  } catch (e) {
    out.className = 'error';
    out.textContent = e.message;
  }
});

document.getElementById('policy-apply-btn').addEventListener('click', async () => {
  const out = document.getElementById('policy-result');
  const source = document.getElementById('policy-source').value;
  if (!confirm('Apply this policy now? It takes effect immediately.')) return;
  try {
    const resp = await apiPost('/api/policy/apply', { source });
    if (resp.ok) {
      out.className = 'ok';
      out.innerHTML = '<b>applied ✓</b>';
      renderRules(out, resp.rules);
    } else {
      out.className = 'error';
      out.textContent = resp.error;
    }
  } catch (e) {
    out.className = 'error';
    out.textContent = e.message;
  }
});

function alertRow(a) {
  return el('div', { class: 'rule-line event-row new' },
    `[${fmtTime(a.ts)}] `, el('b', { text: a.rule }), ` (${a.schema}): ${a.summary}`);
}

async function loadAlerts() {
  const { alerts } = await apiGet('/api/alerts');
  const list = document.getElementById('alerts-list');
  list.innerHTML = '';
  for (const a of (alerts || []).slice().reverse()) list.append(alertRow(a));
}

function connectEvents() {
  const src = new EventSource('/api/events');
  const wire = (type, handle) => src.addEventListener(type, (ev) => handle(JSON.parse(ev.data)));

  for (const [schemaName, evType] of Object.entries(liveEventTypeBySchema)) {
    wire(evType, (data) => {
      if (document.querySelector('#query-form [name=schema]').value !== schemaName) return;
      liveRows.unshift(data);
      if (liveRows.length > 200) liveRows.length = 200;
      renderLiveIfOn();
    });
  }
  wire('alert', (data) => {
    document.getElementById('alerts-list').prepend(alertRow(data));
  });
  src.onerror = () => { /* eventsource auto reconnects */ };
}

refreshSummary();
loadServices();
loadDevices();
loadPolicy();
loadAlerts();
connectEvents();
setInterval(refreshSummary, 10000);
