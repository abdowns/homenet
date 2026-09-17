'use strict';

async function apiGet(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}
async function apiPost(path, data) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${path}: ${res.status}`);
  return body;
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
    document.getElementById('summary').textContent = 'labnetd unreachable';
  }
}

async function loadServices() {
  const { services } = await apiGet('/api/services');
  const tbody = document.querySelector('#services-table tbody');
  tbody.innerHTML = '';
  for (const s of services || []) {
    const downBtn = el('button', { text: 'down' });
    downBtn.addEventListener('click', async () => {
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

function bindForm(id, path, describe) {
  const form = document.getElementById(id);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const out = form.querySelector('.result');
    const data = Object.fromEntries(new FormData(form).entries());
    try {
      const resp = await apiPost(path, data);
      out.className = 'result ok';
      out.textContent = describe(resp);
      form.reset();
      loadServices();
    } catch (e) {
      out.className = 'result error';
      out.textContent = e.message;
    }
  });
}
bindForm('expose-form', '/api/expose', svc => `${svc.name} -> https://${svc.host} -> ${svc.target}`);
bindForm('up-form', '/api/up', resp => `up at https://${resp.host}`);

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

let liveRows = [];
document.getElementById('live-toggle').addEventListener('change', () => { liveRows = []; });

function connectEvents() {
  const src = new EventSource('/api/events');
  for (const type of ['dns', 'http', 'auth']) {
    src.addEventListener(type, (ev) => {
      if (!document.getElementById('live-toggle').checked) return;
      liveRows.unshift(JSON.parse(ev.data));
      if (liveRows.length > 100) liveRows.length = 100;
      renderRows(document.getElementById('query-results'), liveRows);
    });
  }
}

refreshSummary();
loadServices();
connectEvents();
setInterval(refreshSummary, 10000);
