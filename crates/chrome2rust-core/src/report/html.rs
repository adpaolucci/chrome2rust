use crate::error::ChromeError;
use crate::forensics::UserDataReport;

/// Generates a completely self-contained, offline-capable interactive HTML forensic report.
/// All CSS, SVG chart generation, sorting, filtering, pagination, and modal inspection run
/// locally in the browser with zero external network dependencies.
pub fn render_html_report(report: &UserDataReport) -> Result<String, ChromeError> {
    let raw_json = serde_json::to_string(report).map_err(|e| ChromeError::Export(e.to_string()))?;
    // Escape sequences that could close </script> prematurely or trigger JS parser issues
    let safe_json = raw_json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");

    let html = HTML_TEMPLATE.replace("__REPORT_JSON__", &safe_json);
    Ok(html)
}

const HTML_TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>chrome2rust Forensic Report</title>
<style>
:root {
  --bg: #0b1120;
  --surface: #111827;
  --surface-2: #1e293b;
  --border: #334155;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --accent-dim: rgba(56, 189, 248, 0.14);
  --crit: #ef4444;
  --high: #f97316;
  --med: #eab308;
  --low: #22c55e;
  --info: #38bdf8;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
body.light {
  --bg: #f8fafc;
  --surface: #ffffff;
  --surface-2: #f1f5f9;
  --border: #cbd5e1;
  --text: #0f172a;
  --muted: #475569;
  --accent: #0284c7;
  --accent-dim: rgba(2, 132, 199, 0.12);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  font-size: 13px;
  line-height: 1.45;
}
header.topbar {
  position: sticky;
  top: 0;
  z-index: 20;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 20px;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}
.brand {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.brand h1 {
  margin: 0;
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.2px;
}
.brand .meta {
  color: var(--muted);
  font-size: 11px;
  font-family: var(--mono);
}
.controls {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
input, select, button {
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 10px;
  font-size: 12px;
}
input:focus, select:focus {
  outline: 1px solid var(--accent);
}
button {
  cursor: pointer;
  font-weight: 600;
}
button:hover {
  border-color: var(--accent);
}
button.primary {
  background: var(--accent);
  color: #082f49;
  border-color: var(--accent);
}
nav.tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  padding: 8px 20px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
nav.tabs button {
  background: transparent;
  border: 1px solid transparent;
  color: var(--muted);
  padding: 7px 12px;
  border-radius: 6px;
}
nav.tabs button.active {
  background: var(--accent-dim);
  color: var(--accent);
  border-color: rgba(56, 189, 248, 0.35);
}
main {
  padding: 18px 20px 60px;
  max-width: 1600px;
  margin: 0 auto;
}
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(175px, 1fr));
  gap: 10px;
  margin-bottom: 18px;
}
.kpi {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
}
.kpi .label {
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.4px;
}
.kpi .val {
  font-size: 20px;
  font-weight: 700;
  margin-top: 4px;
}
.kpi .sub {
  font-size: 11px;
  color: var(--muted);
  margin-top: 2px;
}
.panel-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  margin-bottom: 14px;
}
.card h2, .card h3 {
  margin: 0 0 10px 0;
  font-size: 14px;
}
.badge {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.sev-critical { background: rgba(239,68,68,.2); color: #fca5a5; border: 1px solid rgba(239,68,68,.4); }
.sev-high { background: rgba(249,115,22,.2); color: #fdba74; border: 1px solid rgba(249,115,22,.4); }
.sev-medium { background: rgba(234,179,8,.2); color: #fde047; border: 1px solid rgba(234,179,8,.4); }
.sev-low { background: rgba(34,197,94,.2); color: #86efac; border: 1px solid rgba(34,197,94,.4); }
.sev-info { background: rgba(56,189,248,.18); color: #7dd3fc; border: 1px solid rgba(56,189,248,.35); }
body.light .sev-critical { color: #991b1b; }
body.light .sev-high { color: #9a3412; }
body.light .sev-medium { color: #854d0e; }
body.light .sev-low { color: #166534; }
body.light .sev-info { color: #075985; }
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
th, td {
  padding: 7px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
th {
  background: var(--surface-2);
  font-weight: 600;
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  position: sticky;
  top: 0;
}
th:hover { color: var(--accent); }
tr:hover td { background: var(--accent-dim); }
.mono { font-family: var(--mono); font-size: 11.5px; }
.break-all { word-break: break-all; max-width: 440px; }
.pager {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 2px;
  color: var(--muted);
  font-size: 12px;
}
.subbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
}
.finding-card {
  border: 1px solid var(--border);
  background: var(--surface);
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 10px;
}
.finding-evidence {
  margin: 8px 0 0 0;
  padding-left: 18px;
  font-family: var(--mono);
  font-size: 11.5px;
  color: var(--muted);
}
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(2, 6, 23, 0.72);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 50;
  padding: 20px;
}
.modal-backdrop.open { display: flex; }
.modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  max-width: 900px;
  width: 100%;
  max-height: 85vh;
  overflow: auto;
  padding: 18px 20px;
}
pre.codebox {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: 11.5px;
  white-space: pre-wrap;
  word-break: break-word;
}
.empty { color: var(--muted); padding: 18px; text-align: center; }
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <h1>chrome2rust Forensic Report</h1>
    <div class="meta" id="headerMeta">Loading report...</div>
  </div>
  <div class="controls">
    <select id="profileFilter" title="Filter by Chrome Profile"></select>
    <input id="globalSearch" type="search" placeholder="Search URLs, hosts, emails, keys..." style="min-width:240px;">
    <button id="themeToggle" type="button">Light / Dark</button>
    <button id="exportCsvBtn" type="button" class="primary">Export Tab CSV</button>
  </div>
</header>

<nav class="tabs" id="tabBar"></nav>
<main id="content"></main>

<div class="modal-backdrop" id="detailModal">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <h3 id="modalTitle" style="margin:0;">Entry Details</h3>
      <button id="modalClose" type="button">Close</button>
    </div>
    <div id="modalBody"></div>
  </div>
</div>

<script id="report-data" type="application/json">__REPORT_JSON__</script>
<script>
(function() {
  const DATA = JSON.parse(document.getElementById('report-data').textContent);
  const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'findings', label: 'Findings' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'cache', label: 'Cache Entries' },
    { id: 'history', label: 'History & Downloads' },
    { id: 'credentials', label: 'Cookies, Logins & Autofill' },
    { id: 'extensions', label: 'Extensions & Bookmarks' },
    { id: 'sessions', label: 'Sessions & Storage' },
    { id: 'inventory', label: 'Inventory & Warnings' },
  ];

  const state = {
    activeTab: 'overview',
    profile: '__ALL__',
    search: '',
    findingSeverity: 'all',
    timelineCategory: 'all',
    cacheCtFilter: '',
    historySub: 'urls',
    credSub: 'logins',
    sessSub: 'tabs',
    pageSize: 100,
    page: 0,
    sortCol: null,
    sortDesc: true,
    lastTableRows: [],
    lastTableHeaders: [],
  };

  function esc(v) {
    if (v === null || v === undefined) return '';
    return String(v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fmtBytes(n) {
    const b = Number(n || 0);
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GiB';
    if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MiB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KiB';
    return b + ' B';
  }

  function fmtDate(s) {
    if (!s) return '';
    return String(s).replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  }

  function activeProfiles() {
    if (state.profile === '__ALL__') return DATA.profiles || [];
    return (DATA.profiles || []).filter(p => p.profile_name === state.profile);
  }

  function matchesSearch(haystackParts) {
    const q = state.search.trim().toLowerCase();
    if (!q) return true;
    for (const part of haystackParts) {
      if (part && String(part).toLowerCase().includes(q)) return true;
    }
    return false;
  }

  function openModal(title, html) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('detailModal').classList.add('open');
  }
  document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('detailModal').classList.remove('open');
  });
  document.getElementById('detailModal').addEventListener('click', (e) => {
    if (e.target.id === 'detailModal') e.currentTarget.classList.remove('open');
  });

  // Init Header & Selectors
  const ver = DATA.local_state?.chrome_version ? `Chrome ${DATA.local_state.chrome_version}` : 'Chrome version unknown';
  document.getElementById('headerMeta').textContent =
    `${DATA.target_path} | ${ver} | Generated ${fmtDate(DATA.generated_at)}`;

  const pfSel = document.getElementById('profileFilter');
  pfSel.innerHTML = '<option value="__ALL__">All Profiles (' + (DATA.profiles?.length || 0) + ')</option>' +
    (DATA.profiles || []).map(p => `<option value="${esc(p.profile_name)}">${esc(p.profile_name)}</option>`).join('');
  pfSel.addEventListener('change', (e) => { state.profile = e.target.value; state.page = 0; render(); });

  document.getElementById('globalSearch').addEventListener('input', (e) => {
    state.search = e.target.value;
    state.page = 0;
    render();
  });

  document.getElementById('themeToggle').addEventListener('click', () => {
    document.body.classList.toggle('light');
  });

  document.getElementById('exportCsvBtn').addEventListener('click', () => {
    if (!state.lastTableHeaders.length) return;
    const csvCell = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const lines = [state.lastTableHeaders.map(csvCell).join(',')];
    for (const r of state.lastTableRows) {
      lines.push(r.map(csvCell).join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `chrome2rust_${state.activeTab}.csv`;
    a.click();
  });

  function renderTabs() {
    const bar = document.getElementById('tabBar');
    bar.innerHTML = TABS.map(t =>
      `<button type="button" class="${state.activeTab === t.id ? 'active' : ''}" data-tab="${t.id}">${esc(t.label)}</button>`
    ).join('');
    bar.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', () => {
        state.activeTab = btn.dataset.tab;
        state.page = 0;
        state.sortCol = null;
        render();
      });
    });
  }

  function renderSortableTable(headers, rawRows, opts = {}) {
    state.lastTableHeaders = headers;
    state.lastTableRows = rawRows;

    const indexed = rawRows.map((cells, idx) => ({ cells, idx }));
    if (state.sortCol !== null && state.sortCol < headers.length) {
      const col = state.sortCol;
      const mult = state.sortDesc ? -1 : 1;
      indexed.sort((a, b) => {
        const av = a.cells[col] ?? '';
        const bv = b.cells[col] ?? '';
        const an = Number(av), bn = Number(bv);
        if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== '' && bv !== '') {
          return (an - bn) * mult;
        }
        return String(av).localeCompare(String(bv)) * mult;
      });
    }

    const total = indexed.length;
    const pages = Math.max(1, Math.ceil(total / state.pageSize));
    if (state.page >= pages) state.page = pages - 1;
    const slice = indexed.slice(state.page * state.pageSize, (state.page + 1) * state.pageSize);

    let html = '<div class="pager">' +
      `<span>Showing ${slice.length} of ${total} rows (Page ${state.page + 1}/${pages})</span>` +
      '<div style="display:flex;gap:6px;align-items:center;">' +
      `<button type="button" id="pgPrev" ${state.page <= 0 ? 'disabled' : ''}>Prev</button>` +
      `<button type="button" id="pgNext" ${state.page + 1 >= pages ? 'disabled' : ''}>Next</button>` +
      '</div></div>';

    html += '<div class="table-wrap"><table><thead><tr>';
    headers.forEach((h, i) => {
      const arrow = state.sortCol === i ? (state.sortDesc ? ' ▼' : ' ▲') : '';
      html += `<th data-col="${i}">${esc(h)}${arrow}</th>`;
    });
    html += '</tr></thead><tbody>';

    if (!slice.length) {
      html += `<tr><td colspan="${headers.length}" class="empty">No matching records</td></tr>`;
    } else {
      for (const item of slice) {
        const clickable = opts.onRowClick ? 'style="cursor:pointer;" data-ridx="' + item.idx + '"' : '';
        html += `<tr ${clickable}>`;
        item.cells.forEach((c, ci) => {
          const cls = opts.monoCols?.includes(ci) ? 'mono ' : '';
          const brk = opts.breakCols?.includes(ci) ? 'break-all ' : '';
          html += `<td class="${cls}${brk}">${esc(c)}</td>`;
        });
        html += '</tr>';
      }
    }
    html += '</tbody></table></div>';
    return { html, bind: (container) => {
      container.querySelectorAll('th[data-col]').forEach(th => {
        th.addEventListener('click', () => {
          const c = Number(th.dataset.col);
          if (state.sortCol === c) state.sortDesc = !state.sortDesc;
          else { state.sortCol = c; state.sortDesc = true; }
          render();
        });
      });
      const prev = container.querySelector('#pgPrev');
      const next = container.querySelector('#pgNext');
      if (prev) prev.addEventListener('click', () => { state.page--; render(); });
      if (next) next.addEventListener('click', () => { state.page++; render(); });
      if (opts.onRowClick) {
        container.querySelectorAll('tr[data-ridx]').forEach(tr => {
          tr.addEventListener('click', () => opts.onRowClick(Number(tr.dataset.ridx)));
        });
      }
    }};
  }

  function svgBarChart(entries, title) {
    if (!entries.length) return `<div class="empty">No ${esc(title)} data</div>`;
    const top = entries.slice(0, 10);
    const maxVal = Math.max(1, ...top.map(e => e[1]));
    const rowH = 26;
    const h = top.length * rowH + 12;
    let bars = '';
    top.forEach(([label, val], idx) => {
      const y = idx * rowH + 6;
      const w = Math.max(4, Math.round((val / maxVal) * 260));
      bars += `<text x="0" y="${y + 14}" fill="currentColor" font-size="11">${esc(String(label).slice(0, 22))}</text>`;
      bars += `<rect x="145" y="${y + 3}" width="${w}" height="15" rx="3" fill="#38bdf8" opacity="0.85"></rect>`;
      bars += `<text x="${152 + w}" y="${y + 14}" fill="#94a3b8" font-size="11">${val}</text>`;
    });
    return `<svg viewBox="0 0 470 ${h}" style="width:100%;height:${h}px;">${bars}</svg>`;
  }

  function renderOverview(el) {
    state.lastTableHeaders = [];
    const s = DATA.summary || {};
    const ls = DATA.local_state || {};
    const profs = activeProfiles();

    const kpis = [
      ['Profiles', s.profile_count, 'Chrome profiles parsed'],
      ['Cache Entries', s.total_cache_entries, fmtBytes(s.total_cache_bytes)],
      ['History URLs / Visits', `${s.total_history_urls} / ${s.total_history_visits}`, 'SQLite History'],
      ['Downloads', s.total_downloads, 'History/downloads'],
      ['Cookies', s.total_cookies, 'Network/Cookies'],
      ['Saved Logins', s.total_logins, 'Login Data'],
      ['Autofill & Addresses', s.total_autofill_entries, 'Web Data'],
      ['Bookmarks', s.total_bookmarks, 'Bookmarks JSON'],
      ['Extensions', s.total_extensions, 'Manifests & Prefs'],
      ['Session Tabs', `${s.total_open_tabs} / ${s.total_closed_tabs}`, 'Open / Closed SNSS'],
      ['Storage Keys', s.total_local_storage_keys, 'LevelDB WAL & LDB'],
      ['Findings', s.total_findings, 'Forensic intelligence'],
    ];

    let html = '<div class="kpi-grid">' + kpis.map(([l, v, sub]) =>
      `<div class="kpi"><div class="label">${esc(l)}</div><div class="val">${esc(v)}</div><div class="sub">${esc(sub)}</div></div>`
    ).join('') + '</div>';

    const ctPairs = Object.entries(s.cache_content_type_breakdown || {}).sort((a, b) => b[1] - a[1]);
    const dayCounts = {};
    for (const ev of (DATA.timeline || [])) {
      const day = String(ev.timestamp || '').slice(0, 10);
      if (day) dayCounts[day] = (dayCounts[day] || 0) + 1;
    }
    const dayPairs = Object.entries(dayCounts).sort((a, b) => b[0].localeCompare(a[0]));

    html += '<div class="panel-grid">' +
      `<div class="card"><h3>Cache Content-Type Categories</h3>${svgBarChart(ctPairs, 'cache content type')}</div>` +
      `<div class="card"><h3>Timeline Activity by Date (UTC)</h3>${svgBarChart(dayPairs, 'timeline date')}</div>` +
    '</div>';

    html += '<div class="panel-grid">';
    html += '<div class="card"><h3>Local State & Encryption Metadata</h3>' +
      '<div class="mono" style="display:grid;gap:4px;">' +
      `<div>Chrome Version: ${esc(ls.chrome_version || 'Unknown')}</div>` +
      `<div>OS Crypt Key Present: ${ls.os_crypt_encrypted_key_present ? 'Yes' : 'No'} (${esc(ls.os_crypt_key_prefix || '-')})</div>` +
      `<div>Portal Info: ${esc(ls.os_crypt_portal_info || '-')}</div>` +
      `<div>Last Active Profiles: ${esc((ls.last_active_profiles || []).join(', ') || '-')}</div>` +
      `<div>Country / Policies: ${esc(ls.variations_country || '-')} / ${ls.policy_count || 0}</div>` +
      '</div></div>';

    html += '<div class="card"><h3>Selected Profile Summary</h3>' +
      profs.map(p =>
        `<div style="border-top:1px solid var(--border);padding:8px 0;">` +
        `<strong>${esc(p.profile_name)}</strong> <span class="mono" style="color:var(--muted);">(${fmtBytes(p.total_profile_bytes)})</span>` +
        `<div style="font-size:12px;color:var(--muted);">Accounts: ${esc((p.preferences?.account_emails || []).join(', ') || 'None')} | Default Search: ${esc(p.preferences?.default_search_name || '-')} | SafeBrowsing: ${String(p.preferences?.safebrowsing_enabled ?? '-')}</div>` +
        `</div>`
      ).join('') +
      '</div></div>';

    // Top domains table
    const domRows = (DATA.top_domains || [])
      .filter(d => matchesSearch([d.domain]))
      .slice(0, 100)
      .map(d => [d.domain, d.history_visits, d.cache_items, fmtBytes(d.cache_bytes), d.cookies]);
    html += '<div class="card"><h3>Top Domains</h3><div id="topDomTbl"></div></div>';
    el.innerHTML = html;
    const tbl = renderSortableTable(['Domain', 'History Visits', 'Cache Items', 'Cache Size', 'Cookies'], domRows, { monoCols: [0] });
    const container = el.querySelector('#topDomTbl');
    container.innerHTML = tbl.html;
    tbl.bind(container);
  }

  function renderFindings(el) {
    state.lastTableHeaders = [];
    const sevs = ['all', 'critical', 'high', 'medium', 'low', 'info'];
    const filtered = (DATA.findings || []).filter(f => {
      if (state.profile !== '__ALL__' && f.profile !== state.profile) return false;
      if (state.findingSeverity !== 'all' && f.severity !== state.findingSeverity) return false;
      return matchesSearch([f.title, f.summary, f.category, f.profile, ...(f.evidence || [])]);
    });

    let html = '<div class="subbar">' +
      sevs.map(sv => `<button type="button" data-sev="${sv}" class="${state.findingSeverity === sv ? 'primary' : ''}">${sv.toUpperCase()}</button>`).join('') +
      `<span style="color:var(--muted);margin-left:8px;">${filtered.length} findings</span></div>`;

    if (!filtered.length) {
      html += '<div class="card empty">No findings match the current filter.</div>';
    } else {
      for (const f of filtered) {
        html += `<div class="finding-card">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span>
            <strong>${esc(f.title)}</strong>
            <span class="mono" style="color:var(--muted);">[${esc(f.profile)} / ${esc(f.category)}]</span>
          </div>
          <div style="margin-top:6px;">${esc(f.summary)}</div>
          ${f.evidence?.length ? '<ul class="finding-evidence">' + f.evidence.map(e => `<li>${esc(e)}</li>`).join('') + '</ul>' : ''}
        </div>`;
      }
    }
    el.innerHTML = html;
    el.querySelectorAll('button[data-sev]').forEach(b => {
      b.addEventListener('click', () => { state.findingSeverity = b.dataset.sev; render(); });
    });
  }

  function renderTimeline(el) {
    const cats = ['all', 'History', 'Download', 'Cache', 'Cookie', 'Credential', 'Bookmark', 'Extension', 'Session'];
    const events = (DATA.timeline || []).filter(ev => {
      if (state.profile !== '__ALL__' && ev.profile !== state.profile) return false;
      if (state.timelineCategory !== 'all' && ev.category !== state.timelineCategory) return false;
      return matchesSearch([ev.category, ev.event_type, ev.target, ev.details, ev.source_artifact]);
    });

    const rows = events.map(ev => [
      fmtDate(ev.timestamp), ev.profile, ev.category, ev.event_type, ev.target, ev.details, ev.source_artifact
    ]);
    el.innerHTML = '<div class="subbar">' +
      cats.map(c => `<button type="button" data-cat="${c}" class="${state.timelineCategory === c ? 'primary' : ''}">${c}</button>`).join('') +
      '</div><div id="tlTbl"></div>';

    el.querySelectorAll('button[data-cat]').forEach(b => {
      b.addEventListener('click', () => { state.timelineCategory = b.dataset.cat; state.page = 0; render(); });
    });
    const tbl = renderSortableTable(
      ['Timestamp (UTC)', 'Profile', 'Category', 'Event Type', 'Target', 'Details', 'Artifact'],
      rows,
      { monoCols: [0, 6], breakCols: [4, 5] }
    );
    const tc = el.querySelector('#tlTbl');
    tc.innerHTML = tbl.html;
    tc.querySelectorAll('button');
    tbl.bind(tc);
  }

  function renderCache(el) {
    const all = [];
    for (const p of activeProfiles()) {
      for (const c of (p.cache_entries || [])) {
        all.push({ profile: p.profile_name, entry: c });
      }
    }
    const ctSet = Array.from(new Set(all.map(x => x.entry.content_type).filter(Boolean))).sort();
    const filtered = all.filter(x => {
      const c = x.entry;
      if (state.cacheCtFilter && c.content_type !== state.cacheCtFilter) return false;
      return matchesSearch([c.url, c.content_type, c.server_name, c.partition_website, c.cache_name, c.server_ip, c.payload_sha256]);
    });

    const rows = filtered.map(x => {
      const c = x.entry;
      return [
        c.url,
        c.content_type || '',
        c.file_size,
        c.compressed_size,
        fmtDate(c.last_accessed),
        fmtDate(c.server_time),
        fmtDate(c.expiration_time),
        c.server_name || '',
        c.server_response || '',
        c.content_encoding || '',
        c.partition_website || '',
        c.server_ip ? (c.server_port ? `${c.server_ip}:${c.server_port}` : c.server_ip) : '',
        c.deleted_file ? 'Yes' : 'No',
        c.cache_name,
        c.backend,
      ];
    });

    el.innerHTML = '<div class="subbar">' +
      '<select id="ctSel"><option value="">All Content-Types (' + ctSet.length + ')</option>' +
      ctSet.map(ct => `<option value="${esc(ct)}" ${state.cacheCtFilter === ct ? 'selected' : ''}>${esc(ct)}</option>`).join('') +
      '</select><span style="color:var(--muted);">Click any row to inspect HTTP headers, TLS & certificate details</span></div><div id="cacheTbl"></div>';

    el.querySelector('#ctSel').addEventListener('change', (e) => {
      state.cacheCtFilter = e.target.value; state.page = 0; render();
    });

    const tbl = renderSortableTable(
      ['URL', 'Content Type', 'Size (B)', 'Compressed', 'Last Accessed', 'Server Time', 'Expires', 'Server', 'Response', 'Encoding', 'Web Site', 'Server IP', 'Deleted', 'Cache Name', 'Backend'],
      rows,
      {
        monoCols: [4, 5, 6, 11, 13],
        breakCols: [0, 10],
        onRowClick: (ridx) => {
          const item = filtered[ridx]?.entry;
          if (!item) return;
          const hdrs = (item.headers || []).map(h => `${h.name}: ${h.value}`).join('\n');
          const certs = (item.certificates || []).map(c => `Subject: ${c.subject}\nIssuer: ${c.issuer}\nValidity: ${c.not_before} -> ${c.not_after}`).join('\n---\n');
          openModal(`Cache Entry: ${item.cache_name}`,
            `<div class="mono" style="display:grid;gap:4px;margin-bottom:10px;">
              <div><strong>URL:</strong> ${esc(item.url)}</div>
              <div><strong>Raw Key:</strong> ${esc(item.raw_key)}</div>
              <div><strong>File Size / Compressed:</strong> ${item.file_size} / ${item.compressed_size} bytes</div>
              <div><strong>SHA-256:</strong> ${esc(item.payload_sha256 || 'Not computed')}</div>
              <div><strong>TLS / ALPN:</strong> ${esc(item.tls_version || '-')} / ${esc(item.alpn_protocol || '-')}</div>
              <div><strong>Cache File:</strong> ${esc(item.cache_file_path)}</div>
            </div>
            <h4>HTTP Response Headers (${esc(item.server_response)})</h4>
            <pre class="codebox">${esc(hdrs || '(none)')}</pre>
            ${certs ? `<h4>X.509 Certificates</h4><pre class="codebox">${esc(certs)}</pre>` : ''}`
          );
        }
      }
    );
    const cc = el.querySelector('#cacheTbl');
    cc.innerHTML = tbl.html;
    tbl.bind(cc);
  }

  function renderHistory(el) {
    const profs = activeProfiles();
    const subs = [['urls', 'URLs'], ['visits', 'Visits'], ['downloads', 'Downloads'], ['searches', 'Search Terms']];
    let html = '<div class="subbar">' +
      subs.map(([id, l]) => `<button type="button" data-sub="${id}" class="${state.historySub === id ? 'primary' : ''}">${l}</button>`).join('') +
      '</div>';

    // Deletion indicators
    html += '<div class="panel-grid">' + profs.map(p => {
      const d = p.history?.deletion_indicators || {};
      return `<div class="card"><h3>${esc(p.profile_name)} SQLite Sequence Health</h3>
        <div class="mono">URLs: ${d.urls_row_count || 0} rows | seq=${d.urls_sqlite_seq || 0} | est. deleted gaps=${d.urls_estimated_deleted || 0} | hidden=${d.hidden_urls_count || 0}<br>
        Visits: ${d.visits_row_count || 0} rows | seq=${d.visits_sqlite_seq || 0} | est. deleted gaps=${d.visits_estimated_deleted || 0}</div></div>`;
    }).join('') + '</div><div id="histTbl"></div>';
    el.innerHTML = html;
    el.querySelectorAll('button[data-sub]').forEach(b => {
      b.addEventListener('click', () => { state.historySub = b.dataset.sub; state.page = 0; state.sortCol = null; render(); });
    });

    let headers = [], rows = [];
    if (state.historySub === 'urls') {
      headers = ['Profile', 'Last Visit', 'Visits', 'Typed', 'Hidden', 'Title', 'URL'];
      for (const p of profs) for (const u of (p.history?.urls || [])) {
        if (matchesSearch([u.url, u.title])) rows.push([p.profile_name, fmtDate(u.last_visit_time), u.visit_count, u.typed_count, u.hidden ? 'Yes' : 'No', u.title, u.url]);
      }
    } else if (state.historySub === 'visits') {
      headers = ['Profile', 'Visit Time', 'Transition', 'Qualifiers', 'Duration (ms)', 'Source', 'Title', 'URL'];
      for (const p of profs) for (const v of (p.history?.visits || [])) {
        if (matchesSearch([v.url, v.title, v.transition_core])) rows.push([p.profile_name, fmtDate(v.visit_time), v.transition_core, (v.transition_qualifiers || []).join(', '), v.visit_duration_ms, v.source, v.title, v.url]);
      }
    } else if (state.historySub === 'downloads') {
      headers = ['Profile', 'Start Time', 'State', 'Danger Type', 'Total Bytes', 'MIME Type', 'Target Path', 'URL Chain'];
      for (const p of profs) for (const d of (p.history?.downloads || [])) {
        const urls = (d.url_chain || []).join(' -> ');
        if (matchesSearch([d.target_path, urls, d.mime_type, d.danger_type])) rows.push([p.profile_name, fmtDate(d.start_time), d.state, d.danger_type, d.total_bytes, d.mime_type, d.target_path, urls]);
      }
    } else {
      headers = ['Profile', 'Last Visit', 'Search Term', 'Normalized', 'URL'];
      for (const p of profs) for (const s of (p.history?.search_terms || [])) {
        if (matchesSearch([s.term, s.url])) rows.push([p.profile_name, fmtDate(s.last_visit_time), s.term, s.normalized_term, s.url || '']);
      }
    }

    const tbl = renderSortableTable(headers, rows, { monoCols: [1], breakCols: [headers.length - 1] });
    const c = el.querySelector('#histTbl');
    c.innerHTML = tbl.html;
    tbl.bind(c);
  }

  function renderCredentials(el) {
    const profs = activeProfiles();
    const subs = [['logins', 'Saved Logins'], ['cookies', 'Cookies'], ['autofill', 'Autofill'], ['addresses', 'Addresses & Cards']];
    el.innerHTML = '<div class="subbar">' +
      subs.map(([id, l]) => `<button type="button" data-sub="${id}" class="${state.credSub === id ? 'primary' : ''}">${l}</button>`).join('') +
      '</div><div id="credTbl"></div>';
    el.querySelectorAll('button[data-sub]').forEach(b => {
      b.addEventListener('click', () => { state.credSub = b.dataset.sub; state.page = 0; state.sortCol = null; render(); });
    });

    let headers = [], rows = [];
    if (state.credSub === 'logins') {
      headers = ['Profile', 'Source', 'Origin URL', 'Username', 'Scheme', 'Password Status', 'Uses', 'Last Used', 'Insecure Issues'];
      for (const p of profs) for (const l of (p.logins || [])) {
        if (matchesSearch([l.origin_url, l.username_value, ...(l.insecure_issues || [])])) {
          const pw = l.password_decrypted !== null && l.password_decrypted !== undefined
            ? l.password_decrypted
            : `[Encrypted ${l.password_encrypted_len} B]`;
          rows.push([p.profile_name, l.source_db, l.origin_url, l.username_value, l.encryption_scheme, pw, l.times_used, fmtDate(l.date_last_used), (l.insecure_issues || []).join(', ')]);
        }
      }
    } else if (state.credSub === 'cookies') {
      headers = ['Profile', 'Host Key', 'Name', 'Path', 'Scheme', 'Value / Status', 'Secure', 'HttpOnly', 'SameSite', 'Expires'];
      for (const p of profs) for (const c of (p.cookies || [])) {
        if (matchesSearch([c.host_key, c.name, c.value])) {
          const val = c.value !== null && c.value !== undefined ? c.value : `[Encrypted ${c.encrypted_len} B]`;
          rows.push([p.profile_name, c.host_key, c.name, c.path, c.encryption_scheme, val, c.is_secure ? 'Yes' : 'No', c.is_httponly ? 'Yes' : 'No', c.samesite, fmtDate(c.expires_utc)]);
        }
      }
    } else if (state.credSub === 'autofill') {
      headers = ['Profile', 'Field Name', 'Value', 'Count', 'Created', 'Last Used'];
      for (const p of profs) for (const a of (p.web_data?.autofill || [])) {
        if (matchesSearch([a.name, a.value])) rows.push([p.profile_name, a.name, a.value, a.count, fmtDate(a.date_created), fmtDate(a.date_last_used)]);
      }
    } else {
      headers = ['Profile', 'Type', 'Name / Nickname', 'Email / Network', 'Address / Card Last4', 'Phone / Exp', 'Uses'];
      for (const p of profs) {
        for (const a of (p.web_data?.addresses || [])) {
          if (matchesSearch([a.full_name, a.email, a.street_address, a.city, a.phone])) {
            rows.push([p.profile_name, 'Address', a.full_name, a.email, `${a.street_address}, ${a.city} ${a.state} ${a.zipcode}`, a.phone, a.use_count]);
          }
        }
        for (const cc of (p.web_data?.credit_cards || [])) {
          if (matchesSearch([cc.name_on_card, cc.network, cc.last_four])) {
            rows.push([p.profile_name, 'Card Meta', `${cc.name_on_card} (${cc.nickname})`, cc.network, cc.last_four ? `****${cc.last_four}` : '', `${cc.expiration_month}/${cc.expiration_year}`, cc.use_count]);
          }
        }
      }
    }
    const tbl = renderSortableTable(headers, rows, { breakCols: [2, 5] });
    const c = el.querySelector('#credTbl');
    c.innerHTML = tbl.html;
    tbl.bind(c);
  }

  function renderExtensions(el) {
    const profs = activeProfiles();
    let html = '<div class="card"><h3>Installed Extensions</h3><div id="extTbl"></div></div>';
    html += '<div class="card"><h3>Bookmarks</h3><div id="bmTbl"></div></div>';
    el.innerHTML = html;

    const extRows = [];
    for (const p of profs) for (const e of (p.extensions || [])) {
      if (matchesSearch([e.id, e.name, e.description, e.location, ...(e.permissions || []), ...(e.risk_flags || [])])) {
        extRows.push([p.profile_name, e.name, e.id, e.version, e.enabled ? 'Yes' : 'No', e.location, e.from_webstore ? 'Yes' : 'No', (e.risk_flags || []).join(', '), (e.permissions || []).join(', ')]);
      }
    }
    const t1 = renderSortableTable(
      ['Profile', 'Name', 'Extension ID', 'Version', 'Enabled', 'Location', 'Webstore', 'Risk Flags', 'Permissions'],
      extRows,
      { monoCols: [2], breakCols: [8] }
    );
    const e1 = el.querySelector('#extTbl');
    e1.innerHTML = t1.html;
    t1.bind(e1);

    const bmRows = [];
    for (const p of profs) for (const b of (p.bookmarks || [])) {
      if (matchesSearch([b.name, b.url, b.folder_path])) {
        bmRows.push([p.profile_name, b.folder_path, b.name, b.url, fmtDate(b.date_added), fmtDate(b.date_last_used)]);
      }
    }
    const t2 = renderSortableTable(
      ['Profile', 'Folder', 'Title', 'URL', 'Added', 'Last Used'],
      bmRows,
      { monoCols: [4, 5], breakCols: [3] }
    );
    const e2 = el.querySelector('#bmTbl');
    e2.innerHTML = t2.html;
    t2.bind(e2);
  }

  function renderSessions(el) {
    const profs = activeProfiles();
    const subs = [['tabs', 'SNSS Tabs'], ['local', 'Local Storage'], ['session', 'Session Storage'], ['misc', 'IndexedDB, Top Sites & NEL']];
    el.innerHTML = '<div class="subbar">' +
      subs.map(([id, l]) => `<button type="button" data-sub="${id}" class="${state.sessSub === id ? 'primary' : ''}">${l}</button>`).join('') +
      '</div><div id="sessTbl"></div>';
    el.querySelectorAll('button[data-sub]').forEach(b => {
      b.addEventListener('click', () => { state.sessSub = b.dataset.sub; state.page = 0; state.sortCol = null; render(); });
    });

    let headers = [], rows = [], tabRefs = [];
    if (state.sessSub === 'tabs') {
      headers = ['Profile', 'State', 'Source File', 'Tab ID', 'Title', 'Current URL', 'Nav Steps', 'Timestamp'];
      for (const p of profs) {
        for (const t of [...(p.sessions?.open_tabs || []), ...(p.sessions?.closed_tabs || [])]) {
          if (matchesSearch([t.current_url, t.current_title, t.source_file])) {
            tabRefs.push(t);
            rows.push([p.profile_name, t.is_closed ? 'Closed' : 'Open', t.source_file, t.tab_id, t.current_title, t.current_url, (t.navigations || []).length, fmtDate(t.timestamp)]);
          }
        }
      }
    } else if (state.sessSub === 'local') {
      headers = ['Profile', 'Origin', 'Key', 'Value'];
      for (const p of profs) for (const kv of (p.storage?.local_storage || [])) {
        if (matchesSearch([kv.origin, kv.key, kv.value])) rows.push([p.profile_name, kv.origin, kv.key, kv.value]);
      }
    } else if (state.sessSub === 'session') {
      headers = ['Profile', 'Origin / Map', 'Key', 'Value'];
      for (const p of profs) for (const kv of (p.storage?.session_storage || [])) {
        if (matchesSearch([kv.origin, kv.key, kv.value])) rows.push([p.profile_name, kv.origin, kv.key, kv.value]);
      }
    } else {
      headers = ['Profile', 'Artifact', 'Origin / URL', 'Details'];
      for (const p of profs) {
        for (const idb of (p.storage?.indexed_db_origins || [])) {
          if (matchesSearch([idb.origin_dir])) rows.push([p.profile_name, 'IndexedDB', idb.origin_dir, `${idb.file_count} files (${fmtBytes(idb.total_bytes)})`]);
        }
        for (const ts of (p.storage?.top_sites || [])) {
          if (matchesSearch([ts.url, ts.title])) rows.push([p.profile_name, 'Top Site #' + ts.rank, ts.url, ts.title]);
        }
        for (const sc of (p.storage?.shortcuts || [])) {
          if (matchesSearch([sc.text, sc.url])) rows.push([p.profile_name, 'Omnibox Shortcut', sc.url, `${sc.text} (${sc.number_of_hits} hits)`]);
        }
        for (const nel of (p.storage?.nel_policies || [])) {
          if (matchesSearch([nel.origin, nel.received_ip])) rows.push([p.profile_name, 'NEL Policy', nel.origin, `IP: ${nel.received_ip} | group: ${nel.group_name}`]);
        }
      }
    }

    const tbl = renderSortableTable(headers, rows, {
      breakCols: [3, 5],
      onRowClick: state.sessSub === 'tabs' ? (ridx) => {
        const t = tabRefs[ridx];
        if (!t) return;
        const navHtml = (t.navigations || []).map(n => `[${n.index}] ${n.title} -> ${n.url}`).join('\n');
        openModal(`Tab #${t.tab_id} (${t.is_closed ? 'Closed' : 'Open'})`,
          `<div class="mono" style="margin-bottom:8px;">Source: ${esc(t.source_file)}</div>
           <pre class="codebox">${esc(navHtml)}</pre>`);
      } : null
    });
    const c = el.querySelector('#sessTbl');
    c.innerHTML = tbl.html;
    tbl.bind(c);
  }

  function renderInventory(el) {
    const profs = activeProfiles();
    let html = '<div class="card"><h3>Profile File Inventory (Largest Artifacts)</h3><div id="invTbl"></div></div>';
    html += '<div class="card"><h3>Diagnostic Warnings</h3><div id="warnTbl"></div></div>';
    el.innerHTML = html;

    const invRows = [];
    for (const p of profs) for (const f of (p.file_inventory || [])) {
      if (matchesSearch([f.relative_path, f.category])) {
        invRows.push([p.profile_name, f.category, f.relative_path, f.size_bytes, fmtBytes(f.size_bytes)]);
      }
    }
    const t1 = renderSortableTable(['Profile', 'Category', 'Relative Path', 'Bytes', 'Human Size'], invRows, { monoCols: [2] });
    const e1 = el.querySelector('#invTbl');
    e1.innerHTML = t1.html;
    t1.bind(e1);

    const wRows = (DATA.warnings || [])
      .filter(w => matchesSearch([w.component, w.artifact_path, w.message]))
      .map(w => [w.severity, w.component, w.artifact_path, w.message]);
    const t2 = renderSortableTable(['Severity', 'Component', 'Artifact Path', 'Message'], wRows, { monoCols: [2], breakCols: [3] });
    const e2 = el.querySelector('#warnTbl');
    e2.innerHTML = t2.html;
    t2.bind(e2);
  }

  function render() {
    renderTabs();
    const el = document.getElementById('content');
    switch (state.activeTab) {
      case 'overview': renderOverview(el); break;
      case 'findings': renderFindings(el); break;
      case 'timeline': renderTimeline(el); break;
      case 'cache': renderCache(el); break;
      case 'history': renderHistory(el); break;
      case 'credentials': renderCredentials(el); break;
      case 'extensions': renderExtensions(el); break;
      case 'sessions': renderSessions(el); break;
      case 'inventory': renderInventory(el); break;
    }
  }

  render();
})();
</script>
</body>
</html>
"##;
