/*
 * CVEs the fleet is exposed to (app/vulnerabilities.py): the machine page's
 * Vulnerabilities tab, Fleet -> Vulnerabilities (search across every
 * host), and Settings -> Vulnerabilities (turning the data on, its state).
 */
/* ============================== VULNERABILITIES ============================== */
async function loadHostVulns(id){
  try{ const v = await api.hostVulns(id); if(state.hostDetailId === id){ state.hostVulns = v; render(); } }
  catch(e){ /* tab shows loading */ }
}
async function loadVulns(){
  try{ state.vulns = await api.fleetVulns(); }
  catch(e){ state.vulns = {error: e.message, items: [], total: 0}; }
  render();
}
async function loadVulnStatus(){
  try{ state.vulnStatus = await api.vulnStatus(); }
  catch(e){ state.vulnStatus = {error: e.message, feeds: []}; }
  render();
  // A download runs in the background for minutes: follow it while the page is open.
  if(state.vulnStatus.refreshing && state.nav === 'settings' && state.settingsTab === 'vulns') setTimeout(loadVulnStatus, 5000);
}
function cveLink(cve, url){
  // A CVE id links to its record; an advisory with no CVE to the advisory.
  const href = /^CVE-\d+-\d+$/.test(cve) ? `https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}` : (url || '');
  return href && /^https:\/\//.test(href)
    ? `<a class="mono" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(cve)}</a>`
    : `<span class="mono">${esc(cve)}</span>`;
}
function vulnSevChips(counts){
  return SEVERITY_ORDER.filter(s => counts && counts[s] && s !== 'none').slice(0, 3).map(s => sevChip(s, counts[s])).join(' ');
}
function liveVulnSearch(input, key, id){
  const pos = input.selectionStart;
  state[key] = input.value;
  state[key === 'hostVulnsQ' ? 'hostVulnsPage' : 'vulnsPage'] = 0;   // a new search starts at its first page
  render();
  const el = document.getElementById(id);
  if(el){ el.focus(); el.setSelectionRange(pos, pos); }
}
const VULN_SOURCE = {go: ['GitHub', 'GitHub security advisory, via OSV (Go tools)'], nvd: ['NVD', 'NVD — matched by product and version, less exact than a distribution’s own advisory']};
function vulnSourceTag(source){
  const s = VULN_SOURCE[source];
  return s ? ` <span class="badge neutral" style="font-size:9.5px;padding:1px 5px" title="${esc(s[1])}">${s[0]}</span>` : '';
}
const VULN_LAG_NOTE = 'Matched against the distribution’s advisories as published on OSV. They and this machine’s repositories don’t change at the same moment, so for a few days around a release this list and the Updates tab can differ.';

/* ---------- machine page ---------- */
function hostVulnTile(){
  const V = state.hostVulns;
  const tile = (value, sub) => `<div class="host-tile" onclick="setHostTab('vulns')"><div class="lbl">Vulnerabilities</div><div class="val">${value}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;
  if(!V) return '';
  if(!V.covered) return tile('<span class="muted">—</span>', 'not checked');
  const n = V.counts.total;
  return tile(n ? `${n} CVE${n===1?'':'s'}` : '<span style="color:var(--ok)">&#10003; none known</span>', vulnSevChips(V.counts));
}
function renderHostVulns(){
  const V = state.hostVulns;
  if(!V) return '<div class="banner neutral">Loading…</div>';
  if(!V.covered) return `<div class="banner neutral">${esc(V.reason || 'Not checked.')}</div>`;
  const q = (state.hostVulnsQ || '').trim().toLowerCase();
  const items = V.items.filter(v => !q || `${v.cve} ${v.summary} ${v.advisories.join(' ')} ${v.packages.map(p => p.name).join(' ')}`.toLowerCase().includes(q));
  const pg = vulnPage(items, 'hostVulnsPage');
  const hasVendor = V.items.some(v => v.source && v.source !== 'distro' && v.source !== 'msrc');
  const head = `<p class="card-help" style="margin-top:0">${V.counts.total
    ? `${V.counts.total} known vulnerabilit${V.counts.total===1?'y':'ies'} an update fixes${hasVendor ? ' — OS packages via patching, vendor software via its own updates' : ' — patching this machine clears them'}.`
    : 'No known vulnerability in what’s installed.'}
    ${V.windows_fix ? `<strong>Windows:</strong> the latest cumulative update, ${esc(V.windows_fix.fix)}, fixes all ${V.windows_fix.count} of its Windows CVEs.` : ''}
    ${V.ecosystem && V.refreshed_at ? `OS: ${esc(V.ecosystem)} advisories, refreshed ${esc(relTime(V.refreshed_at))}${V.error ? ` <span class="badge warning">last refresh failed</span>` : ''}.` : ''}
    ${V.third_party_refreshed_at ? `Vendor software: GitHub advisories and NVD, refreshed ${esc(relTime(V.third_party_refreshed_at))}.` : ''}
    ${V.os_note ? esc(V.os_note) : ''} ${(V.feed || '').startsWith('MSRC:') ? '' : VULN_LAG_NOTE}</p>`;
  if(!V.items.length) return head;
  return `${head}
    <label class="fleet-search" style="margin-bottom:12px"><span style="width:11px;height:11px;border:1.5px solid var(--text-faint);border-radius:50%;flex:none"></span>
      <input id="host-vulns-q" placeholder="Find a CVE, advisory or package" value="${esc(state.hostVulnsQ || '')}" oninput="liveVulnSearch(this, 'hostVulnsQ', 'host-vulns-q')">
      <span class="count">${items.length} match${items.length===1?'':'es'}</span></label>
    <div class="panel">
      <div class="panel-head" style="grid-template-columns:110px 150px minmax(0,1.4fr) minmax(0,1.6fr)"><div>Severity</div><div>CVE</div><div>Package</div><div>Fixed in</div></div>
      ${pg.rows.map(v => `<div class="panel-row" style="grid-template-columns:110px 150px minmax(0,1.4fr) minmax(0,1.6fr)">
        <div>${severityBadge(v.severity)}${v.score ? ` <span class="muted mono" style="font-size:10.5px">${esc(v.score)}</span>` : ''}</div>
        <div style="overflow-wrap:anywhere">${cveLink(v.cve, v.url)}${vulnSourceTag(v.source)}<div class="muted" style="font-size:10.5px">${esc(v.advisories.filter(a => a !== v.cve).join(' '))}</div></div>
        <div style="min-width:0">${v.packages.map(p => `<div class="mono" style="overflow-wrap:anywhere">${esc(p.name)} <span class="muted">${esc(p.installed)}</span></div>`).join('')}
          ${v.summary ? `<div class="secondary" style="font-size:11.5px;overflow-wrap:anywhere">${esc(v.summary)}</div>` : ''}</div>
        <div class="mono secondary" style="overflow-wrap:anywhere">${v.packages.map(p => `<div>${esc(p.fixed)}</div>`).join('')}</div>
      </div>`).join('') || '<div class="section-empty">Nothing matches.</div>'}
      ${pg.pager}
    </div>`;
}

// 50 CVEs to a page; `key` is the state field holding the page number.
const VULN_PAGE = 50;
function vulnPage(items, key){
  const pages = Math.max(1, Math.ceil(items.length / VULN_PAGE)), page = Math.min(state[key] || 0, pages - 1);
  const rows = items.slice(page * VULN_PAGE, (page + 1) * VULN_PAGE);
  const pager = pages > 1 ? `<div class="pager"><span>${page * VULN_PAGE + 1}–${page * VULN_PAGE + rows.length} of ${items.length}</span><span class="grow"></span>
    <button ${page===0?'disabled':''} onclick="state.${key}=${page-1};render()">&larr; Prev</button><button ${page>=pages-1?'disabled':''} onclick="state.${key}=${page+1};render()">Next &rarr;</button></div>` : '';
  return {rows, pager};
}
/* ---------- Fleet -> Vulnerabilities ---------- */
function setVulnSeverity(s){ state.vulnsSeverity = state.vulnsSeverity === s ? '' : s; state.vulnsPage = 0; render(); }
function renderFleetVulns(){
  const V = state.vulns;
  if(V === null) return `${fleetSectionHeader()}<div class="loading-rows"><div class="skeleton" style="height:38px"></div><div class="skeleton" style="height:38px"></div></div>`;
  if(V.error) return `${fleetSectionHeader()}${errorBanner(V.error)}`;
  if(!V.enabled) return `${fleetSectionHeader()}<div class="banner neutral">Vulnerability data is off. ${atLeast(state.user.role, 'admin')
    ? `<a href="#" onclick="state.settingsTab='vulns';loadVulnStatus();navigate('settings');return false">Turn it on in Settings → Vulnerabilities</a>`
    : 'An admin can turn it on in Settings → Vulnerabilities'} to see which CVEs each machine is exposed to.</div>`;
  const q = (state.vulnsQ || '').trim().toLowerCase();
  const sev = state.vulnsSeverity || '';
  const counts = {};
  V.items.forEach(v => { counts[v.severity] = (counts[v.severity] || 0) + 1; });
  const items = V.items.filter(v => (!sev || v.severity === sev) && (!q || `${v.cve} ${v.summary} ${v.hosts.map(h => h.hostname + ' ' + h.packages.map(p => p.name).join(' ')).join(' ')}`.toLowerCase().includes(q)));
  const pg = vulnPage(items, 'vulnsPage');
  const hostsHit = new Set(V.items.flatMap(v => v.hosts.map(h => h.host_id))).size;
  return `${fleetSectionHeader()}
    <p class="card-help" style="margin-top:0">${V.total} known vulnerabilit${V.total===1?'y':'ies'} across ${hostsHit} machine${hostsHit===1?'':'s'}, each fixed by an update. ${VULN_LAG_NOTE}</p>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
      <label class="fleet-search" style="flex:1 1 320px;margin:0"><span style="width:11px;height:11px;border:1.5px solid var(--text-faint);border-radius:50%;flex:none"></span>
        <input id="fleet-vulns-q" placeholder="Find a CVE (e.g. 2024-6387), package or machine" value="${esc(state.vulnsQ || '')}" oninput="liveVulnSearch(this, 'vulnsQ', 'fleet-vulns-q')">
        <span class="count">${items.length} match${items.length===1?'':'es'}</span></label>
      ${SEVERITY_ORDER.filter(s => counts[s]).map(s => `<button class="${sev===s?'primary':''}" style="padding:5px 9px;font-size:11px" onclick="setVulnSeverity('${s}')">${sevChip(s, counts[s])}</button>`).join('')}
    </div>
    <div class="panel">
      <div class="panel-head" style="grid-template-columns:110px 160px minmax(0,1fr) minmax(0,1.6fr)"><div>Severity</div><div>CVE</div><div>Summary</div><div>Machines</div></div>
      ${pg.rows.map(v => `<div class="panel-row" style="grid-template-columns:110px 160px minmax(0,1fr) minmax(0,1.6fr)">
        <div>${severityBadge(v.severity)}${v.score ? ` <span class="muted mono" style="font-size:10.5px">${esc(v.score)}</span>` : ''}</div>
        <div style="overflow-wrap:anywhere">${cveLink(v.cve, v.url)}${vulnSourceTag(v.source)}</div>
        <div class="secondary" style="font-size:12px;overflow-wrap:anywhere">${esc(v.summary || '—')}</div>
        <div style="min-width:0">${(state.vulnsHostsOpen[v.cve] ? v.hosts : v.hosts.slice(0, 5)).map(h => `<div style="overflow-wrap:anywhere"><a href="#" class="mono" onclick="state.hostTab='vulns';openHostDetail(${h.host_id});return false">${esc(h.hostname)}</a>
          <span class="muted mono" style="font-size:11px">${esc(h.packages.map(p => `${p.name} → ${p.fixed}`).join(', '))}</span></div>`).join('')}
          ${v.hosts.length > 5 ? `<button class="history-toggle" onclick="state.vulnsHostsOpen['${jsq(v.cve)}']=${!state.vulnsHostsOpen[v.cve]};render()">${state.vulnsHostsOpen[v.cve] ? 'show fewer' : `+${v.hosts.length - 5} more machines`}</button>` : ''}</div>
      </div>`).join('') || `<div class="section-empty">${V.total ? 'Nothing matches.' : 'No known vulnerabilities on any machine. A machine is covered once its agent has reported its software on a covered OS.'}</div>`}
      ${pg.pager}
    </div>`;
}

/* ---------- Settings -> Vulnerabilities ---------- */
async function setVulnFeedEnabled(on){
  try{
    await api.updateSetting('vuln_feed_enabled', on ? 'true' : 'false');
    await loadSettings();
    toast(on ? 'Vulnerability data on — the first download runs in the background.' : 'Vulnerability data off — matches cleared.', 'success');
  }catch(e){ toast(e.message, 'danger'); }
  loadVulnStatus();
}
async function refreshVulnData(){
  try{ const r = await api.refreshVulns(); toast(r.note || 'Refresh started — it runs in the background.', 'success'); }
  catch(e){ toast(e.message, 'danger'); }
  loadVulnStatus();
}
function renderVulnSettings(){
  const on = !!state.settings && state.settings.vuln_feed_enabled === 'true';
  const S = state.vulnStatus;
  const feeds = S && S.feeds ? S.feeds : [];
  return `
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:16px">
        <div>
          <p style="font-weight:500;margin:0 0 4px">Download vulnerability data</p>
          <p style="font-size:12px;color:var(--text-secondary);margin:0">Matches each machine’s installed software against published advisories, to name the CVEs an update fixes. OS packages: the distribution’s own advisories (RHEL, Rocky, AlmaLinux, Debian, Ubuntu) from OSV. Windows itself: Microsoft’s Security Update Guide. Software from vendors’ own repositories, snaps and Windows programs: GitHub advisories for Go tools (Docker, containerd, Vault…) from OSV, and NVD for the rest (Node.js, PostgreSQL, browsers…). When on, the controller fetches these once a day — its one connection to the internet. Only public data is fetched: OSV as whole files, NVD by product for a fixed list of products. Microsoft is asked only about the Windows versions your machines run (“Windows 11 Version 24H2 for x64-based Systems”) — nothing else about them is sent. The first Ubuntu download is about 800 MB; NVD is slow, so its first pass can take an hour. After that only changes are fetched.</p>
        </div>
        <button class="${on?'primary':''}" style="flex:none" onclick="setVulnFeedEnabled(${!on})">${on ? 'Enabled' : 'Disabled'} — click to ${on?'disable':'enable'}</button>
      </div>
    </div>
    ${S && S.error ? errorBanner(S.error) : ''}
    ${on || feeds.length ? `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="font-weight:600">Data</div><div class="grow"></div>
      ${S && S.refreshing ? '<span class="badge info running"><span class="g"></span>Refreshing</span>' : ''}
      <button onclick="loadVulnStatus()">Reload</button>
      ${on ? `<button ${S && S.refreshing ? 'disabled' : ''} onclick="refreshVulnData()">Refresh now</button>` : ''}
    </div>
    <div class="panel">
      <div class="panel-head" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr) 90px 130px minmax(0,1.4fr)"><div>Source</div><div>Covers</div><div>Advisories</div><div>Refreshed</div><div>Status</div></div>
      ${feeds.map(f => `<div class="panel-row" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr) 90px 130px minmax(0,1.4fr)">
        <div>${esc(f.label || f.name)}</div>
        <div class="secondary" style="font-size:12px;overflow-wrap:anywhere">${esc(f.ecosystems.join(', ') || (f.needed ? '' : 'no machine needs it now'))}</div>
        <div class="mono">${f.records || 0}</div>
        <div class="secondary">${f.refreshed_at ? esc(relTime(f.refreshed_at)) : '—'}</div>
        <div style="overflow-wrap:anywhere;font-size:12px">${f.error ? `<span class="badge danger">Failed</span> ${esc(f.error)}`
          : f.refreshed_at ? '<span class="badge success"><span class="g">&#10003;</span>Up to date</span>'
          : '<span class="badge neutral">Not downloaded yet</span>'}</div>
      </div>`).join('') || `<div class="section-empty">${S ? 'No machine has reported a covered OS yet (each agent reports it with its software).' : 'Loading…'}</div>`}
    </div>` : ''}`;
}
