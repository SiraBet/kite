/*
 * The fleet: a query language + saved-view tabs over a triage-railed
 * table, plus the Add-machine drawer that polls until the host checks in.
 */
const FLEET_SORT_KEYS = {
  risk: f => {
    const rank = ['critical','important','moderate','low','unknown','none'];
    if(f.updates_assessed_ok === false) return 1 * 1e6;   // beside 'important'
    const idx = rank.indexOf(f.max_severity || 'none');
    return (idx < 0 ? rank.length : idx) * 1e6 - (f.pending_updates || 0);
  },
  hostname: f => f.hostname.toLowerCase(),
  team: f => (f.team||'').toLowerCase(),
  os: f => (f.os_family||'').toLowerCase(),
  last_patched: f => f.last_patched ? parseUTC(f.last_patched).getTime() : -1,
  last_seen: f => f.last_seen ? parseUTC(f.last_seen).getTime() : -1,
};
const FLEET_PAGE_SIZE = 12;

function sortFleetBy(key){
  if(state.fleetSort.key === key) state.fleetSort.dir *= -1;
  else state.fleetSort = {key, dir: 1};
  render();
}
function sortHeader(key, label){
  const active = state.fleetSort.key === key;
  const arrow = active ? (state.fleetSort.dir===1 ? '&uarr;' : '&darr;') : '';
  return `<div class="sortable-th" onclick="sortFleetBy('${key}')">${label}${active ? `<span class="sort-arrow">${arrow}</span>` : ''}</div>`;
}

// One word for a host's fused state — drives the triage rail, the tabs,
// and the status: token in the query language. Mirrors fleetStatusBadge.
function hostStateKey(f){
  const tier = connectivityTier(f);
  if(f.status === 'locked') return 'patching';
  if(tier === 'offline' || tier === 'stale') return 'unreachable';
  if(f.updates_assessed_ok === false) return 'unknown';
  const sev = f.max_severity;
  if((sev === 'critical' || sev === 'important') && f.pending_updates) return 'urgent';
  if(f.pending_updates) return 'due';
  return 'current';
}
function railClass(key){
  if(key === 'urgent') return 'rail-urgent';
  if(key === 'patching') return 'rail-info';
  if(key === 'unknown' || key === 'unreachable') return 'rail-unknown';
  return '';
}
function riskCell(host){
  if(host.updates_assessed_ok === false){
    return `<span class="badge unknown" title="This host's package manager could not be queried — what's pending is unknown, not zero"><span class="g">?</span>Unknown</span>`;
  }
  if(!host.pending_updates) return `<span class="dash-row-meta">none</span>`;
  return `<span title="${host.pending_updates} pending update(s), worst severity ${host.max_severity||'unknown'}">${sevChip(host.max_severity, host.pending_updates)}</span>`;
}

// ---- query language: free words + field:value tokens ----
function parseFleetQuery(q){
  return (q || '').trim().split(/\s+/).filter(Boolean).map(tok => {
    const m = tok.match(/^([a-z]+):(.+)$/i);
    return m ? {field: m[1].toLowerCase(), value: m[2].toLowerCase(), raw: tok} : {field: '', value: tok.toLowerCase(), raw: tok};
  });
}
function matchesFleetQuery(f, tokens){
  return tokens.every(t => {
    const v = t.value;
    if(t.field === 'os') return `${f.os_family||''} ${f.os_version||''}`.toLowerCase().includes(v);
    if(t.field === 'owner' || t.field === 'team') return (f.team||'').toLowerCase().includes(v);
    if(t.field === 'role') return (f.role||'').toLowerCase().includes(v);
    if(t.field === 'status') return hostStateKey(f) === v;
    if(t.field === 'sev' || t.field === 'severity') return (f.max_severity||'') === v;
    // free word: hostname / role / os
    return `${f.hostname} ${f.role||''} ${f.os_family||''} ${f.os_version||''} ${f.team||''}`.toLowerCase().includes(v);
  });
}
function setFleetQuery(input){
  state.fleetSearch = input.value;
  state.fleetPage = 0;
  render();
  const el = document.getElementById('fleet-search-input');
  if(el){ el.focus(); try{ el.setSelectionRange(input.selectionStart, input.selectionStart); }catch(e){} }
}
function removeFleetToken(raw){
  state.fleetSearch = parseFleetQuery(state.fleetSearch).filter(t => t.raw !== raw).map(t => t.raw).join(' ');
  state.fleetPage = 0; render();
}
function setFleetTab(tab){ state.fleetTab = tab; state.fleetPage = 0; render(); }
function fleetPageBy(delta){ state.fleetPage += delta; render(); }

const FLEET_TABS = [
  {id:'all',         label:'All',          match: () => true},
  {id:'needs',       label:'Needs action', match: f => f.updates_assessed_ok === false || (f.pending_updates||0) > 0},
  {id:'unreachable', label:'Unreachable',  match: f => { const t = connectivityTier(f); return t==='offline'||t==='stale'; }},
  {id:'current',     label:'Current',      match: f => hostStateKey(f) === 'current'},
];

function fleetExportCsv(){
  const cols = ['hostname','os_family','os_version','role','team','last_patched','last_seen','state','pending_updates','max_severity'];
  const rows = (state.fleet || []).map(f => ({...f, state: hostStateKey(f)}));
  const csv = [cols.join(',')].concat(rows.map(r => cols.map(c => {
    let v = r[c] == null ? '' : String(r[c]);
    // A cell starting with = + - @ (or a tab/CR) is a formula to a
    // spreadsheet; os_version, team and role come from hosts and admins.
    if(/^[=+\-@\t\r]/.test(v)) v = "'" + v;
    return /[",\n]/.test(v) ? `"${v.replace(/"/g,'""')}"` : v;
  }).join(','))).join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `kite-fleet-${new Date().toISOString().slice(0,10)}.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function renderFleet(){
  if(state.fleet===null) return `${fleetSectionHeader()}<p class="view-sub">Loading…</p><div class="loading-rows"><div class="skeleton" style="height:38px"></div><div class="skeleton" style="height:38px"></div><div class="skeleton" style="height:38px"></div></div>`;
  const canManage = atLeast(state.user.role, 'admin');
  const canPatch = atLeast(state.user.role, 'operator');   // as POST /runs and /batches allow
  const all = state.fleet;
  const tokens = parseFleetQuery(state.fleetSearch);
  const tab = FLEET_TABS.find(t => t.id === state.fleetTab) || FLEET_TABS[0];

  // tab first, then query
  let rows = all.filter(tab.match).filter(f => matchesFleetQuery(f, tokens));
  if(state.fleetSort.key){
    const keyFn = FLEET_SORT_KEYS[state.fleetSort.key];
    rows = rows.slice().sort((a,b) => { const av=keyFn(a),bv=keyFn(b); return (av<bv?-1:av>bv?1:0)*state.fleetSort.dir; });
  }
  const matchCount = rows.length;

  // pagination
  const pages = Math.max(1, Math.ceil(matchCount / FLEET_PAGE_SIZE));
  // Clamp the stored value too. Clamping only the local copy left
  // state.fleetPage sitting past the end after the result set shrank, so
  // Prev stayed enabled and needed several dead clicks to have any effect.
  const page = Math.min(Math.max(0, state.fleetPage), pages - 1);
  state.fleetPage = page;
  const pageRows = rows.slice(page*FLEET_PAGE_SIZE, (page+1)*FLEET_PAGE_SIZE);

  const cols = '34px 1.5fr 0.85fr 1.05fr 0.82fr 0.82fr 0.7fr 118px';
  const selectedInView = [...state.fleetSelected].filter(id => rows.some(f=>f.id===id));
  const allShownSelected = pageRows.length>0 && pageRows.every(f => state.fleetSelected.has(f.id));
  const selectedHosts = all.filter(f => state.fleetSelected.has(f.id));
  const deletable = selectedHosts.filter(hostRemovable);
  const busy = selectedHosts.length - deletable.length;

  const onlyOne = selectedHosts.length === 1 ? selectedHosts[0] : null;

  return `
    ${fleetSectionHeader()}
    ${state.loadError ? errorBanner(state.loadError) : ''}
    ${fleetStaleNote()}
    ${fleetAgentUpdateBanner()}

    <div class="fleet-topbar">
      <label class="fleet-search">
        <span style="width:11px;height:11px;border:1.5px solid var(--text-faint);border-radius:50%;flex:none"></span>
        <input id="fleet-search-input" placeholder="Search — try  os:windows  owner:corp-it  status:urgent" value="${esc(state.fleetSearch||'')}" oninput="setFleetQuery(this)">
        <span class="count">${matchCount} match${matchCount===1?'':'es'}</span>
      </label>
      <div class="grow"></div>
      <button onclick="fleetExportCsv()">Export CSV</button>
      ${canManage ? `<button class="primary" onclick="openAddMachine()">Add machine</button>` : ''}
    </div>

    <div class="fleet-tabs">
      ${FLEET_TABS.map(t => {
        const n = all.filter(t.match).length;
        const danger = t.id==='needs' || t.id==='unreachable';
        return `<button class="fleet-tab ${state.fleetTab===t.id?'active':''}" onclick="setFleetTab('${t.id}')">${t.label}<span class="n ${danger&&n?'danger':''}">${n}</span></button>`;
      }).join('')}
    </div>

    ${tokens.length ? `<div class="filter-chips">
      <span class="lbl">Filter</span>
      ${tokens.map(t => `<span class="fchip">${esc(t.field?`${t.field}: ${t.value}`:t.value)} <span class="x" onclick="removeFleetToken('${jsq(t.raw)}')">&times;</span></span>`).join('')}
      <span style="color:var(--accent);cursor:pointer;font-size:11.5px;font-weight:600" onclick="state.fleetSearch='';state.fleetPage=0;render()">Clear all</span>
    </div>` : ''}

    ${selectedHosts.length ? `
      <div class="sel-bar">
        <span class="chk">&#10003;</span>
        <span class="lead">${selectedHosts.length} selected${selectedInView.length !== selectedHosts.length
            ? ` <span class="secondary" style="font-weight:400">(${selectedHosts.length - selectedInView.length} hidden by this view)</span>` : ''}</span>
        <span class="facts">${fleetSelectionFacts(selectedHosts)}</span>
        <div class="grow"></div>
        <button onclick="loadFleet()">Re-check now</button>
        ${canPatch ? `<button class="primary"
            title="${onlyOne?`Start a run for ${esc(onlyOne.hostname)}`:`Patch these ${selectedHosts.length} machines, one at a time or in parallel`}"
            onclick="${onlyOne?`startRun(${onlyOne.id})`:`startBatchRun([${selectedHosts.map(f => f.id).join(',')}])`}">Patch${onlyOne?'':` ${selectedHosts.length} machines…`}</button>` : ''}
        ${canManage ? `<button ${deletable.length?'':'disabled'} title="${busy ? `${busy} selected ${busy===1?'has':'have'} a run in progress and stay${busy===1?'s':''}` : 'Remove the selected machines from kite'}" onclick="bulkDeleteHosts()">Remove ${deletable.length}</button>` : ''}
        <span class="x" onclick="state.fleetSelected.clear();render()">Clear</span>
      </div>` : ''}

    ${all.length===0
      ? `<div class="banner neutral">No machines yet.${canManage ? ' Use <strong>Add machine</strong> above to onboard one.' : ''}</div>`
      : matchCount===0
      ? `<div class="banner neutral">No machines match this view.</div>`
      : `<div class="panel">
      <div class="panel-head" style="grid-template-columns:${cols}">
        <div><input type="checkbox" ${allShownSelected?'checked':''} onchange="toggleSelectAllFleet(this, ${JSON.stringify(pageRows.map(f=>f.id))})" style="accent-color:var(--accent);cursor:pointer"></div>
        ${sortHeader('hostname','Host')}${sortHeader('team','Owner')}${sortHeader('os','Operating system')}${sortHeader('last_patched','Last patched')}${sortHeader('last_seen','Last heard from')}${sortHeader('risk','Pending')}<div>Health</div>
      </div>
      ${pageRows.map(f=>{
        const tier = connectivityTier(f);
        const offline = tier === 'offline';
        const stateKey = hostStateKey(f);
        const rail = railClass(stateKey);
        const patchedTone = (()=>{ const d = daysSince(f.last_patched); return d===null? '' : d>30 ? 'color:var(--urgent)' : d>14 ? 'color:var(--due)' : ''; })();
        const seenTone = offline||tier==='stale' ? 'color:var(--unknown-ink);font-weight:600' : '';
        return `<div class="panel-row ${rail}" style="grid-template-columns:${cols}">
          <div><input type="checkbox" ${state.fleetSelected.has(f.id)?'checked':''} onchange="toggleSelectFleet(${f.id})" style="accent-color:var(--accent);cursor:pointer"></div>
          <div>
            <a href="#" onclick="openHostDetail(${f.id});return false" class="mono" style="font-weight:500;color:var(--text-primary);font-size:12.5px">${esc(f.hostname)}</a>
            <div class="host-sub">${esc(f.role||'—')}${f.agent_version?` &middot; agent ${esc(f.agent_version)}`:''}</div>
          </div>
          <div class="secondary" style="font-size:11.5px">${esc(f.team||'—')}</div>
          <div>${osBadge(f.os_family)}</div>
          <div class="mono" style="font-size:11.5px;${patchedTone}" title="${f.last_patched ? fmtTs(f.last_patched) : 'never patched'}">${f.last_patched ? relTime(f.last_patched) : 'never'}</div>
          <div class="mono" style="font-size:11.5px;${seenTone}" title="${f.last_seen ? fmtTs(f.last_seen) : 'never reported in'}">${fmtLastSeen(f.last_seen)}</div>
          <div>${riskCell(f)}</div>
          <div>${fleetStatusBadge(f)}</div>
        </div>`;
      }).join('')}
      <div class="pager">
        <span>${matchCount===0?0:page*FLEET_PAGE_SIZE+1}&ndash;${Math.min(matchCount,(page+1)*FLEET_PAGE_SIZE)} of ${matchCount} matching &middot; ${all.length} total</span>
        <div class="grow"></div>
        <button ${page<=0?'disabled':''} onclick="fleetPageBy(-1)">&larr; Prev</button>
        <button ${page>=pages-1?'disabled':''} onclick="fleetPageBy(1)">Next &rarr;</button>
      </div>
    </div>`}
    ${state.addMachine ? renderAddMachine() : ''}`;
}

function fleetSelectionFacts(hosts){
  const win = hosts.filter(h => osPlatform(h.os_family)==='windows').length;
  const lin = hosts.filter(h => osPlatform(h.os_family)==='linux').length;
  const off = hosts.filter(h => connectivityTier(h)==='offline').length;
  const parts = [];
  if(win) parts.push(`${win} Windows`);
  if(lin) parts.push(`${lin} Linux`);
  if(off) parts.push(`${off} offline`);
  return parts.join(' · ') || '—';
}

function toggleSelectFleet(id){
  if(state.fleetSelected.has(id)) state.fleetSelected.delete(id);
  else state.fleetSelected.add(id);
  render();
}
function toggleSelectAllFleet(checkboxEl, visibleIds){
  if(checkboxEl.checked) visibleIds.forEach(id=>state.fleetSelected.add(id));
  else visibleIds.forEach(id=>state.fleetSelected.delete(id));
  render();
}
async function bulkDeleteHosts(){
  const targets = state.fleet.filter(f => state.fleetSelected.has(f.id) && hostRemovable(f));
  if(targets.length===0) return;
  const ok = await confirmDialog({
    title: targets.length === 1 ? 'Remove host' : `Remove ${targets.length} hosts`,
    message: removeHostsMessage(targets),
    confirmLabel: 'Remove', danger: true,
  });
  if(!ok) return;
  const results = await Promise.allSettled(targets.map(f => api.deleteHost(f.id)));
  const failed = results.filter(r=>r.status==='rejected').length;
  state.fleetSelected.clear();
  await loadFleet();
  if(failed) toast(`${targets.length-failed} removed, ${failed} failed.`, 'warning');
  else toast(`${targets.length} host${targets.length===1?'':'s'} removed.`, 'success');
}

/* ---------- Add machine drawer ---------- */
function openAddMachine(){
  state.addMachine = {platform:'rhel', hostname:'', team:'', role:'', result:null, pollHandle:null, since:0};
  if(state.agentDownloads === null) loadAgentDownloads();
  render();
}
function closeAddMachine(){
  if(state.addMachine && state.addMachine.pollHandle){ clearInterval(state.addMachine.pollHandle); }
  state.addMachine = null;
  loadFleet();
  render();
}
function addMachineField(k, v){ if(state.addMachine){ state.addMachine[k] = v; } }
function addMachinePlatform(p){ if(state.addMachine){ state.addMachine.platform = p; render(); } }
async function addMachineGenerate(){
  const a = state.addMachine;
  const hostname = (document.getElementById('am-hostname')||{}).value?.trim() || '';
  const team = (document.getElementById('am-team')||{}).value?.trim() || '';
  const role = (document.getElementById('am-role')||{}).value?.trim() || '';
  if(!hostname){ toast('Enter a hostname first.', 'warning'); return; }
  a.hostname = hostname; a.team = team; a.role = role;
  try{
    a.result = await api.createEnrollToken({hostname, team, role});
    // Baseline the host's CURRENT server-side last_seen (null when the host
    // doesn't exist yet, which is the normal case). "Checked in" is then a
    // change in that server value, never a comparison against this
    // browser's clock — a workstation running a few minutes fast used to
    // mean the drawer never flipped to Connected at all.
    const existing = (state.fleet || []).find(f => f.hostname === hostname);
    a.baselineSeen = existing ? (existing.last_seen || '') : null;
    render();
    startAddMachinePoll();
  }catch(e){ toast(e.message, 'danger'); }
}
function startAddMachinePoll(){
  const a = state.addMachine;
  if(!a) return;
  if(a.pollHandle) clearInterval(a.pollHandle);
  a.pollHandle = setInterval(async () => {
    // Navigating away suspends the poll; resumeAddMachinePoll() restarts it
    // when the fleet view comes back, so the drawer can't be left pinned on
    // "Waiting for first check-in…" forever after a detour to another page.
    if(!state.addMachine || state.nav!=='fleet'){
      clearInterval(a.pollHandle); a.pollHandle = null; return;
    }
    // Refresh the fleet SILENTLY (no render) — re-rendering the whole view
    // every tick is what made the drawer flicker and dropped input focus.
    // Only re-render when the host actually transitions to "checked in".
    const was = addMachineConnected();
    try{ state.fleet = await api.listHosts(); }catch(e){ return; }
    if(addMachineConnected() && !was){
      clearInterval(state.addMachine.pollHandle); state.addMachine.pollHandle = null;
      render();
      toast(`${state.addMachine.hostname} checked in.`, 'success');
    }
  }, 4000);
}
// Called when the fleet view is (re-)entered. A drawer left open across a
// navigation has a token but a stopped timer; without this it waits forever.
function resumeAddMachinePoll(){
  const a = state.addMachine;
  if(!a || !a.result || a.pollHandle) return;
  if(addMachineConnected()) return;
  startAddMachinePoll();
}
function addMachineConnected(){
  const a = state.addMachine;
  if(!a || !a.result) return false;
  const h = (state.fleet||[]).find(f => f.hostname === a.hostname);
  if(!h || !h.last_seen) return false;
  // The host wasn't in the fleet when we issued the token, so its mere
  // presence with a last_seen means it enrolled AND polled.
  if(a.baselineSeen === null || a.baselineSeen === undefined) return true;
  // Re-enrolling an existing host: it's checked in once the server's own
  // last_seen moves. Both sides of this comparison are server values.
  return h.last_seen !== a.baselineSeen;
}
// Offer a download only when this controller actually has the artefact.
// The link used to render unconditionally, so on an install where
// build-release.sh/build.sh never ran the operator clicked it and got a bare
// 404 with nothing saying why. state.agentDownloads already carried the
// answer; nothing consulted it.
function addMachineDownload(a){
  const want = a.platform === 'windows' ? 'windows' : 'linux';
  const list = state.agentDownloads;
  if(list === null || list === undefined){
    return `<span class="dash-row-meta">checking what this controller can hand out…</span>`;
  }
  if(list && list.error){
    return `<span class="dash-row-meta">couldn't check downloads: ${esc(list.error)}</span>`;
  }
  const entry = (list || []).find(d => d.platform === want);
  if(want === 'windows'){
    if(entry && entry.installer_available){
      return `<a class="chip" href="/download/installer/windows?token=${encodeURIComponent(a.result.token)}" download style="text-decoration:none">Download installer</a>`;
    }
    return `<span class="dash-row-meta">Windows installer not built on this controller — run <code class="mono">${esc((entry && entry.build_command) || 'agent-windows/build.sh')}</code> there. The command above still works.</span>`;
  }
  if(entry && entry.available){
    return `<a class="chip" href="/download/agent-linux" download style="text-decoration:none">Download agent bundle</a>`;
  }
  return `<span class="dash-row-meta">Linux agent bundle not staged on this controller — run <code class="mono">${esc((entry && entry.build_command) || 'build-release.sh')}</code> there. The command above still works.</span>`;
}
function renderAddMachine(){
  const a = state.addMachine;
  const connected = addMachineConnected();
  const platforms = [{id:'rhel',label:'RHEL / Rocky'},{id:'debian',label:'Ubuntu / Debian'},{id:'windows',label:'Windows'}];
  return `
    <div class="drawer-backdrop" onclick="if(event.target===this)closeAddMachine()">
      <div class="drawer">
        <div class="drawer-head">
          <div class="grow">
            <div style="font-size:15px;font-weight:600">Add a machine</div>
            <div style="font-size:11.5px;color:var(--text-muted);margin-top:3px">Installs the agent and registers the host. Nothing is patched on enrolment.</div>
          </div>
          <span style="cursor:pointer;color:var(--text-muted);font-size:16px" onclick="closeAddMachine()">&times;</span>
        </div>
        <div class="drawer-body">
          <div>
            <div class="step-lbl">1 · Platform</div>
            <div class="chip-row">
              ${platforms.map(p=>`<span class="chip ${a.platform===p.id?'active':''}" onclick="addMachinePlatform('${p.id}')">${p.label}</span>`).join('')}
            </div>
          </div>
          <div>
            <div class="step-lbl">2 · Identity</div>
            <div class="field-row" style="margin-bottom:8px">
              <input id="am-hostname" placeholder="hostname, e.g. app-web-04" value="${esc(a.hostname)}" oninput="addMachineField('hostname',this.value)">
            </div>
            <div class="field-row">
              <input id="am-team" placeholder="owner team" value="${esc(a.team)}" oninput="addMachineField('team',this.value)">
              <input id="am-role" placeholder="role / tier" value="${esc(a.role)}" oninput="addMachineField('role',this.value)">
            </div>
          </div>
          ${!a.result ? `
            <button class="primary" onclick="addMachineGenerate()">Generate enrolment token</button>
            <p class="card-help" style="margin:0">A one-time token scoped to this hostname. The install command below appears once it's generated.</p>
          ` : `
            <div>
              <div style="display:flex;align-items:baseline;gap:8px;margin-bottom:7px">
                <span class="step-lbl" style="margin:0">3 · Run this on the host</span>
                <span class="grow"></span>
                <button style="padding:4px 9px;font-size:11px" onclick="copyEnrollCmd(this)">Copy</button>
              </div>
              <pre id="enroll-cmd" class="cmd-block">${esc(enrollCommand(a.platform, a.result))}</pre>
              ${controllerCaFingerprint() ? `<p class="card-help" style="margin:7px 0 0">Checks the controller's certificate authority before trusting it — SHA-256 <span class="mono" style="overflow-wrap:anywhere">${esc(controllerCaFingerprint())}</span>, the same fingerprint your browser shows for it.</p>` : ''}
              <p class="card-help" style="margin:7px 0 0">Token for <strong>${esc(a.result.hostname)}</strong> — single-use, expires ${fmtTs(a.result.expires_at)}.</p>
            </div>
            <div style="display:flex;gap:8px">${addMachineDownload(a)}</div>
            <div class="await-box ${connected?'ok':''}">
              <span class="sp">${connected?'&#10003;':''}</span>
              <div>
                <div style="font-weight:600;font-size:11.5px">${connected?`Connected — ${esc(a.hostname)} reported in`:'Waiting for first check-in…'}</div>
                <div style="font-size:10.5px;color:var(--text-muted);margin-top:2px">${connected?'The host is enrolled and now appears in the fleet.':'This host counts as <strong>not checked</strong> until it reports.'}</div>
              </div>
            </div>
          `}
        </div>
        <div class="drawer-foot">
          <button onclick="closeAddMachine()">${addMachineConnected()?'Done':'Close'}</button>
        </div>
      </div>
    </div>`;
}

// Above the host list: agents behind the newest published build, and one
// button to bring them all up to it. Shown only when there's something to do.
function fleetAgentUpdateBanner(){
  const U = state.agentUpdates;
  if(!U || !(U.latest || U.windows)) return '';
  const isAdmin = atLeast(state.user.role, 'admin');
  const updating = U.hosts.filter(h => h.updating_to);
  const behind = U.hosts.filter(h => h.behind && h.can_self_update && !h.updating_to);
  const manual = U.hosts.filter(h => h.behind && !h.can_self_update);
  const n = k => `${k} machine${k===1?'':'s'}`;
  const manualNote = manual.length ? ` ${n(manual.length)} can’t update themselves from this controller and need updating by hand.` : '';
  const targets = [...new Set(updating.map(h => h.updating_to))];
  if(updating.length)
    return `<div class="banner info" style="margin-bottom:12px"><span class="pm-spin"></span><span><strong>Updating ${n(updating.length)} to ${targets.map(esc).join(' / ')}.</strong> Each agent installs it on its next check-in.${behind.length ? ` ${n(behind.length)} more still behind.` : ''}${manualNote}</span>
      <span class="grow"></span>${isAdmin && U.fleet_target ? '<button onclick="cancelAgentUpdate(null)">Stop</button>' : ''}</div>`;
  if(!behind.length && !manual.length) return '';
  // One version for every agent (they're released together); per OS only while a controller serves mismatched builds.
  const versions = [...new Set([U.latest, U.windows].filter(Boolean))];
  const newest = versions.length === 1 ? versions[0]
    : [U.latest && `${U.latest} for Linux`, U.windows && `${U.windows} for Windows`].filter(Boolean).join(', ');
  return `<div class="banner neutral" style="margin-bottom:12px"><span><strong>${n(behind.length + manual.length)} run${behind.length + manual.length===1?'s':''} an older agent</strong> — the newest is ${esc(newest)}.${manualNote}</span>
    <span class="grow"></span>${isAdmin && behind.length ? `<button class="primary" onclick="requestAgentUpdate('latest', null)">Update ${behind.length===1 ? 'it' : `all ${behind.length}`}${versions.length === 1 ? ` to ${esc(versions[0])}` : ''}</button>` : ''}</div>`;
}

// Says so when the list on screen is older than a minute (a background
// tab, or the controller not answering): its states are as of then.
function fleetStaleNote(){
  const at = state.fleetFetchedAt;
  if(!at || Date.now() - at < 60000) return '';
  const when = new Date(at).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  return `<div class="banner neutral" style="margin-bottom:12px">${state.fleetRefreshing ? '<span class="pm-spin"></span>' : ''}<span>Showing the fleet as of <strong>${esc(when)}</strong>${state.fleetRefreshing ? ' — updating…' : ' — the controller hasn’t answered since.'}</span></div>`;
}
