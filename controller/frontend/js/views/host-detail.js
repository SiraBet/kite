/*
 * One host: its facts, its run history, and the actions available on it.
 */
/* ============================== HOST DETAIL ============================== */
const JOB_STATUS_STYLE = {
  done:['success','Done'], failed:['danger','Failed'], cancelled:['warning','Cancelled'],
  running:['info','Running'], queued:['neutral','Queued'],
};
async function openHostDetail(id){
  state.nav = 'host';
  state.hostDetailId = id;
  loadGroups();
  state.hostDetail = null;
  state.hostContainers = null;
  state.hostUpdates = null;
  state.hostNetwork = null;
  state.hostSnapshots = null;
  state.hostLoadErrors = {};
  state.hostSoftware = null;
  state.hostSoftwareQ = '';
  state.hostVulns = null;
  state.hostVulnsQ = '';
  state.hostVulnsPage = 0;
  state.hostUpdatesAll = {};
  setHash(`h/${id}`);
  render();
  if(state.agentUpdates === null) loadAgentUpdates();
  try{
    const [host, runs] = await Promise.all([api.getHost(id), api.listRunsForHost(id)]);
    if(state.hostDetailId !== id) return; // navigated away before this resolved
    state.hostDetail = {host, runs};
    render();
    loadHostVulns(id);
    // Inventory is supplementary — fetched after the page is already on
    // screen, and a failure leaves the section absent rather than
    // blocking the host detail behind it.
    try{
      const [containers, updates] = await Promise.all([api.hostContainers(id), api.hostUpdates(id)]);
      if(state.hostDetailId === id){
        state.hostContainers = containers;
        state.hostUpdates = updates;
        render();
      }
    }catch(e){ /* sections stay hidden */ }
    // The connection picker (admin card) needs the list of connections.
    if(atLeast(state.user.role, 'admin') && state.pmConnections === null) loadProxmoxConnections();
    // Network detail is operator+ (it's a map of what to attack), so a
    // read-only account doesn't ask for it.
    if(atLeast(state.user.role, 'operator')){
      try{
        const net = await api.hostNetwork(id);
        if(state.hostDetailId === id){ state.hostNetwork = net; render(); }
      }catch(e){ hostLoadFailed(id, 'network', e); }
      if(host.proxmox_vmid) loadHostSnapshots(id);
      loadHostSoftware(id);
    }
    // Which custom stage scripts this machine runs (its group's, else its
    // OS family's) — powers the "Scripts" rail card. Best-effort, like inventory.
    try{
      const fs = await api.scriptsForHost(id);
      if(state.hostDetailId === id && state.hostDetail){ state.hostDetail.familyScripts = fs; render(); }
    }catch(e){ /* card falls back to "defaults" */ }
    if(atLeast(state.user.role, 'admin') && state.osScripts === null) loadOsScripts();   // the Script group choices
  }catch(e){
    state.loadError = `Couldn't load host: ${e.message}`;
    state.nav = 'fleet';
    render();
  }
}
function renderHostDetail(){
  if(state.hostDetail===null) return `<div class="view-header"><h1 class="view-title">Host</h1><p class="view-sub">Loading…</p></div><div class="loading-rows"><div class="skeleton" style="height:90px"></div><div class="skeleton" style="height:200px"></div></div>`;
  const {host: f, runs} = state.hostDetail;
  const canEnroll = atLeast(state.user.role, 'admin');
  const canDelete = atLeast(state.user.role, 'admin');
  const age = daysSince(f.last_patched);
  return `
    <div class="view-header">
      <p style="margin:0 0 8px"><a href="#" onclick="navigate('fleet');return false">&larr; Fleet</a></p>
      <div style="display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap">
        <div class="grow">
          <h1 class="view-title mono">${esc(f.hostname)}</h1>
          <p class="view-sub">${esc(f.role||'No role set')} &middot; ${esc(f.team||'No team')}</p>
          <div style="margin-top:8px;display:flex;gap:8px;align-items:center">${osBadge(f.os_family)}${fleetStatusBadge(f)}</div>
        </div>
        <div style="display:flex;gap:8px">
          <button onclick="openHostDetail(${f.id})">Re-check</button>
          ${f.active_job_id
            ? `<button class="primary" onclick="openJobProgress(${f.active_job_id})">View active run</button>`
            : atLeast(state.user.role, 'operator')
              ? `<button class="primary" onclick="startRun(${f.id}, state.hostDetail.host)">Patch this host…</button>` : ''}
        </div>
      </div>
    </div>
    ${state.loadError ? errorBanner(state.loadError) : ''}
    <div style="display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:16px;align-items:start">
      <div style="min-width:0">
        ${renderHostSummary(f)}
        ${renderHostTabs(f, runs)}
        <div class="host-tab-body">${renderHostTab(f, runs)}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:14px;min-width:0">
        ${renderHostIdentity(f)}
        ${renderHostEvidence(f)}
        ${renderHostFamilyScripts(f)}
        ${renderHostAdminActions(f, canDelete, canEnroll)}
      </div>
    </div>
  `;
}
/* ---------- summary strip and tabs ---------- */
// The page used to stack every section -- all updates, every container,
// one row per listening port -- so the runs sat a long scroll down. Now a
// strip says where the machine stands, and one section shows at a time.
const HOST_TABS = [
  {id: 'updates', label: 'Updates'},
  {id: 'vulns', label: 'Vulnerabilities'},
  {id: 'containers', label: 'Containers'},
  {id: 'network', label: 'Network'},
  {id: 'software', label: 'Software'},
  {id: 'snapshots', label: 'Snapshots'},
  {id: 'runs', label: 'Runs'},
];
function hostTabCounts(f, runs){
  const n = state.hostNetwork;
  return {
    updates: state.hostUpdates ? state.hostUpdates.length : null,
    containers: state.hostContainers ? state.hostContainers.length : null,
    network: n && n.listening ? reachablePortCount(n.listening) : null,
    snapshots: state.hostSnapshots && state.hostSnapshots.snapshots ? state.hostSnapshots.snapshots.length : null,
    software: state.hostSoftware && state.hostSoftware.items ? state.hostSoftware.items.length : null,
    vulns: state.hostVulns && state.hostVulns.covered ? state.hostVulns.counts.total : null,
    runs: runs.length,
  };
}
// Ports reachable from the network, each once: a service on "every
// interface" usually listens on IPv4 and IPv6 both.
function reachablePortCount(listening){
  return new Set(listening.filter(p => !p.loopback).map(p => `${p.proto}/${p.port}/${p.process || ''}`)).size;
}
// Network, software and snapshots are operator+ (a map of what to attack,
// what's installed, the way back): a read-only account isn't offered them.
const OPERATOR_TABS = ['network', 'software', 'snapshots'];
function hostTabsShown(f){
  // A tab with nothing to say for this machine isn't offered: no containers
  // runtime, or no Proxmox VM to hold snapshots.
  return HOST_TABS.filter(t => !(t.id === 'containers' && Array.isArray(state.hostContainers) && !state.hostContainers.length)
    && !(t.id === 'snapshots' && !f.proxmox_vmid)
    && !(OPERATOR_TABS.includes(t.id) && !atLeast(state.user.role, 'operator')));
}
function hostTab(f){
  const shown = hostTabsShown(f).map(t => t.id);
  return shown.includes(state.hostTab) ? state.hostTab : shown[0];
}
function setHostTab(id){ state.hostTab = id; render(); }
function renderHostTabs(f, runs){
  const counts = hostTabCounts(f, runs), current = hostTab(f);
  return `<div class="fleet-tabs host-tabs">${hostTabsShown(f).map(t => `
    <button class="fleet-tab ${current===t.id?'active':''}" onclick="setHostTab('${t.id}')">${t.label}${counts[t.id] != null ? `<span class="n">${counts[t.id]}</span>` : ''}</button>`).join('')}</div>`;
}
function renderHostTab(f, runs){
  const t = hostTab(f);
  if(t === 'containers') return renderHostContainers() || '<div class="banner neutral">No containers reported.</div>';
  const failed = (state.hostLoadErrors || {})[t];
  if(failed) return `<div class="banner danger">Couldn't load this: ${esc(failed)} <button style="margin-left:8px" onclick="openHostDetail(${f.id})">Try again</button></div>`;
  if(t === 'network') return renderHostNetwork() || '<div class="banner neutral">Loading…</div>';
  if(t === 'snapshots') return renderHostSnapshots() || '<div class="banner neutral">Loading…</div>';
  if(t === 'runs') return renderHostRuns(runs);
  if(t === 'software') return renderHostSoftware();
  if(t === 'vulns') return renderHostVulns();
  return renderHostUpdates() || '<div class="banner neutral">Loading…</div>';
}
function renderHostRuns(runs){
  if(!runs.length) return `<div class="banner neutral">No runs recorded for this host yet.</div>`;
  return `
    <div class="panel">
      <div class="panel-head" style="grid-template-columns:70px 110px 1fr 1fr 90px">
        <div>Job</div><div>Status</div><div>Ticket</div><div>Operator</div><div></div>
      </div>
      ${runs.map(job=>{
        const js = JOB_STATUS_STYLE[job.status] || ['neutral', job.status];
        return `<div class="panel-row" style="grid-template-columns:70px 110px 1fr 1fr 90px">
          <div class="mono muted">#${job.id}</div>
          <div><span class="badge ${js[0]}">${js[1]}</span></div>
          <div class="mono secondary">${esc(job.ticket_id||'—')}</div>
          <div class="secondary">${esc(job.operator)}</div>
          <div style="text-align:right"><button style="padding:5px 9px;font-size:11px" onclick="openJobProgress(${job.id})">View</button></div>
        </div>`;
      }).join('')}
    </div>`;
}
// Where the machine stands, at a glance; each tile opens its tab.
function renderHostSummary(f){
  const tile = (tab, label, value, sub) => `<div class="host-tile" onclick="setHostTab('${tab}')"><div class="lbl">${label}</div><div class="val">${value}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;
  const u = state.hostUpdates;
  let updates;
  if(f.updates_assessed_ok === false) updates = tile('updates', 'Updates', '<span class="sev none">?</span>', 'couldn’t check');
  else if(!u) updates = tile('updates', 'Updates', '…', '');
  else {
    const by = {};
    u.forEach(x => { by[x.severity || 'unknown'] = (by[x.severity || 'unknown'] || 0) + 1; });
    const chips = SEVERITY_ORDER.filter(s => by[s] && s !== 'none').slice(0, 3).map(s => sevChip(s, by[s])).join(' ');
    updates = tile('updates', 'Updates', u.length ? `${u.length} pending` : '<span style="color:var(--ok)">&#10003; none</span>', chips);
  }
  const c = state.hostContainers;
  const containers = Array.isArray(c) && c.length
    ? tile('containers', 'Containers', `${c.length}`, `${c.filter(x => x.update_available === true).length} outdated`) : '';
  const n = state.hostNetwork;
  let network = '';
  if(n && n.ok !== null){
    const addr = (n.interfaces || []).filter(i => !i.container).flatMap(i => i.addresses || [])[0];
    network = tile('network', 'Network', addr ? `<span class="mono">${esc(addr.split('/')[0])}</span>` : '—',
      `${reachablePortCount(n.listening || [])} listening`);
  }
  const safe = TOPO_SAFE[f.safety_net] || TOPO_SAFE.none;
  return `<div class="host-tiles">
    ${updates}${hostVulnTile()}${containers}${network}
    <div class="host-tile static"><div class="lbl">Checked in</div><div class="val">${esc(fmtLastSeen(f.last_seen))}</div><div class="sub">every ${Math.round((f.poll_interval_seconds || 900) / 60)} min</div></div>
    <div class="host-tile" onclick="setHostTab('snapshots')"><div class="lbl">Safety net</div><div class="val"><span class="topo-safe ${safe.cls}">${safe.t}</span></div><div class="sub">${esc({snapshot:'snapshot before each run', package_history:'package history only', none:'no rollback'}[f.safety_net] || '')}</div></div>
  </div>`;
}

// Right-rail cards ---------------------------------------------------------
// Read-only facts only. The editable overrides (rollback backend, Proxmox
// node) live in the Admin card below, where a full-width control fits —
// putting a <select> in this key/value table forced the value column wider
// than the 320px rail and pushed it off-screen.
function renderHostIdentity(f){
  const backend = f.rollback_backend
    ? rollbackBackendLabel(f.rollback_backend)
    : `Auto (${rollbackBackendLabel((state.settings||{}).rollback_default_backend)})`;
  return `
    <div class="card">
      <p class="card-title">Identity</p>
      <table class="kv-table">
        <tr><td>Operating system</td><td>${esc(f.os_version||f.os_family||'—')}</td></tr>
        <tr><td>Family key</td><td>${esc(f.os_family||'—')}</td></tr>
        <tr><td>Owner</td><td>${esc(f.team||'—')}</td></tr>
        <tr><td>Role / tier</td><td>${esc(f.role||'—')}</td></tr>
        <tr><td>Agent</td><td>${esc(f.agent_version || '—')}${hostAgentUpdate(f)}</td></tr>
        <tr><td>Poll interval</td><td>${f.poll_interval_seconds ? `${f.poll_interval_seconds}s` : '—'}</td></tr>
        <tr><td>Proxmox VM ID</td><td>${f.proxmox_vmid ?? '—'}${f.proxmox_vmid != null && hostConnectionName(f) ? ` <span class="muted">on ${esc(hostConnectionName(f))}</span>` : ''}</td></tr>
        <tr><td>Proxmox node</td><td>${esc(f.proxmox_node || 'Auto (cluster)')}</td></tr>
        <tr><td>Rollback</td><td>${esc(backend)}</td></tr>
      </table>
    </div>`;
}
// Evidence: the two questions an operator actually has — when did we last
// LOOK at this host, and when did we last ACT on it — kept distinct.
function renderHostEvidence(f){
  const patchedAge = daysSince(f.last_patched);
  const checkFailed = f.updates_assessed_ok === false;
  return `
    <div class="card">
      <p class="card-title">Evidence</p>
      <div style="display:flex;gap:9px;align-items:flex-start;padding-bottom:9px;border-bottom:1px solid var(--border)">
        <span class="stage-icon ${checkFailed?'failed':'done'}" style="width:16px;height:16px">${checkFailed?'&#10007;':'&#10003;'}</span>
        <div><div style="font-weight:600;font-size:12px">${f.last_seen?`Checked ${fmtLastSeen(f.last_seen)}`:'Never checked in'}</div>
          <div style="font-size:10.5px;color:var(--text-muted)">${checkFailed?"last inventory couldn't be assessed":'agent reported inventory'}</div></div>
      </div>
      <div style="display:flex;gap:9px;align-items:flex-start;padding-top:9px">
        <span class="stage-icon waiting" style="width:16px;height:16px;border-style:solid;border-color:var(--border-strong);color:var(--text-secondary)">&#8635;</span>
        <div><div style="font-weight:600;font-size:12px">${f.last_patched?`Patched ${fmtDate(f.last_patched)}`:'Never patched'}${patchedAge!==null?` · ${patchedAge}d ago`:''}</div>
          <div style="font-size:10.5px;color:var(--text-muted)">${patchedAge!==null && patchedAge>30?'overdue — over 30 days':'last completed patch run'}</div></div>
      </div>
    </div>`;
}
function renderHostFamilyScripts(f){
  const fs = state.hostDetail ? state.hostDetail.familyScripts : undefined;
  const canManage = atLeast(state.user.role, 'admin');
  const mine = groupsOf(f);
  let body;
  if(!f.os_family && !mine.length) body = `<p class="card-help" style="margin:0">OS family not reported yet.</p>`;
  else if(fs === undefined || fs === null) body = `<p class="card-help" style="margin:0">Checking…</p>`;
  else if(fs.length === 0) body = `<p class="card-help" style="margin:0">Using the built-in agent defaults for every stage.</p>`;
  else body = fs.map(s => `
      <div style="display:flex;align-items:center;gap:7px;font-size:11.5px;padding:3px 0">
        <span class="g mono" style="color:${s.tested?'var(--ok)':'var(--due)'};font-size:10px">${s.tested?'&#10003;':'&#9679;'}</span>
        <span class="mono" style="font-size:11px">${esc(stageLabels[s.stage_name]||s.stage_name)}</span>
        <span class="grow"></span>
        <span class="secondary" style="font-size:10.5px">${groupByName(s.os_family) ? `group ${esc(s.os_family)}` : esc(s.os_family)} · ${s.tested?'tested':'untested'}</span>
      </div>`).join('');
  const home = scriptHomeFor(f, fs);
  return `
    <div class="card">
      <p class="card-title">Scripts for this machine</p>
      ${mine.length ? `<p class="card-help" style="margin:0 0 6px">Groups: ${mine.map(g => `<span class="mono">${esc(g.name)}</span>`).join(', ')}</p>` : ''}
      ${body}
      ${canManage && home ? `<a href="#" onclick="openScriptsFor('${jsq(home)}');return false" style="font-size:11.5px;display:inline-block;margin-top:9px">Manage ${groupByName(home) ? `group ${esc(home)}` : `${esc(home)} scripts`} &rarr;</a>` : ''}
    </div>`;
}
function openScriptsFor(name){ state.scriptsFamily = name; state.scriptsPick = []; state.scriptsPickQ = ''; navigate('scripts'); }
function renderHostAdminActions(f, canDelete, canEnroll){
  if(!canDelete && !canEnroll) return '';
  return `
    <div class="card">
      <p class="card-title">Admin</p>
      ${canEnroll ? `
        <div style="margin-bottom:11px">
          <div class="host-admin-lbl">Rollback backend</div>
          <select style="width:100%" onchange="updateHostRollbackBackend(${f.id}, this.value)">
            <option value="" ${!f.rollback_backend?'selected':''}>Auto (${esc(rollbackBackendLabel((state.settings||{}).rollback_default_backend))})</option>
            ${ROLLBACK_BACKENDS.map(b=>`<option value="${b.id}" ${f.rollback_backend===b.id?'selected':''}>${esc(b.label)}</option>`).join('')}
          </select>
        </div>
        ${(state.pmConnections || []).length > 1 ? `
        <div style="margin-bottom:11px">
          <div class="host-admin-lbl">Proxmox connection</div>
          <select style="width:100%" onchange="updateHostConnection(${f.id}, this.value)">
            <option value="" ${f.proxmox_connection_id == null ? 'selected' : ''}>Not chosen</option>
            ${state.pmConnections.map(c => `<option value="${c.id}" ${f.proxmox_connection_id === c.id ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}
          </select>
        </div>` : ''}
        <div style="margin-bottom:11px">
          <div class="host-admin-lbl">Groups</div>
          <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:6px">
            ${groupsOf(f).map(g => `<span class="badge neutral" style="gap:4px">${esc(g.name)}<a href="#" title="Take it out of ${esc(g.name)}" onclick="removeFromGroup(${g.id}, [${f.id}]);return false" style="text-decoration:none">✕</a></span>`).join('') || '<span class="secondary" style="font-size:11.5px">In no group</span>'}
          </div>
          ${(state.groups || []).some(g => !(f.group_ids||[]).includes(g.id)) ? `<select style="width:100%" onchange="if(this.value) addToGroup(+this.value, [${f.id}])">
            <option value="">Add to a group…</option>
            ${(state.groups || []).filter(g => !(f.group_ids||[]).includes(g.id)).map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('')}
          </select>` : ''}
        </div>
        <div style="margin-bottom:11px">
          <div class="host-admin-lbl">Proxmox node</div>
          <div style="display:flex;gap:6px">
            <input id="host-proxmox-node" value="${esc(f.proxmox_node||'')}" placeholder="auto" style="flex:1;min-width:0">
            <button style="flex:none" onclick="updateHostProxmoxNode(${f.id})">Save</button>
          </div>
        </div>` : ''}
      <div style="display:flex;flex-direction:column;gap:8px">
        ${!f.proxmox_vmid && f.smbios_uuid && canEnroll ? `<button onclick="resolveVmid(${f.id})">Retry Proxmox VMID match</button>` : ''}
        ${canDelete ? `<button class="danger-ghost" ${hostRemovable(f)?'':'disabled'} title="${hostRemovable(f)?'Remove this machine from kite':'It has a run in progress — remove it once the run ends'}" onclick="deleteHost(${f.id})">Remove from fleet</button>` : ''}
      </div>
    </div>`;
}
function renderHostUpdates(){
  const list = state.hostUpdates;
  const host = state.hostDetail && state.hostDetail.host;
  // Explicitly false means the host's package manager could not be
  // queried. An empty list then means "unknown", not "fully patched",
  // and saying the latter would be worse than saying nothing.
  if(host && host.updates_assessed_ok === false){
    return `
      <p class="card-title">Pending updates</p>
      <div class="banner warning" style="margin-bottom:20px">
        This host's package manager could not be queried, so what's pending is unknown.
        A single unreachable repository is enough to cause this.
        ${host.updates_error
          ? `<div class="mono" style="margin-top:8px;font-size:11.5px;white-space:pre-wrap">${esc(host.updates_error)}</div>`
          : `Check the agent log on the host — it reported no reason.`}
      </div>`;
  }
  if(list === null || list === undefined) return '';
  if(!list.length){
    return `<p class="card-title">Pending updates</p>
      <div class="banner success" style="margin-bottom:20px">No pending updates reported.</div>`;
  }
  return `
    <p class="card-title">Pending updates</p>
    <p class="card-help">
      ${list.length} available across ${sourceCount(list)}, most severe first. Operating-system
      updates come from the host's own package manager (dnf/apt/Windows Update); third-party apps
      come from their own manager (winget, Flatpak, Snap), which is named on each group.
    </p>
    ${orderedSources(list).map(src => renderUpdateSource(src, list.filter(u => (u.source || 'os') === src))).join('')}`;
}

// The sources a host can report, in the order they are shown: the OS
// first (it is what "is this host patched" has always meant), then the
// third-party managers. Only sources actually present in the list appear.
const SOURCE_ORDER = ['os', 'winget', 'flatpak', 'snap'];
const SOURCE_LABELS = {
  os: 'Operating system',
  winget: 'Windows apps · winget',
  flatpak: 'Flatpak apps',
  snap: 'Snap packages',
};

function orderedSources(list){
  const present = new Set(list.map(u => u.source || 'os'));
  const known = SOURCE_ORDER.filter(s => present.has(s));
  // Any source the agent introduces that the console does not yet name is
  // still shown, appended, rather than silently dropped.
  const extra = [...present].filter(s => !SOURCE_ORDER.includes(s)).sort();
  return [...known, ...extra];
}

function sourceCount(list){
  const n = orderedSources(list).length;
  return n === 1 ? '1 source' : `${n} sources`;
}

function renderUpdateSource(src, rows){
  const label = SOURCE_LABELS[src] || src;
  // The ten most severe, until asked for the rest (the list comes most severe first).
  const all = !!(state.hostUpdatesAll || {})[src];
  const shown = rows.slice(0, all ? 500 : 10);
  // Third-party managers report the installed version, so their group
  // shows "current → available"; the OS managers report only the target,
  // so that column would be empty noise and is dropped for them.
  const hasCurrent = rows.some(u => u.current_version);
  const cols = hasCurrent ? '1.4fr 1.6fr 1fr 130px' : '1.2fr 1.4fr 1fr 130px';
  const versionHead = hasCurrent ? 'Current → available' : 'New version';
  const advisoryHead = src === 'os' ? 'Advisory' : 'Package id';
  return `
    <div style="margin-bottom:8px;margin-top:14px;font-weight:600">${esc(label)}
      <span class="secondary" style="font-weight:400">· ${rows.length}</span></div>
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-head" style="grid-template-columns:${cols}">
        <div>${src === 'os' ? 'Package' : 'App'}</div><div>${versionHead}</div><div>${advisoryHead}</div><div></div>
      </div>
      ${shown.map(u=>`
        <div class="panel-row" style="grid-template-columns:${cols}">
          <div class="mono">${esc(u.package)}</div>
          <div class="mono secondary">${hasCurrent
            ? `${esc(u.current_version || '?')} → ${esc(u.new_version || '—')}`
            : esc(u.new_version || '—')}</div>
          <div class="mono secondary">${esc(u.advisory || '—')}</div>
          <div style="text-align:right">${severityBadge(u.severity)}</div>
        </div>`).join('')}
      ${rows.length > 10 ? `<div class="pager"><a href="#" onclick="state.hostUpdatesAll={...(state.hostUpdatesAll||{}), '${jsq(src)}': ${!all}};render();return false">${all ? 'Show the 10 most severe' : `Show all ${rows.length}`}</a>${rows.length > shown.length ? `<span class="grow"></span><span>${rows.length - shown.length} more not shown</span>` : ''}</div>` : ''}
    </div>`;
}
function containerStatusBadge(c){
  // Three distinct answers, never two. "Not determined" is its own
  // outcome — the registry could not be read, so claiming the image is
  // current would be asserting something never checked.
  if(c.pinned) return '<span class="badge neutral" title="Digest-pinned; cannot drift">pinned</span>';
  if(c.update_available === true) return '<span class="badge danger">update available</span>';
  if(c.update_available === false) return '<span class="badge success">up to date</span>';
  return '<span class="badge warning" title="Registry unreachable or private, or a locally built image">not determined</span>';
}
function renderHostNetwork(){
  const n = state.hostNetwork;
  if(!n) return '';
  const head = `<p class="card-title" style="margin-top:22px">Network</p>`;
  if(n.ok === null) return `${head}<div class="banner neutral">Not reported by this host's agent.</div>`;
  const stale = n.ok === false
    ? `<div class="banner warning" style="margin-bottom:10px">The last report couldn't read the network (${esc(n.error || 'no reason given')}). Showing what was known before.</div>` : '';
  const ifaces = n.interfaces.filter(i => !i.container || state.hostShowContainerIfaces);
  const hidden = n.interfaces.length - ifaces.length;
  const exposed = n.listening.filter(p => !p.loopback), local = n.listening.filter(p => p.loopback);
  return `${head}
    <p class="card-help">Reported by this host's agent${n.reported_at ? `, ${relTime(n.reported_at)}` : ''}. The VLAN comes from the Proxmox NIC with the same MAC. <em>Listening</em> means a process accepts connections there — a firewall may still block it.</p>
    ${stale}
    <div class="panel" style="margin-bottom:12px">
      <div class="panel-head" style="grid-template-columns:110px 1.4fr 150px 1.2fr 70px"><div>Interface</div><div>Addresses</div><div>MAC</div><div>Network</div><div>State</div></div>
      ${ifaces.map(i => `
        <div class="panel-row" style="grid-template-columns:110px 1.4fr 150px 1.2fr 70px">
          <div class="mono">${esc(i.name)}${i.kind ? ` <span class="muted" style="font-size:10.5px">${esc(i.kind)}</span>` : ''}</div>
          <div class="mono" style="font-size:12px">${i.addresses.length ? i.addresses.map(esc).join('<br>') : '<span class="muted">—</span>'}</div>
          <div class="mono secondary" style="font-size:11px">${esc(i.mac || '—')}</div>
          <div style="font-size:12px">${i.proxmox ? `${i.proxmox.vlan_id != null ? `<strong>VLAN ${i.proxmox.vlan_id}</strong>` : 'untagged'} <span class="mono muted">${esc(i.proxmox.bridge)} &middot; ${esc(i.proxmox.proxmox_iface)}</span>` : '<span class="muted">not a Proxmox NIC</span>'}</div>
          <div>${i.up ? '<span class="badge success">up</span>' : '<span class="badge neutral">down</span>'}</div>
        </div>`).join('') || '<div class="section-empty">No interfaces with addresses.</div>'}
      ${hidden || state.hostShowContainerIfaces ? `<div class="pager"><a href="#" onclick="state.hostShowContainerIfaces=!state.hostShowContainerIfaces;render();return false">${state.hostShowContainerIfaces ? 'Hide' : `Show ${hidden}`} container interface${hidden===1?'':'s'}</a>${n.default_gateway ? `<span class="grow"></span><span>gateway ${esc(n.default_gateway)}</span>` : ''}</div>`
        : n.default_gateway ? `<div class="pager"><span>gateway ${esc(n.default_gateway)}</span></div>` : ''}
    </div>
    ${state.hostPortsTable ? '' : renderHostPortChips(exposed, local)}
    <div class="panel" ${state.hostPortsTable ? '' : 'style="display:none"'}>
      <div class="panel-head" style="grid-template-columns:60px 70px 1.2fr 1fr 110px"><div>Proto</div><div>Port</div><div>Bound to</div><div>Process</div><div>First seen</div></div>
      ${exposed.map(p => `
        <div class="panel-row" style="grid-template-columns:60px 70px 1.2fr 1fr 110px">
          <div class="mono secondary">${esc(p.proto)}</div>
          <div class="mono" style="font-weight:600">${p.port}</div>
          <div class="mono" style="font-size:12px">${p.address === '0.0.0.0' || p.address === '::' ? `${esc(p.address)} <span class="muted">every interface</span>` : esc(p.address)}</div>
          <div class="mono secondary" style="font-size:12px">${esc(p.process || '—')}</div>
          <div class="mono secondary" style="font-size:11px" title="${fmtTs(p.first_seen)} UTC">${relTime(p.first_seen)}</div>
        </div>`).join('') || '<div class="section-empty">Nothing listening beyond loopback.</div>'}
      ${local.length ? `<div class="pager"><span>${local.length} more listening on loopback only (${local.slice(0, 6).map(p => `${esc(p.proto)}/${p.port}`).join(', ')}${local.length > 6 ? ', …' : ''}) — not reachable from the network</span></div>` : ''}
      <div class="pager"><a href="#" onclick="state.hostPortsTable=false;render();return false">Compact view</a></div>
    </div>`;
}
// Listening ports as one line of chips per address they're bound to,
// instead of a table row each; the table is one click away.
function renderHostPortChips(exposed, local){
  const groups = {};
  exposed.forEach(p => { const k = p.address === '0.0.0.0' || p.address === '::' ? '*' : p.address; (groups[k] = groups[k] || []).push(p); });
  const keys = Object.keys(groups).sort((a, b) => (a === '*' ? -1 : b === '*' ? 1 : a.localeCompare(b)));
  const seen = new Set();
  const chip = p => {
    const k = `${p.proto}/${p.port}/${p.process}`;
    if(seen.has(k)) return '';   // IPv4 and IPv6 "every interface" twice over
    seen.add(k);
    return `<span class="topo-port" title="${esc(p.address)}${p.first_seen ? ` · first seen ${fmtTs(p.first_seen)} UTC` : ''}">${esc(p.proto)}/${p.port}${p.process ? ` <span class="muted">${esc(p.process)}</span>` : ''}</span>`;
  };
  return `<div class="panel host-ports">
    ${keys.length ? keys.map(k => `<div class="host-ports-row"><span class="host-ports-addr mono">${k === '*' ? 'every interface' : esc(k)}</span><span class="topo-ports">${groups[k].sort((a, b) => a.port - b.port).map(chip).join('')}</span></div>`).join('')
      : '<div class="section-empty">Nothing listening beyond loopback.</div>'}
    <div class="pager">${local.length ? `<span>+${local.length} on loopback only</span><span class="grow"></span>` : ''}<a href="#" onclick="state.hostPortsTable=true;render();return false">Details</a></div>
  </div>`;
}
function renderHostContainers(){
  const list = state.hostContainers;
  if(list === null || list === undefined) return '';   // not fetched yet
  if(!list.length) return '';                          // nothing to say
  const managed = {
    compose: ['neutral', 'compose'],
    standalone: ['warning', 'standalone'],
    kubernetes: ['info', 'kubernetes'],
    swarm: ['info', 'swarm'],
    nomad: ['info', 'nomad'],
  };
  return `
    <p class="card-title">Containers</p>
    <p class="card-help">
      Reported by this host's agent. Compose services can be updated by a
      run; standalone and orchestrated containers are shown but never
      touched, because neither can be recreated safely. Each update first
      captures the image it replaces, so exactly one rollback point is
      kept per service.
    </p>
    <div class="panel" style="margin-bottom:20px">
      <div class="panel-head" style="grid-template-columns:1fr 1.4fr 95px 115px 140px 110px">
        <div>Name</div><div>Image</div><div>State</div><div>Managed by</div><div></div><div></div>
      </div>
      ${list.map(c=>{
        const m = managed[c.managed_by] || ['neutral', c.managed_by || 'unknown'];
        return `<div class="panel-row" style="grid-template-columns:1fr 1.4fr 95px 115px 140px 110px">
          <div class="mono">${esc(c.name)}</div>
          <div class="mono secondary" title="${esc(c.image)}">${esc(c.image)}</div>
          <div class="secondary">${esc(c.state || '—')}</div>
          <div><span class="badge ${m[0]}">${esc(m[1])}</span>${c.compose_project ? `<div class="dash-row-meta">${esc(c.compose_project)}</div>` : ''}</div>
          <div style="text-align:right">${containerStatusBadge(c)}</div>
          <div style="text-align:right">${c.rollback_available && atLeast(state.user.role, 'operator')
            ? `<button style="padding:4px 9px;font-size:11px" title="Restore the image captured before the last update${c.rollback_captured_at ? ` (${fmtTs(c.rollback_captured_at)})` : ''}" onclick="rollbackContainerHandler(${state.hostDetail.host.id},'${jsq(c.name)}')">Roll back</button>`
            : `<span class="dash-row-meta">${c.rollback_available ? 'capture held' : 'no capture'}</span>`}</div>
        </div>`;
      }).join('')}
    </div>`;
}
async function rollbackContainerHandler(hostId, name){
  // A rollback is a run like any other: when runs need a ticket, so does this.
  const ticketFields = requireTicket() ? [
    {id: 'ticket_id', label: 'Ticket', placeholder: 'an approved ticket, e.g. CHG-1234', required: true},
    {id: 'window_override_reason', label: "Reason, if outside the ticket's window (lead or admin)",
     placeholder: 'leave empty inside the window'},
  ] : [];
  const ok = await confirmDialog({
    title: `Roll back ${name}?`,
    message: `This recreates ${name} on the image captured before its last update.\n\n`
           + `Data written into volumes is NOT rolled back — if the newer image migrated `
           + `anything on disk, restoring the image does not undo that.`,
    confirmLabel: 'Roll back', danger: true, inputs: ticketFields,
  });
  if(!ok) return;
  const ticket = ok === true ? {} : {ticket_id: ok.ticket_id, window_override_reason: ok.window_override_reason || null};
  try{
    const job = await api.rollbackContainer(hostId, name, ticket);
    toast(`Rollback started for ${name}.`, 'warning');
    openJobProgress(job.id);
  }catch(e){
    toast(e.message, 'danger');
  }
}
// The enrol commands. With the default self-signed setup the controller
// publishes its root CA (app/controller_ca.py), and the commands check
// it against the fingerprint shown here before trusting anything: each
// step is chained with &&, so a mismatch stops everything after it.
// Without one (a public certificate needs none; Docker without
// KITE_CA_CERT has none) they turn certificate checks off as before.
const CA_TMP = '/tmp/kite-ca.crt';
const CA_PATH = '/etc/kite/controller-ca.crt';
function controllerCaFingerprint(){
  return state.controllerCa && state.controllerCa.available ? state.controllerCa.sha256 : '';
}
function caCheckSteps(base, fp){
  return [
    `curl -fsSk ${base}/download/ca.crt -o ${CA_TMP}`,
    `test "$(openssl x509 -in ${CA_TMP} -outform DER | sha256sum | cut -d' ' -f1)" = "${fp}"`,
  ];
}
function enrollCommand(platform, r){
  const base = `${window.location.protocol}//${window.location.host}`;
  const fp = controllerCaFingerprint();
  if(platform === 'windows'){
    // Downloads the installer and runs it silently. One file, and the
    // same code path the wizard takes -- an unattended install cannot
    // drift from an interactive one. With a fingerprint, the agent checks
    // the controller's CA against it and pins it before enrolling.
    return [
      fp ? `# PowerShell accepts the controller's self-signed certificate for this`
         : `# The controller uses a self-signed certificate by default, so these`,
      fp ? `# download only; the agent itself checks the controller's CA against`
         : `# two lines let PowerShell accept it and the agent is installed with`,
      fp ? `# its fingerprint (/ca-fingerprint) and trusts nothing else from then on.`
         : `# /insecure. If you've given the controller a real (Let's Encrypt)`,
      ...(fp ? [] : [`# certificate, remove both lines and the /insecure flag.`]),
      `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`,
      `[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`,
      ``,
      `$setup = "$env:TEMP\\kite-agent-setup.exe"`,
      `Invoke-WebRequest -Uri "${base}/download/installer/windows" -OutFile $setup`,
      ``,
      `& $setup /S /controller=${base} /token=${r.token} ${fp ? `/ca-fingerprint=${fp}` : '/insecure'}`,
    ].join('\n');
  }
  if(platform === 'debian'){
    // Fetches the agent bundle from THIS controller rather than cloning
    // the repository — no GitHub, and it works while the repo is private.
    // install-debian.sh lays the files down; enrol is a second step.
    if(fp){
      return [
        ...caCheckSteps(base, fp),
        `curl -fsSL --cacert ${CA_TMP} ${base}/download/agent-linux -o /tmp/kite-agent.tar.gz`,
        `mkdir -p /tmp/kite-agent && tar xzf /tmp/kite-agent.tar.gz -C /tmp/kite-agent`,
        `(cd /tmp/kite-agent/agent-linux && sudo bash install-debian.sh)`,
        `sudo python3 /opt/kite-agent/enroll.py --controller ${base} --token ${r.token} --ca-cert ${CA_TMP}`,
        `sudo systemctl enable --now kite-agent`,
      ].join(' && \\\n');
    }
    // The -k / --insecure accept the controller's self-signed cert
    // unchecked; this controller publishes no CA to check it against.
    return [
      `curl -fsSLk ${base}/download/agent-linux -o /tmp/kite-agent.tar.gz`,
      `mkdir -p /tmp/kite-agent && tar xzf /tmp/kite-agent.tar.gz -C /tmp/kite-agent`,
      `cd /tmp/kite-agent/agent-linux && sudo bash install-debian.sh`,
      ``,
      `sudo python3 /opt/kite-agent/enroll.py --controller ${base} --token ${r.token} --insecure`,
      `sudo systemctl enable --now kite-agent`,
    ].join('\n');
  }
  // skip_if_unavailable=1 matters more than it looks. Without it dnf
  // treats an unreachable repository as a hard error, so a controller
  // that is down would break EVERY dnf command on every managed host --
  // `dnf update` included. The tool meant to keep these hosts patched
  // would be the reason they could not be.
  // A signed repo (app/repo_signing.py) is checked package by package and
  // index by index. dnf -y imports the key on first install.
  const repo = (Array.isArray(state.agentDownloads) ? state.agentDownloads : []).find(d => d.platform === 'rhel');
  const check = repo && repo.signed
    ? `gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=${base}/repo/RPM-GPG-KEY-kite`
    : 'gpgcheck=0';
  const repoFile = tls => `[kite]\nname=kite agent\nbaseurl=${base}/repo\nenabled=1\n${check}\n${tls}\nskip_if_unavailable=1\nmetadata_expire=300\nEOF`;
  if(fp){
    // The repo file goes in after the CA has been checked and installed,
    // and dnf checks the controller's certificate against it.
    return [
      ...caCheckSteps(base, fp),
      `sudo install -D -m 644 ${CA_TMP} ${CA_PATH}`,
      `sudo tee /etc/yum.repos.d/kite.repo >/dev/null << 'EOF' && \\\n`
        + `sudo KITE_CONTROLLER=${base} KITE_TOKEN=${r.token} KITE_CA_CERT=${CA_PATH} dnf install -y kite-agent\n`
        + repoFile(`sslverify=1\nsslcacert=${CA_PATH}`),
    ].join(' && \\\n');
  }
  // sslverify=0 (repo) and KITE_INSECURE=1 (enrol) accept the
  // controller's self-signed cert unchecked: it publishes no CA to pin.
  return `sudo tee /etc/yum.repos.d/kite.repo << 'EOF'\n${repoFile('sslverify=0')}\n\nsudo KITE_CONTROLLER=${base} KITE_TOKEN=${r.token} KITE_INSECURE=1 dnf install -y kite-agent`;
}
function copyTextToClipboard(text){
  if(navigator.clipboard && window.isSecureContext){
    return navigator.clipboard.writeText(text);
  }
  // navigator.clipboard is only exposed in secure contexts (https:// or
  // localhost) — this app is commonly reached over plain http:// on a
  // LAN address, where it's undefined. Fall back to the older
  // execCommand path via a hidden textarea in that case.
  return new Promise((resolve, reject) => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try{
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error('execCommand copy failed'));
    }catch(e){
      document.body.removeChild(ta);
      reject(e);
    }
  });
}
function copyEnrollCmd(btn){
  const text = document.getElementById('enroll-cmd').textContent;
  copyTextToClipboard(text).then(()=>{
    const original = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(()=>{ btn.textContent = original; }, 1500);
  }).catch(()=>{
    toast('Could not copy automatically — select the command text and copy manually.', 'warning');
  });
}
async function deleteHost(id){
  const f = (state.hostDetail && state.hostDetail.host && state.hostDetail.host.id === id ? state.hostDetail.host : null)
    || (state.fleet || []).find(h => h.id === id);
  if(!f) return;
  const hostname = f.hostname;
  const ok = await confirmDialog({
    title: 'Remove host',
    message: removeHostsMessage([f]),
    confirmLabel: 'Remove', danger: true,
  });
  if(!ok) return;
  try{ await api.deleteHost(id); await loadFleet(); if(state.hostDetailId === id){ state.hostDetailId = null; navigate('fleet'); } toast(`${hostname} removed from the fleet.`, 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function resolveVmid(id){
  try{ await api.resolveVmid(id); await Promise.all([loadFleet(), openHostDetail(id)]); toast('VM ID resolved.', 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function updateHostRollbackBackend(id, value){
  try{
    await api.patchHost(id, {rollback_backend: value});
    await openHostDetail(id);
    toast(value ? `Rollback backend set to ${rollbackBackendLabel(value)}.` : 'Rollback backend override cleared — using the default.', 'success');
  }catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
// Which connection the machine's VM id is on. Only asked when there are
// several -- the same VM id can exist on each.
function hostConnectionName(f){
  const c = (state.pmConnections || []).find(x => x.id === f.proxmox_connection_id);
  return c && (state.pmConnections || []).length > 1 ? c.name : '';
}
async function updateHostConnection(id, value){
  try{
    await api.patchHost(id, {proxmox_connection_id: value === '' ? null : +value});
    await openHostDetail(id);
    toast('Proxmox connection updated.', 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function updateHostProxmoxNode(id){
  const value = document.getElementById('host-proxmox-node').value.trim();
  try{
    await api.patchHost(id, {proxmox_node: value});
    await openHostDetail(id);
    toast(value ? `Proxmox node pinned to ${value}.` : 'Proxmox node override cleared — resolved automatically at snapshot time.', 'success');
  }catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
/* ---------- software ---------- */
// Everything installed, as the agent last reported it: what
// vulnerability matching works from.
async function loadHostSoftware(id){
  try{ const s = await api.hostSoftware(id); if(state.hostDetailId === id){ state.hostSoftware = s; render(); } }
  catch(e){ hostLoadFailed(id, 'software', e); }
}
const SOFTWARE_KINDS = {
  rpm: 'Packages (rpm)', deb: 'Packages (deb)', snap: 'Snap', flatpak: 'Flatpak',
  app: 'Programs', kb: 'Installed updates', os: 'Operating system',
};
function liveHostSoftwareSearch(input){
  const pos = input.selectionStart;
  state.hostSoftwareQ = input.value;
  render();
  const el = document.getElementById('host-software-q');
  if(el){ el.focus(); el.setSelectionRange(pos, pos); }
}
function renderHostSoftware(){
  const S = state.hostSoftware;
  if(!S) return '<div class="banner neutral">Loading…</div>';
  if(!S.reported_at) return '<div class="banner neutral">Not reported yet; it arrives with the next check-in from this machine.</div>';
  const q = state.hostSoftwareQ.trim().toLowerCase();
  const items = S.items.filter(i => !q || `${i.name} ${i.version} ${i.publisher} ${i.source_name}`.toLowerCase().includes(q));
  const counts = {};
  S.items.forEach(i => { counts[i.kind] = (counts[i.kind] || 0) + 1; });
  const groups = Object.keys(SOFTWARE_KINDS).filter(k => items.some(i => i.kind === k));
  const LIMIT = 200;
  return `
    <p class="card-help" style="margin-top:0">${S.items.length} installed, reported ${esc(relTime(S.reported_at))}: ${Object.keys(SOFTWARE_KINDS).filter(k => counts[k]).map(k => `${counts[k]} ${esc(SOFTWARE_KINDS[k].toLowerCase())}`).join(' · ')}.</p>
    <label class="fleet-search" style="margin-bottom:12px"><span style="width:11px;height:11px;border:1.5px solid var(--text-faint);border-radius:50%;flex:none"></span>
      <input id="host-software-q" placeholder="Find a package, program or publisher" value="${esc(state.hostSoftwareQ)}" oninput="liveHostSoftwareSearch(this)">
      <span class="count">${items.length} match${items.length===1?'':'es'}</span></label>
    ${groups.map(k => {
      const rows = items.filter(i => i.kind === k);
      return `<div style="font-weight:600;margin:12px 0 6px">${esc(SOFTWARE_KINDS[k])} <span class="secondary" style="font-weight:400">· ${rows.length}</span></div>
        <div class="panel">
          <div class="panel-head" style="grid-template-columns:1.6fr 1.2fr 1.2fr"><div>Name</div><div>Version</div><div>${k === 'rpm' || k === 'deb' ? 'Source package' : 'Publisher'}</div></div>
          ${rows.slice(0, LIMIT).map(i => `<div class="panel-row" style="grid-template-columns:1.6fr 1.2fr 1.2fr">
            <div class="mono" style="overflow-wrap:anywhere">${esc(i.name)}${i.arch && i.arch !== 'noarch' ? ` <span class="muted" style="font-size:10.5px">${esc(i.arch)}</span>` : ''}</div>
            <div class="mono secondary" style="overflow-wrap:anywhere">${esc(i.version || '—')}</div>
            <div class="secondary" style="overflow-wrap:anywhere;font-size:12px">${esc(k === 'rpm' || k === 'deb' ? (i.source_name && i.source_name !== i.name ? i.source_name : '—') : (i.publisher || '—'))}</div>
          </div>`).join('')}
          ${rows.length > LIMIT ? `<div class="pager"><span>${rows.length - LIMIT} more — narrow it with the search box</span></div>` : ''}
        </div>`;
    }).join('') || '<div class="section-empty">Nothing matches.</div>'}`;
}

/* ---------- snapshots ---------- */
// kite's own Proxmox snapshots of this VM, newest first, and what the
// cleanup policy will do with each (app/snapshot_retention.py).
async function loadHostSnapshots(id){
  try{ const s = await api.hostSnapshots(id); if(state.hostDetailId === id){ state.hostSnapshots = s; render(); } }
  catch(e){ hostLoadFailed(id, 'snapshots', e); }
}
// A tab whose data couldn't be fetched says so, instead of "Loading…" forever.
function hostLoadFailed(id, tab, e){
  if(state.hostDetailId !== id) return;
  state.hostLoadErrors = Object.assign({}, state.hostLoadErrors, {[tab]: e.message});
  render();
}
function renderHostSnapshots(){
  const S = state.hostSnapshots, id = state.hostDetailId;
  if(!S) return '';
  const p = S.policy, canAct = atLeast(state.user.role, 'lead'), isAdmin = atLeast(state.user.role, 'admin');
  const rule = !p.enabled ? 'Automatic cleanup is off — every snapshot is kept.'
    : `Keeps the newest ${p.keep_count || 'any number'}${p.keep_days ? `, none older than ${p.keep_days} day${p.keep_days===1?'':'s'}` : ''}. Snapshots from failed or stopped runs, and ones marked Keep, are never removed.`;
  const head = `<p class="card-title" style="margin-top:22px">Snapshots</p><p class="card-help" style="margin-top:-4px">${rule}${atLeast(state.user.role, 'admin') ? ' <a href="#" onclick="setSettingsTab(\'policy\');navigate(\'settings\');return false">Change</a>' : ''}</p>`;
  if(S.error) return `${head}<div class="banner neutral">Couldn't read them: ${esc(S.error)}</div>`;
  if(!S.snapshots.length) return `${head}<div class="banner neutral">No snapshots taken by kite on this VM. Ones you made yourself aren't listed or touched.</div>`;
  return `${head}<div class="panel">${S.snapshots.map(s => `
    <div class="snap-row ${s.remove ? 'going' : ''}">
      <span class="mono" style="font-weight:600">${esc(s.name)}</span>
      <a href="#" class="mono" style="font-size:11.5px" onclick="openJobProgress(${s.job_id});return false">run ${s.job_id}</a>
      <span class="muted" style="font-size:12px">${esc(relTime(s.taken_at))}</span>
      <span class="grow"></span>
      <span class="${s.remove ? 'snap-going' : 'muted'}" style="font-size:12px">${s.remove ? 'removed at the next cleanup — ' : 'kept: '}${esc(s.reason)}</span>
      ${canAct && !['queued','running'].includes(s.job_status) ? `
        <button class="topo-mini" onclick="keepSnapshot(${id},'${jsq(s.name)}',${!s.kept})">${s.kept ? 'Unkeep' : 'Keep'}</button>
        <button class="topo-mini" onclick="deleteSnapshotNow(${id},'${jsq(s.name)}')">Delete now</button>` : ''}
      ${isAdmin && !['queued','running'].includes(s.job_status) ? `<button class="topo-mini" style="color:var(--danger);border-color:var(--danger)" onclick="restoreSnapshot(${id},'${jsq(s.name)}')">Restore</button>` : ''}
    </div>`).join('')}</div>
    ${isAdmin ? '<p class="card-help" style="margin-top:8px">Restore puts the VM\'s disks back to that snapshot: everything written since is lost. The VM is started again if it was running.</p>' : ''}`;
}
async function keepSnapshot(id, name, keep){
  try{ await api.keepSnapshot(id, name, keep); toast(keep ? `${name} will be kept.` : `${name} follows the cleanup rule again.`, 'success'); loadHostSnapshots(id); }
  catch(e){ toast(e.message, 'danger'); }
}
async function deleteSnapshotNow(id, name){
  const ok = await confirmDialog({title: 'Delete snapshot', confirmLabel: 'Delete', danger: true,
    message: `Delete ${name} in Proxmox? There's no undoing it, and it's this run's way back.`});
  if(!ok) return;
  try{ await api.deleteSnapshot(id, name); toast(`Deleting ${name} in Proxmox.`, 'success'); setTimeout(() => loadHostSnapshots(id), 3000); }
  catch(e){ toast(e.message, 'danger'); }
}

// Roll the VM back to a snapshot. Admin-only and typed-confirmed on both
// sides: it throws away everything the machine did since.
async function restoreSnapshot(id, name){
  let host = (state.hostDetail && state.hostDetail.host && state.hostDetail.host.id === id) ? state.hostDetail.host
    : (state.fleet || []).find(f => f.id === id);
  if(!host){
    try{ host = await api.getHost(id); }catch(e){ toast(e.message, 'danger'); return; }
  }
  const ok = await confirmDialog({title: `Restore ${host.hostname} to ${name}?`, confirmLabel: 'Restore', danger: true,
    typeToConfirm: host.hostname,
    message: `The VM's disks go back to the moment this snapshot was taken. Everything written on ${host.hostname} since — updates, data, logs — is lost. The VM restarts if it was running.`});
  if(!ok) return;
  toast(`Restoring ${host.hostname}… this can take a few minutes.`, 'neutral', 8000);
  try{
    const r = await api.restoreSnapshot(id, name, host.hostname);
    toast(r.note || `${host.hostname} restored to ${name}${r.started ? ' and started again' : ''}.`, r.note ? 'warning' : 'success');
    if(state.nav === 'host' && state.hostDetailId === id) openHostDetail(id);
  }catch(e){ toast(e.message, 'danger'); }
}

/* ---------- agent updates ---------- */
// Agents update themselves on their next idle check-in once a target is
// set (GET/POST /agents/updates); nobody has to log in to the host.
function hostAgentUpdate(f){
  const U = state.agentUpdates;
  const row = U && U.hosts.find(h => h.host_id === f.id);
  if(!row) return '';
  const isAdmin = atLeast(state.user.role, 'admin');
  if(row.updating_to)
    return `<div class="kv-sub"><span class="badge info">updating to ${esc(row.updating_to)} on its next check-in</span></div>${isAdmin && f.agent_update_to ? `<div class="kv-sub"><a href="#" onclick="cancelAgentUpdate(${f.id});return false">cancel</a></div>` : ''}`;
  const latest = row.latest || U.latest;
  if(!row.behind) return row.latest ? ' <span class="muted">(latest)</span>' : '';
  if(!row.can_self_update) return ` <span class="muted">· ${esc(latest)} available — update this one by hand</span>`;
  return isAdmin ? ` <button class="topo-mini" onclick="requestAgentUpdate('${jsq(latest)}', ${f.id})">Update to ${esc(latest)}</button>`
    : ` <span class="muted">· ${esc(latest)} available</span>`;
}
async function requestAgentUpdate(version, hostId){
  const latest = version === 'latest';
  const what = latest ? 'the newest build for its OS' : version;
  const who = hostId == null ? 'every agent that’s behind' : 'this machine’s agent';
  const ok = await confirmDialog({title: latest ? 'Update agents' : `Update agent to ${version}`, confirmLabel: 'Update',
    message: `Update ${who} to ${what}? Each agent installs it on its next check-in and restarts itself; a run in progress is never interrupted.`});
  if(!ok) return;
  try{ state.agentUpdates = await api.setAgentUpdate(version, hostId); toast(`Agents will update to ${what} on their next check-in.`, 'success'); loadFleet(); render(); }
  catch(e){ toast(e.message, 'danger'); }
}
async function cancelAgentUpdate(hostId){
  try{ state.agentUpdates = await api.cancelAgentUpdate(hostId); toast('Agent update stopped; agents that haven’t updated stay where they are.', 'success'); loadFleet(); render(); }
  catch(e){ toast(e.message, 'danger'); }
}
function startRun(hostId, hostRecord){
  // `hostRecord` lets a caller that already has the host (host detail,
  // a #run/host/<id> deep link) pass it straight in. Falling back to the
  // fleet cache is fine, but it can legitimately be null here — Home no
  // longer loads the fleet, and this used to depend on an unawaited
  // loadFleet() at login having happened to finish first.
  const host = hostRecord || (state.fleet || []).find(f=>f.id===hostId) || null;
  if(state.fleet===null) loadFleet();
  if(state.checklistItems===null) loadChecklistItems();  // rare fallback -- normally already loaded at login
  if(state.tickets===null) loadTickets();  // powers the ticket-ID suggestion list on the Ticket step
  state.showNewTicketForm = false;
  // Always 0 — whichever step is actually first (ticket or checklist,
  // depending on requireTicket()) is index 0 in stepIndex()'s map either
  // way. The old `requireTicket() ? 0 : 1` assumed checklist was always
  // index 1, which broke the moment ticket-optional shifted indices down.
  state.run = { step: 0, host, ticketId:'', ticketInfo:null, ticketError:'', windowOverrideReason:'',
    checklist:(state.checklistItems||[]).map(()=>false),
    jobId:null, job:null, pollHandle:null, familyScripts:null };
  resetRunScope(hostId);
  state.nav = 'run';
  setHash(`run/host/${hostId}`);
  render();
}
// Several machines from Fleet: the same steps, confirmed once, then a
// batch (POST /batches) that rolls out one at a time or in parallel.
function startBatchRun(hostIds){
  const hosts = hostIds.map(id => (state.fleet || []).find(f => f.id === id)).filter(Boolean);
  if(hosts.length < 2) return hosts.length ? startRun(hosts[0].id, hosts[0]) : undefined;
  if(state.checklistItems===null) loadChecklistItems();
  if(state.tickets===null) loadTickets();
  state.showNewTicketForm = false;
  state.run = { step: 0, host: null, hosts, rollout: null, ticketId:'', ticketInfo:null, ticketError:'', windowOverrideReason:'',
    checklist:(state.checklistItems||[]).map(()=>false),
    jobId:null, job:null, batchId:null, batch:null, pollHandle:null, familyScripts:null };
  resetRunScope(null);
  state.nav = 'run';
  setHash('run');
  render();
}
async function openBatch(id){
  state.batchFilter = 'all'; state.batchShowAll = false;
  setHash(`run/batch/${id}`);
  await restoreFromHash();
}
async function openJobProgress(jobId){
  setHash(`run/job/${jobId}`);
  await restoreFromHash();
}
