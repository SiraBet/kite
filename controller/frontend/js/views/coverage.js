/*
 * Fleet → Coverage: every Proxmox guest and whether kite manages it
 * (GET /proxmox/coverage). The question it answers is the one the host
 * list can't: what in the cluster is going unpatched because nobody
 * enrolled it. Also home to proxmoxStatusBar(), shared with Topology.
 *
 * Actions are hidden, not disabled, for roles that can't use them — the
 * server enforces the same rules (Ignore/Un-ignore lead+, Enroll, Link and
 * Fix admin).
 */
/* ============================== FLEET SECTIONS ============================== */
function setFleetSection(id){
  state.fleetSection = id;
  if(id==='coverage') loadCoverage();
  if(id==='vulns') loadVulns();
  if(id==='hosts' && state.fleet===null) loadFleet();
  render();
}
function fleetSectionHeader(right){
  const n = state.fleet ? state.fleet.length : null;
  return `
    <div class="fleet-section-head">
      <h1 class="view-title" style="margin:0">Fleet</h1>
      <div class="grow"></div>
      ${right || ''}
    </div>
    <div class="fleet-tabs section-tabs">
      <button class="fleet-tab ${!['coverage','vulns'].includes(state.fleetSection)?'active':''}" onclick="setFleetSection('hosts')">Hosts${n!=null?`<span class="n">${n}</span>`:''}</button>
      <button class="fleet-tab ${state.fleetSection==='coverage'?'active':''}" onclick="setFleetSection('coverage')">Coverage</button>
      <button class="fleet-tab ${state.fleetSection==='vulns'?'active':''}" onclick="setFleetSection('vulns')">Vulnerabilities${state.vulns && state.vulns.enabled ? `<span class="n">${state.vulns.total}</span>` : ''}</button>
    </div>`;
}

/* ============================== PROXMOX STATUS BAR ============================== */
// The four states from the design: fetched, refreshing, error (showing the
// last good fetch, with its age), and not configured. `loading` is true
// while a request is in flight; `onRefresh` is the handler's source text.
function proxmoxStatusBar(pm, loading, onRefresh){
  if(!pm){
    return `<div class="pm-bar refreshing"><span class="pm-spin"></span><strong>Fetching from Proxmox…</strong></div>`;
  }
  if(!pm.configured){
    return `
      <div class="pm-empty">
        <div class="pm-q">?</div>
        <div class="grow">
          <div style="font-weight:600;font-size:14px">Proxmox isn't connected</div>
          <div class="secondary" style="font-size:12px;margin-top:3px">Coverage and Topology read guests from Proxmox. Add the API address and token under Settings &rarr; Connections — the same connection kite uses for snapshots.</div>
        </div>
        ${atLeast(state.user.role, 'admin') ? `<button class="primary" onclick="state.settingsTab='connections';navigate('settings')">Settings &rarr; Connections</button>` : `<span class="muted" style="font-size:11.5px">Ask an admin to connect it.</span>`}
      </div>`;
  }
  const age = pm.fetched_at ? relTime(pm.fetched_at) : null;
  if(loading){
    return `<div class="pm-bar refreshing"><span class="pm-spin"></span><strong>Fetching from Proxmox…</strong><span class="secondary">${age ? `numbers below stay from ${age} until it returns` : ''}</span><span class="grow"></span><button disabled>Refresh</button></div>`;
  }
  if(pm.error){
    return `
      <div class="pm-bar error">
        <span class="g">&#9650;</span>
        <div class="grow">
          <div style="font-weight:600">${esc(pm.error)}</div>
          <div style="font-size:11.5px;margin-top:2px">${pm.stale
            ? `Showing the last good fetch from <strong>${fmtTs(pm.fetched_at).slice(11,16)} (${age})</strong>. Counts may be out of date.`
            : 'Nothing has been fetched yet, so there is nothing to show.'}${pm.refreshing
            ? ' Trying again now…'
            : pm.retry_in != null ? ` Tries again ${pm.retry_in < 60 ? 'within a minute' : `in about ${Math.round(pm.retry_in / 60)} min`}.` : ''}</div>
        </div>
        <button onclick="${onRefresh}">Retry</button>
      </div>`;
  }
  return `
    <div class="pm-bar">
      <span class="pm-dot"></span><strong>Proxmox</strong>
      <span class="mono muted">${esc(pm.host)} &middot; ${pm.nodes} node${pm.nodes===1?'':'s'}</span>
      <span class="grow"></span>
      <span class="mono muted">fetched ${age}${pm.refreshing ? ' &middot; updating…' : ''}</span>
      <button onclick="${onRefresh}">Refresh</button>
    </div>`;
}

/* ============================== COVERAGE ============================== */
const COVERAGE_BADGE = {
  unmanaged:  ['cov-unmanaged', '&#9675;', 'Unmanaged'],
  name_match: ['info',          '&#8776;', 'Name match'],
  ignored:    ['unknown',       '&minus;', 'Ignored'],
  managed:    ['success',       '&#10003;','Managed'],
  template:   ['neutral',       '',        'Template'],
  gateway:    ['cov-gateway',   '&#8679;', 'Gateway'],
};
function coverageBadge(cov){
  const [cls, g, label] = COVERAGE_BADGE[cov] || COVERAGE_BADGE.unmanaged;
  return `<span class="badge ${cls}">${g?`<span class="g">${g}</span>`:''}${label}</span>`;
}
const COVERAGE_FILTERS = [
  {id:'all', label:'All'},
  {id:'unmanaged', label:'Unmanaged'},
  {id:'name_match', label:'Name match'},
  {id:'ignored', label:'Ignored'},
  {id:'gateway', label:'Gateways'},
  {id:'managed', label:'Managed'},
];
function guestTypeLabel(t){ return t==='lxc' ? 'CT' : t==='qemu' ? 'VM' : '—'; }

const COVERAGE_PAGE = 50;
function renderCoverage(){
  const c = state.coverage;
  const bar = proxmoxStatusBar(c && c.proxmox, state.coverageLoading, 'loadCoverage(true)');
  if(!c || !c.proxmox.configured || (c.proxmox.error && !c.proxmox.stale)){
    return `${fleetSectionHeader()}${state.loadError ? errorBanner(state.loadError) : ''}${bar}`;
  }
  const role = state.user.role;
  const canIgnore = atLeast(role, 'lead'), isAdmin = atLeast(role, 'admin');
  const guests = c.guests.filter(g => state.coverageShowTemplates || g.coverage !== 'template');
  const countOf = cov => c.guests.filter(g => g.coverage === cov).length;
  const rows = guests.filter(g => state.coverageFilter === 'all' || g.coverage === state.coverageFilter);
  // 50 to a page: a cluster can hold hundreds of guests
  const pages = Math.max(1, Math.ceil(rows.length / COVERAGE_PAGE)), page = Math.min(state.coveragePage || 0, pages - 1);
  const s = c.summary;
  const real = s.guests - s.templates;
  const vm = c.guests.filter(g => g.type==='qemu' && !g.template).length;
  const ct = c.guests.filter(g => g.type==='lxc' && !g.template).length;
  const pct = real ? Math.round(100 * s.managed / real) : 100;
  // Several connections: say which one each guest is on (VM ids repeat across them).
  const multi = ((c.proxmox || {}).connections || []).length > 1;
  const cols = multi ? '64px 1.4fr 0.9fr 0.8fr 44px 92px 132px 1.6fr' : '64px 1.5fr 0.9fr 44px 92px 132px 1.6fr';

  return `
    ${fleetSectionHeader(bar.includes('pm-empty') ? '' : `<div style="min-width:0;flex:0 1 560px">${bar}</div>`)}
    ${state.loadError ? errorBanner(state.loadError) : ''}

    <div class="cov-tiles">
      <div class="cov-tile"><div class="lbl">Guests</div><div class="num">${real}</div><div class="sub">${vm} VM &middot; ${ct} CT</div></div>
      <div class="cov-tile ok"><div class="lbl"><span class="g">&#10003;</span> Managed</div><div class="num">${s.managed} <span class="pct">${pct} %</span></div><div class="bar-track"><div class="bar-seg ok" style="width:${pct}%"></div></div></div>
      <div class="cov-tile urgent"><div class="lbl"><span class="g">&#9675;</span> Unmanaged, running</div><div class="num">${s.unmanaged_running}</div><div class="sub">${s.unmanaged_running ? 'nobody is patching these' : 'none running unmanaged'}</div></div>
      <div class="cov-tile info"><div class="lbl"><span class="g">&#8776;</span> Name matches</div><div class="num">${s.name_match}</div><div class="sub">likely managed, not linked</div></div>
      <div class="cov-tile due"><div class="lbl"><span class="g">&#9679;</span> Stale links</div><div class="num">${s.stale_links}</div><div class="sub">VM id no longer exists</div></div>
      <div class="cov-tile hatched"><div class="lbl">&minus; Ignored</div><div class="num">${s.ignored}</div><div class="sub">each has a stated reason${s.gateways ? ` &middot; ${s.gateways} gateway${s.gateways===1?'':'s'} patched elsewhere` : ''}</div></div>
    </div>

    <div class="cov-grid">
      <div class="panel" style="min-width:0">
        <div class="cov-toolbar">
          ${COVERAGE_FILTERS.map(f => {
            const n = f.id==='all' ? guests.length : countOf(f.id);
            return `<button class="chip ${state.coverageFilter===f.id?'active':''}" onclick="state.coverageFilter='${f.id}';state.coveragePage=0;render()">${f.label} <span class="n ${f.id==='unmanaged'&&n?'danger':''}">${n}</span></button>`;
          }).join('')}
          <span class="grow"></span>
          <label class="tok-toggle" style="border:none;padding:0"><input type="checkbox" ${state.coverageShowTemplates?'checked':''} onchange="state.coverageShowTemplates=this.checked;render()"> Show templates <span class="mono muted">${s.templates}</span></label>
        </div>
        <div class="panel-head" style="grid-template-columns:${cols}">
          <div>VM id</div><div>Name</div>${multi ? '<div>Connection</div>' : ''}<div>Node</div><div>Type</div><div>Power</div><div>Coverage</div><div>Action</div>
        </div>
        ${rows.length===0 ? `<div class="section-empty">${c.guests.length ? 'Nothing in this view.' : 'Proxmox reported no guests this token can see.'}</div>` : rows.slice(page * COVERAGE_PAGE, (page + 1) * COVERAGE_PAGE).map(g => `
          <div class="panel-row ${coverageRail(g)}" style="grid-template-columns:${cols}">
            <div class="mono secondary">${g.vmid}</div>
            <div class="mono" style="font-size:12.5px">${esc(g.name || '—')}</div>
            ${multi ? `<div style="font-size:11.5px">${esc(g.connection || '—')}</div>` : ''}
            <div class="mono secondary" style="font-size:11.5px">${esc(g.node)}</div>
            <div class="mono secondary" style="font-size:11px">${guestTypeLabel(g.type)}</div>
            <div style="font-size:12px">${g.status==='running' ? '<span class="pm-dot"></span> running' : `<span class="pm-dot off"></span> ${esc(g.status)}`}</div>
            <div>${coverageBadge(g.coverage)}</div>
            <div class="cov-action">${coverageAction(g, canIgnore, isAdmin)}</div>
          </div>`).join('')}
        <div class="pager"><span>sorted: needs action first &middot; ${pages > 1 ? `${page * COVERAGE_PAGE + 1}–${Math.min(rows.length, (page + 1) * COVERAGE_PAGE)} of ` : ''}${rows.length}${rows.length !== guests.length ? ` of ${guests.length}` : ''}${state.coverageShowTemplates ? '' : ` &middot; ${s.templates} template${s.templates===1?'':'s'} hidden`}</span>
          ${pages > 1 ? `<span class="grow"></span><button ${page===0?'disabled':''} onclick="state.coveragePage=${page-1};render()">&larr; Prev</button><button ${page>=pages-1?'disabled':''} onclick="state.coveragePage=${page+1};render()">Next &rarr;</button>` : ''}</div>
      </div>

      <div style="display:flex;flex-direction:column;gap:12px;min-width:0">
        ${c.stale_links.length ? `
        <div class="card cov-stale">
          <div style="display:flex;align-items:baseline"><p class="card-title" style="margin:0"><span class="g">&#9679;</span> Stale links</p><span class="grow"></span><span class="mono muted">${c.stale_links.length}</span></div>
          <p class="card-help" style="margin:4px 0 0">The host record points at a VM id Proxmox no longer reports — deleted, or not visible to this token. Snapshots for these hosts will fail, and Topology can't place them.</p>
          ${c.stale_links.map(h => `
            <div class="cov-stale-row">
              <div class="grow" style="min-width:0">
                <a href="#" onclick="openHostDetail(${h.host_id});return false" class="mono" style="font-size:12px;color:var(--text-primary)">${esc(h.hostname)}</a>
                <div class="mono muted" style="font-size:10.5px">recorded vmid <s>${h.proxmox_vmid}</s> &middot; not found</div>
              </div>
              ${isAdmin ? `<button style="padding:4px 10px;font-size:11.5px" onclick="fixStaleLink(${h.host_id},'${jsq(h.hostname)}')">Fix</button>` : ''}
            </div>`).join('')}
          ${isAdmin ? `<p class="card-help" style="margin:8px 0 0">Fix re-resolves the VM id from the SMBIOS UUID the agent reported. If there's no match it says so and leaves the link alone.</p>` : ''}
        </div>` : ''}
        <div class="card">
          <p class="card-title" style="font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted)">Per node</p>
          ${coveragePerNode(c.guests, multi)}
          <div class="cov-legend"><span><i class="sw ok"></i>managed</span><span><i class="sw urgent"></i>unmanaged</span><span><i class="sw info"></i>name match</span><span><i class="sw hatch"></i>ignored</span></div>
        </div>
      </div>
    </div>
    ${state.coverageIgnoring ? renderIgnoreDialog() : ''}`;
}
function coverageRail(g){
  if(g.coverage==='unmanaged' && g.status==='running') return 'rail-urgent';
  if(g.coverage==='name_match') return 'rail-info';
  if(g.coverage==='ignored') return 'rail-unknown';
  return '';
}
function coverageAction(g, canIgnore, isAdmin){
  if(g.coverage==='managed' && g.host)
    return `<a href="#" class="mono" style="font-size:11.5px" onclick="openHostDetail(${g.host.id});return false">${esc(g.host.hostname)} &rarr;</a>`;
  if(g.coverage==='name_match' && g.host)
    return `<span class="mono secondary" style="font-size:11.5px">&rarr; ${esc(g.host.hostname)}</span>
      ${isAdmin ? `<button class="info-outline" onclick="linkGuest(${g.host.id},${g.vmid},'${jsq(g.host.hostname)}',${g.connection_id ?? 'null'})">Link</button>` : ''}`;
  if(g.coverage==='ignored')
    return `<span class="secondary" style="font-size:11.5px;min-width:0">&ldquo;${esc(g.ignore_reason)}&rdquo;${g.ignored_by?` &middot; ${esc(g.ignored_by)}`:''}</span>
      ${canIgnore ? `<button onclick="unignoreGuest(${g.vmid},${g.connection_id ?? 'null'})">Un-ignore</button>` : ''}`;
  if(g.coverage==='gateway')
    return `<span class="secondary" style="font-size:11.5px;min-width:0">router/firewall &middot; patched outside kite</span>
      ${canIgnore && g.gateway_source === 'marked' ? `<button onclick="setGateway(${g.vmid},${g.connection_id ?? 'null'},false)">Not a gateway</button>` : ''}`;
  if(g.coverage==='unmanaged')
    return `${isAdmin ? `<button class="primary" onclick="enrollGuest('${jsq(g.name)}')">Enroll</button>` : ''}
      ${canIgnore ? `<button onclick="openIgnoreDialog(${g.vmid},'${jsq(g.name)}',${g.connection_id ?? 'null'})">Ignore&hellip;</button>` : ''}`;
  return '';
}
function coveragePerNode(guests, multi){
  const nodes = {};
  guests.filter(g => !g.template).forEach(g => {
    // Node names repeat across connections ("pve" on each), so label by both when there are several.
    const label = multi ? `${g.connection} · ${g.node}` : g.node;
    const n = nodes[label] = nodes[label] || {managed:0, unmanaged:0, name_match:0, ignored:0, total:0};
    n[g.coverage] = (n[g.coverage]||0) + 1; n.total++;
  });
  const names = Object.keys(nodes).sort();
  if(!names.length) return '<div class="muted" style="font-size:12px">No guests.</div>';
  return names.map(name => {
    const n = nodes[name], w = k => (100 * n[k] / n.total).toFixed(1);
    return `
      <div class="cov-node">
        <div style="display:flex"><span class="mono" style="font-size:11.5px">${esc(name)}</span><span class="grow"></span><span class="mono muted" style="font-size:11px">${n.managed} / ${n.total}</span></div>
        <div class="bar-track cov-stack">
          <div class="bar-seg ok" style="width:${w('managed')}%"></div><div class="bar-seg urgent" style="width:${w('unmanaged')}%"></div><div class="bar-seg info" style="width:${w('name_match')}%"></div><div class="bar-seg hatch" style="width:${w('ignored')}%"></div>
        </div>
      </div>`;
  }).join('');
}
function renderIgnoreDialog(){
  const g = state.coverageIgnoring;
  return `
    <div class="modal-backdrop" onclick="if(event.target===this) closeIgnoreDialog()">
      <div class="modal" style="max-width:420px;padding:0">
        <div style="padding:18px 18px 12px;border-bottom:1px solid var(--border)">
          <p class="modal-title" style="margin:0 0 4px">Ignore <span class="mono">${g.vmid} &middot; ${esc(g.name)}</span>?</p>
          <p class="modal-message" style="margin:0">It leaves the unmanaged count but stays listed with your reason and name. Anyone with lead or above can un-ignore it.</p>
        </div>
        <div style="padding:14px 18px">
          <label class="tok-lbl" for="ignore-reason">Reason <span style="color:var(--urgent)">*</span></label>
          <textarea id="ignore-reason" maxlength="200" rows="3" placeholder="e.g. Appliance, vendor-updated" oninput="document.getElementById('ignore-count').textContent=this.value.length+' / 200';document.getElementById('ignore-go').disabled=!this.value.trim()"></textarea>
          <div style="display:flex;font-size:11px" class="muted"><span>Shown in the table and the activity log</span><span class="grow"></span><span id="ignore-count" class="mono">0 / 200</span></div>
        </div>
        <div class="modal-actions" style="padding:12px 18px;border-top:1px solid var(--border);background:var(--surface-1)">
          <button onclick="closeIgnoreDialog()">Cancel</button>
          <button id="ignore-go" class="dark" disabled onclick="ignoreGuest()">Ignore guest</button>
        </div>
      </div>
    </div>`;
}
function openIgnoreDialog(vmid, name, connectionId){
  state.coverageIgnoring = {vmid, name, connection_id: connectionId ?? null};
  render();
  const el = document.getElementById('ignore-reason');
  if(el && el.focus) el.focus();
}
function closeIgnoreDialog(){ state.coverageIgnoring = null; render(); }
// Topology shares these handlers; reload whichever page is on screen.
function reloadInventory(){ return state.nav==='topology' ? loadTopology() : loadCoverage(); }
async function ignoreGuest(){
  const g = state.coverageIgnoring;
  const reason = (document.getElementById('ignore-reason')||{}).value?.trim() || '';
  if(!g || !reason) return;
  try{
    await api.ignoreGuest(g.vmid, reason, g.connection_id);
    state.coverageIgnoring = null;
    toast(`VM ${g.vmid} ignored.`, 'success');
    await reloadInventory();
  }catch(e){ toast(e.message, 'danger'); }
}
async function unignoreGuest(vmid, connectionId){
  try{ await api.unignoreGuest(vmid, connectionId); toast(`VM ${vmid} is back in the unmanaged count.`, 'success'); await reloadInventory(); }
  catch(e){ toast(e.message, 'danger'); }
}
async function setGateway(vmid, connectionId, gateway){
  try{
    await api.setGateway(vmid, connectionId, gateway);
    toast(gateway ? `VM ${vmid} is drawn as a gateway.` : `VM ${vmid} won't be suggested as a gateway again.`, 'success');
    await reloadInventory();
  }catch(e){ toast(e.message, 'danger'); }
}
async function clearGateway(vmid, connectionId){
  try{ await api.clearGateway(vmid, connectionId); toast(`VM ${vmid} is back to automatic gateway detection.`, 'success'); await reloadInventory(); }
  catch(e){ toast(e.message, 'danger'); }
}
async function linkGuest(hostId, vmid, hostname, connectionId){
  const ok = await confirmDialog({title:'Link VM to host', message:`Record VM ${vmid} as ${hostname}? Snapshots for this host will use that VM from now on.`, confirmLabel:'Link'});
  if(!ok) return;
  try{ await api.patchHost(hostId, {proxmox_vmid: vmid, proxmox_connection_id: connectionId ?? null}); toast(`${hostname} linked to VM ${vmid}.`, 'success'); await reloadInventory(); }
  catch(e){ toast(e.message, 'danger'); }
}
async function fixStaleLink(hostId, hostname){
  try{
    const host = await api.resolveVmid(hostId);
    toast(`${hostname} re-linked to VM ${host.proxmox_vmid}.`, 'success');
    await reloadInventory();
  }catch(e){ toast(e.message, 'danger', 6000); }
}
// Enrolling a guest is the ordinary Add-machine flow with its name
// filled in — there is no separate path to keep in step with it.
function enrollGuest(name){
  state.nav = 'fleet';
  state.fleetSection = 'hosts';
  setHash('fleet');
  openAddMachine();
  state.addMachine.hostname = name;
  if(state.fleet===null) loadFleet();
  render();
}
