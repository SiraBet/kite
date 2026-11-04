/*
 * The guarded patch wizard — ticket, checklist, confirmation, then live
 * stage progress polled until the job finishes.
 */
/* ============================== RUN FLOW ============================== */
function runStepLabels(){ return requireTicket() ? ['Ticket','Checklist','Confirm','Progress'] : ['Checklist','Confirm','Progress']; }
// Scope resets per run rather than persisting: "containers only" is a
// deliberate choice each time, never something inherited from the last
// run on a different host. A batch has no single host to list containers
// for -- each machine updates all of its updatable ones.
function resetRunScope(hostId){
  state.runScope = 'os';
  state.runSeverity = '';
  state.runContainers = hostId == null ? [] : null;
  state.runContainerPick = null;
  if(hostId != null) loadRunContainers(hostId);
}
async function loadRunContainers(hostId){
  try{
    const all = await api.hostContainers(hostId);
    // Only compose-managed containers can be recreated safely, so those
    // are the only ones offered — the server enforces the same rule.
    state.runContainers = all.filter(c => c.updatable);
  }catch(e){ state.runContainers = []; }
  if(state.nav === 'run') render();
}
function runScopeIncludesContainers(){ return state.runScope !== 'os'; }
function setRunScope(scope){
  state.runScope = scope;
  render();
}
function toggleRunContainer(name){
  const all = (state.runContainers || []).map(c => c.name);
  if(state.runContainerPick === null) state.runContainerPick = new Set(all);
  if(state.runContainerPick.has(name)) state.runContainerPick.delete(name);
  else state.runContainerPick.add(name);
  render();
}
function runContainerSelection(){
  // null means "everything updatable", which the API also accepts as an
  // empty list — send the explicit names only when the operator narrowed it.
  if(state.runContainerPick === null) return [];
  return [...state.runContainerPick];
}
function renderScopePicker(){
  const batch = !!(state.run && state.run.hosts);   // several machines: no single container list to show
  const containers = batch ? [] : state.runContainers;
  const scope = state.runScope;
  const none = !batch && containers !== null && containers.length === 0;
  const picked = state.runContainerPick;
  return `
    <div class="card" style="margin-bottom:16px">
      <p class="card-title">What this run touches</p>
      <div class="chip-row" style="margin-bottom:10px">
        <span class="chip ${scope==='os'?'active':''}" onclick="setRunScope('os')">OS packages</span>
        <span class="chip ${scope==='containers'?'active':''} ${none?'':''}" onclick="setRunScope('containers')">Containers only</span>
        <span class="chip ${scope==='both'?'active':''}" onclick="setRunScope('both')">Both</span>
      </div>
      ${scope !== 'containers' ? `
        <p class="card-help" style="margin:10px 0 6px">Which OS updates</p>
        <div class="chip-row">
          <span class="chip ${!state.runSeverity?'active':''}" onclick="state.runSeverity='';render()">Everything</span>
          <span class="chip ${state.runSeverity==='security'?'active':''}" onclick="state.runSeverity='security';render()">Security only</span>
          <span class="chip ${state.runSeverity==='critical,important'?'active':''}" onclick="state.runSeverity='critical,important';render()">Critical + Important</span>
          <span class="chip ${state.runSeverity==='critical'?'active':''}" onclick="state.runSeverity='critical';render()">Critical only</span>
        </div>
        ${state.runSeverity && state.runSeverity !== 'security' ? `<p class="card-help" style="margin:8px 0 0">
          apt publishes no per-advisory severity, so on Debian/Ubuntu hosts this runs as
          security-only and the stage output says so.</p>` : ''}` : ''}
      ${containers === null ? `<p class="card-help" style="margin:0">Checking what this host runs…</p>` : ''}
      ${none ? `<p class="card-help" style="margin:0">
          No compose-managed containers on this host. Only compose containers can be
          updated — a standalone container's creation flags aren't recorded anywhere,
          and an orchestrated one belongs to its orchestrator.
        </p>` : ''}
      ${runScopeIncludesContainers() && containers && containers.length ? `
        <p class="card-help" style="margin:4px 0 8px">
          ${picked === null ? `All ${containers.length} updatable container(s).` : `${picked.size} of ${containers.length} selected.`}
          Images are pulled and the compose service recreated.
        </p>
        ${containers.map(c=>{
          const on = picked === null || picked.has(c.name);
          return `<label class="checklist-item" style="padding:7px 0">
            <input type="checkbox" ${on?'checked':''} onclick="toggleRunContainer('${jsq(c.name)}')">
            <span><span class="mono">${esc(c.name)}</span>
              <span class="dash-row-meta">${esc(c.image)}${c.compose_project?` &middot; ${esc(c.compose_project)}`:''}</span>
            </span>
          </label>`;
        }).join('')}` : ''}
    </div>`;
}
function stepIndex(name){
  const labels = runStepLabels();
  const map = requireTicket() ? {ticket:0, checklist:1, confirm:2, progress:3} : {checklist:0, confirm:1, progress:2};
  return map[name];
}

function renderRun(){
  if(!state.run.host && !state.run.jobId && !state.run.hosts && !state.run.batchId) return renderRunHome();
  const r = state.run;
  if(r.batchId) return renderBatchProgress();
  const labels = runStepLabels();
  const titleSuffix = r.hosts ? `${r.hosts.length} machines` : r.host ? esc(r.host.hostname) : `job ${r.jobId}`;
  return `
    <div class="view-header">
      <p style="margin:0 0 8px"><a href="#" onclick="navHome('run');return false">&larr; Run patching</a></p>
      <h1 class="view-title">Run patch <span class="mono" style="color:var(--text-secondary);font-weight:400;font-size:15px">/ ${titleSuffix}</span></h1>
      <p class="view-sub">${r.hosts ? r.hosts.map(h => esc(h.hostname)).join(', ') : r.host ? esc(r.host.role||'')+' &middot; '+esc(r.host.team||'') : ''}</p>
      ${r.host ? `<div style="margin-top:8px">${osBadge(r.host.os_family)}</div>` : ''}
    </div>
    <div class="stepper">
      ${labels.map((l,i)=>`
        <span class="step-pill ${i===r.step?'active':i<r.step?'done':''}"><span class="n">${i<r.step?'✓':i+1}</span>${l}</span>
        ${i<labels.length-1?'<span class="step-arrow">&rarr;</span>':''}
      `).join('')}
    </div>
    <div id="run-step">${renderRunStep()}</div>`;
}
// The tab's own page: how to start a run, and the runs to go back to.
function renderRunHome(){
  const dash = state.dashboard || {};
  const active = dash.active_runs || [], recent = (dash.recent_runs || []).filter(r => !active.some(a => a.job_id === r.job_id));
  const row = (id, host, right) => `<div class="run-home-row" onclick="openJobProgress(${id})"><span class="mono">run ${id}</span><span class="mono" style="font-weight:600">${esc(host || '—')}</span><span class="grow"></span>${right}<span class="muted">&rarr;</span></div>`;
  const statusBadge = s => `<span class="badge ${s==='done'?'success':s==='failed'?'danger':s==='cancelled'?'warning':'info'}">${esc(s)}</span>`;
  return `
    <div class="view-header"><h1 class="view-title">Run patching</h1><p class="view-sub">Start a run from a machine in Fleet — its <em>Patch</em> button opens the steps here.</p></div>
    <div style="margin-bottom:18px"><button class="primary" onclick="navigate('fleet')">Choose a machine in Fleet &rarr;</button></div>
    <p class="card-title" style="margin:0 0 8px">In progress${active.length > 10 ? ` <span class="muted" style="font-weight:400">${active.length}</span>` : ''}</p>
    ${active.length ? `<div class="run-home-list">${(state.runHomeAllActive ? active : active.slice(0, 10)).map(a => row(a.job_id, a.hostname, `<span class="muted" style="font-size:12px">${esc(stageLabels[a.stage] || a.stage)} &middot; ${a.stage_index + 1}/${a.total_stages}</span>`)).join('')}</div>
      ${active.length > 10 ? `<button class="history-toggle" style="margin-top:6px" onclick="state.runHomeAllActive=!state.runHomeAllActive;render()">${state.runHomeAllActive ? 'Show fewer' : `Show all ${active.length}`}</button>` : ''}`
      : '<div class="muted" style="font-size:12.5px;margin-bottom:6px">Nothing running.</div>'}
    ${(state.batchesRecent || []).length ? `<p class="card-title" style="margin:18px 0 8px">Batches</p>
      <div class="run-home-list">${state.batchesRecent.slice(0, 5).map(b => `<div class="run-home-row" onclick="openBatch(${b.id})"><span class="mono">batch ${b.id}</span>
        <span>${b.hosts.length} machines, ${b.rollout === 'parallel' ? 'in parallel' : 'one at a time'}</span><span class="grow"></span>
        <span class="badge ${b.status === 'done' ? 'success' : b.status === 'paused' || b.status === 'stopped' ? 'warning' : 'info'}">${esc(b.status)}</span>
        <span class="mono muted" style="font-size:11.5px">${b.counts.done}/${b.hosts.length} done</span><span class="muted">&rarr;</span></div>`).join('')}</div>` : ''}
    <p class="card-title" style="margin:18px 0 8px">Recent</p>
    ${recent.length ? `<div class="run-home-list">${recent.slice(0, 10).map(r => row(r.job_id, r.hostname, statusBadge(r.status))).join('')}</div>`
      : `<div class="muted" style="font-size:12.5px">${state.dashboard ? 'No runs yet.' : 'Loading…'}</div>`}`;
}
// The way back from a finished run: the snapshot its snapshot stage took,
// restored from here (admin), as on the machine's Snapshots tab.
function runSnapshotName(job){
  const st = (job.stages || []).find(s => s.name === 'snapshot' && s.status === 'done');
  const m = st && (st.output || '').match(/Snapshot '(kite-job\d+-\d+)' created/);
  return m ? m[1] : '';
}
function runRestoreOffer(job){
  const name = runSnapshotName(job);
  if(!name || !['done', 'failed', 'cancelled'].includes(job.status) || !atLeast(state.user.role, 'admin')) return '';
  return `<div class="banner neutral" style="margin-top:16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
    <span>${job.status === 'done' ? 'Something wrong after this run?' : 'Need to undo what this run changed?'} The VM was snapshotted before patching: <span class="mono">${esc(name)}</span>.</span>
    <span class="grow"></span><button onclick="restoreSnapshot(${job.host_id}, '${jsq(name)}')">Restore that snapshot&hellip;</button></div>`;
}
// What the agent said it couldn't install ("[uninstallable] ..." when the
// patch step failed, "[skipped] ..." when the policy let the rest go
// ahead), with a one-click skip rule for each.
const RUN_PKG_LINE = /^\[(uninstallable|skipped)\] (\S+) (\S*) ?\(from ([^)]+)\)(.*)$/;
function runPackageProblems(job){
  const patch = (job.stages || []).find(s => s.name === 'patch');
  if(!patch || !patch.output) return '';
  const items = patch.output.split('\n').map(l => l.match(RUN_PKG_LINE)).filter(Boolean)
    .map(m => ({kind: m[1], name: m[2], version: m[3], repo: m[4], why: m[5].trim()}));
  if(!items.length) return '';
  const failed = items[0].kind === 'uninstallable';
  const isAdmin = atLeast(state.user.role, 'admin');
  const host = state.run.host || (state.fleet || []).find(f => f.id === job.host_id) || null;
  const family = host ? host.os_family : '';
  const ruled = new Set((state.defs || []).filter(d => d.mode === 'skip' && (!host || ruleApplies(d, host))).map(d => d.pkg_pattern));
  return `<div class="banner ${failed ? 'danger' : 'warning'}" style="margin-top:16px;display:block">
    <strong>${failed ? 'Nothing was installed: these updates can’t be installed on this machine.' : 'Installed everything else; these were skipped.'}</strong>
    ${items.map(i => `<div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">
      <span class="mono" style="font-weight:600">${esc(i.name)}</span><span class="mono muted">${esc(i.version)}</span><span class="muted">from ${esc(i.repo)}</span>
      ${ruled.has(i.name) ? '<span class="badge neutral">skip rule exists</span>'
        : isAdmin ? `<button class="topo-mini" onclick="addSkipRuleFromRun('${jsq(i.name)}','${jsq(family)}','${jsq(i.repo)}')">Add skip rule${family ? ` for ${esc(family)}` : ''}</button>` : ''}
      ${i.why ? `<div class="muted" style="flex-basis:100%;font-size:11.5px">${esc(i.why)}</div>` : ''}
    </div>`).join('')}
    <div style="font-size:12px;margin-top:10px">${failed
      ? `A skip rule leaves the package at its current version until you remove the rule; then run again. Or fix the repository on the machine, or turn on <em>Skip updates that can’t be installed</em> in Settings &rarr; Policy.${isAdmin ? '' : ' Adding rules needs an admin.'}`
      : 'They stay at their current version. A skip rule stops them being listed every run.'}</div>
  </div>`;
}
// apt's own leftovers on Debian/Ubuntu: "[kept-back] pkg ..." (needs a
// package added or removed) and "[phased] pkg ..." (staged rollout).
const RUN_APT_LINE = /^\[(kept-back|phased)\] (\S+) (.*)$/;
function runAptHeldBack(job){
  const patch = (job.stages || []).find(s => s.name === 'patch');
  if(!patch || !patch.output) return '';
  const items = patch.output.split('\n').map(l => l.match(RUN_APT_LINE)).filter(Boolean)
    .map(m => ({kind: m[1], name: m[2]}));
  if(!items.length) return '';
  const kept = items.filter(i => i.kind === 'kept-back'), phased = items.filter(i => i.kind === 'phased');
  const host = state.run.host || (state.fleet || []).find(f => f.id === job.host_id) || null;
  const family = host ? host.os_family : '';
  const isAdmin = atLeast(state.user.role, 'admin');
  const ruled = new Set((state.defs || []).filter(d => d.mode === 'skip' && (!host || ruleApplies(d, host))).map(d => d.pkg_pattern));
  const list = arr => arr.map(i => `<span class="mono" style="font-weight:600">${esc(i.name)}</span>`).join(', ');
  return `<div class="banner warning" style="margin-top:16px;display:block">
    <strong>apt left ${items.length} update${items.length===1?'':'s'} out of this run.</strong>
    ${kept.length ? `<div style="margin-top:8px"><strong>Kept back</strong> (${kept.length}): ${list(kept)}
      <div style="font-size:12px;margin-top:3px">Each needs a package added or removed — often a new kernel — which <span class="mono">apt-get upgrade</span> never does. Install them on the machine with <span class="mono">sudo apt-get install --only-upgrade ${kept.map(i => esc(i.name)).join(' ')}</span>, or add skip rules to stop them being listed.</div>
      ${isAdmin ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px">${kept.map(i => ruled.has(i.name) ? `<span class="badge neutral">${esc(i.name)}: skip rule exists</span>`
        : `<button class="topo-mini" onclick="addSkipRuleFromRun('${jsq(i.name)}','${jsq(family)}','','kept back by apt: needs a package added or removed')">Skip ${esc(i.name)}</button>`).join('')}</div>` : ''}</div>` : ''}
    ${phased.length ? `<div style="margin-top:8px"><strong>Phased</strong> (${phased.length}): ${list(phased)}
      <div style="font-size:12px;margin-top:3px">The distribution is rolling these out gradually; they install on a later run by themselves. Nothing to do.</div></div>` : ''}
  </div>`;
}
async function addSkipRuleFromRun(name, family, repo, reason){
  const ok = await confirmDialog({title: 'Add skip rule', confirmLabel: 'Add rule',
    message: `Skip ${name} on ${family || 'every OS family'} from now on? It stays at its current version until the rule is removed (Update rules).`});
  if(!ok) return;
  try{
    await api.addDef({pkg_pattern: name, mode: 'skip', version: '', targets: family ? [{kind: 'os', value: family}] : [],
      reason: reason || `update from ${repo} can't be installed on this OS`});
    state.defs = await api.listDefs();
    toast(`${name} will be skipped. Start the run again when ready.`, 'success');
    render();
  }catch(e){ toast(e.message, 'danger'); }
}
function renderRunStep(){
  const r = state.run;
  if(r.hosts && r.step===stepIndex('confirm')) return renderStepConfirmBatch();
  if(requireTicket() && r.step===stepIndex('ticket')) return renderStepTicket();
  if(r.step===stepIndex('checklist')) return renderStepChecklist();
  if(r.step===stepIndex('confirm')) return renderStepConfirm();
  if(r.step===stepIndex('progress')) return renderStepProgress();
}

function renderStepTicket(){
  const r = state.run;
  // r.ticketId can point at a ticket that no longer appears in
  // state.tickets (still loading, or deleted after this run started) --
  // keep it selectable rather than silently dropping the selection.
  const knownIds = new Set((state.tickets||[]).map(t=>t.ticket_id));
  const staleOption = r.ticketId && !knownIds.has(r.ticketId)
    ? `<option value="${esc(r.ticketId)}" selected>${esc(r.ticketId)} (not found)</option>` : '';
  return `
    <div class="card" style="margin-bottom:14px">
      <table class="kv-table">
        ${r.hosts ? `<tr><td>Machines</td><td>${r.hosts.map(h => esc(h.hostname)).join(', ')}</td></tr>` : `
        <tr><td>Host</td><td>${esc(r.host.hostname)}</td></tr>
        <tr><td>Owner team</td><td>${esc(r.host.team||'—')}</td></tr>`}
      </table>
    </div>
    <div class="field-row" style="margin-bottom:8px">
      <select id="ticket-input" onchange="lookupTicket()" class="grow">
        <option value="">${state.tickets===null ? 'Loading tickets…' : (state.tickets.length ? '— select a ticket —' : 'No tickets exist yet')}</option>
        ${staleOption}
        ${(state.tickets||[]).map(t=>`<option value="${esc(t.ticket_id)}" ${r.ticketId===t.ticket_id?'selected':''}>${esc(t.ticket_id)} — ${esc(t.status)}</option>`).join('')}
      </select>
      <button onclick="lookupTicket()">Look up</button>
    </div>
    <div style="margin-bottom:12px">
      ${state.showNewTicketForm ? renderNewTicketForm()
        : atLeast(state.user.role, 'lead') ? `<button style="padding:5px 10px;font-size:11.5px" onclick="state.showNewTicketForm=true;render()">+ New ticket</button>` : ''}
    </div>
    <div id="ticket-result">${renderTicketResult()}</div>
    <button class="primary" style="margin-top:16px" ${r.ticketInfo && r.ticketInfo.status==='Approved' ? '' : 'disabled'} onclick="state.run.step=stepIndex('checklist');render()">Continue to checklist</button>
  `;
}
function renderTicketResult(){
  const r = state.run;
  if(r.ticketError) return errorBanner(r.ticketError);
  if(!r.ticketInfo) return '';
  const t = r.ticketInfo;
  const approved = t.status==='Approved';
  const now = new Date();
  const inWindow = within(now.getUTCHours(), t.window_start, t.window_end);
  return `
    <div class="card">
      <div style="display:flex;justify-content:space-between;margin-bottom:8px">
        <span class="mono" style="font-weight:600">${esc(t.ticket_id)}</span>
        <span class="badge ${approved?'success':'warning'}">${esc(t.status)}</span>
      </div>
      <p style="color:var(--text-secondary);margin:3px 0">${esc(t.description||'')}</p>
      <p style="color:var(--text-muted);margin:3px 0" class="mono">Window: ${String(t.window_start).padStart(2,'0')}:00–${String(t.window_end).padStart(2,'0')}:00 UTC &middot; requested by ${esc(t.requester||'—')}</p>
      ${approved && !inWindow ? `<div class="banner warning" style="margin-top:10px">Outside approved maintenance window right now (${pad2(now.getUTCHours())}:${pad2(now.getUTCMinutes())} UTC).</div>` : ''}
      ${!approved ? `<div class="banner danger" style="margin-top:10px">Ticket is not in an approved state — run cannot proceed.</div>` : ''}
    </div>`;
}
async function lookupTicket(){
  const val = document.getElementById('ticket-input').value.trim();
  const r = state.run;
  r.ticketId = val;
  if(!val){ r.ticketError=''; r.ticketInfo=null; render(); return; }
  try{
    const t = await api.getTicket(val);
    r.ticketError=''; r.ticketInfo=t;
  }catch(e){
    r.ticketError = `${val}: ${e.message}`; r.ticketInfo = null;
  }
  render();
}

// Shared by the Run page's Ticket step and the Schedules form -- both
// need an existing ticket to select, and (unlike Team, which is a plain
// attribute on already-enrolled hosts) there was previously no UI at all
// for creating one manually, only the ITSM webhook or raw API
// calls. Constraining those fields to "must already exist" without this
// would be a dead end for anyone not running a real ITSM behind kite.
function renderNewTicketForm(){
  return `
    <div class="card" style="margin-top:10px;background:var(--surface-0)">
      <p class="card-help">Manual ticket, for a lab without a real ITSM behind it. If you do have one, point it at Settings → ITSM ticket webhook instead of creating tickets by hand here.</p>
      <div class="field-row" style="margin-bottom:8px">
        <input id="nt-id" placeholder="Ticket ID, e.g. CHG-4821" class="grow">
        <select id="nt-status" style="flex:0.8;background:var(--surface-0);border:1px solid var(--border);color:var(--text-primary);padding:9px 11px;border-radius:var(--radius)">
          <option value="Approved">Approved</option>
          <option value="Pending approval">Pending approval</option>
        </select>
      </div>
      <div class="field-row" style="margin-bottom:8px">
        <input id="nt-desc" placeholder="Description">
        <input id="nt-requester" placeholder="Requester" style="flex:0.8">
      </div>
      <div class="field-row" style="margin-bottom:10px">
        <input id="nt-window-start" placeholder="Window start hour, UTC (0-23)">
        <input id="nt-window-end" placeholder="Window end hour, UTC (0-23)">
      </div>
      <div style="display:flex;gap:8px">
        <button class="primary" onclick="createTicketHandler()">Create ticket</button>
        <button onclick="state.showNewTicketForm=false;render()">Cancel</button>
      </div>
      <div id="new-ticket-error"></div>
    </div>`;
}
async function createTicketHandler(){
  const ticket_id = document.getElementById('nt-id').value.trim();
  const status = document.getElementById('nt-status').value;
  const description = document.getElementById('nt-desc').value.trim();
  const requester = document.getElementById('nt-requester').value.trim();
  const startRaw = document.getElementById('nt-window-start').value.trim();
  const endRaw = document.getElementById('nt-window-end').value.trim();
  const window_start = startRaw ? parseInt(startRaw, 10) : 0;
  const window_end = endRaw ? parseInt(endRaw, 10) : 23;
  const errEl = document.getElementById('new-ticket-error');
  errEl.innerHTML = '';
  if(!ticket_id){ errEl.innerHTML = errorBanner('Ticket ID is required.'); return; }
  if(!Number.isInteger(window_start) || window_start<0 || window_start>23 || !Number.isInteger(window_end) || window_end<0 || window_end>23){
    errEl.innerHTML = errorBanner('Window hours must be 0-23.'); return;
  }
  try{
    const created = await api.createTicket({ ticket_id, status, description, requester, window_start, window_end });
    state.showNewTicketForm = false;
    await loadTickets();  // re-renders with the new ticket in every select on screen
    if(state.nav==='run' && state.run && state.run.step===stepIndex('ticket')){
      // Already have the full ticket from the create response -- no need
      // for a separate lookup round-trip just to populate the same data.
      state.run.ticketId = created.ticket_id;
      state.run.ticketInfo = created;
      state.run.ticketError = '';
      render();
    }
    toast(`Ticket ${ticket_id} created.`, 'success');
  }catch(e){ errEl.innerHTML = errorBanner(e.message); }
}

function renderStepChecklist(){
  const r = state.run;
  if(state.checklistError){
    return `<div class="banner danger">Couldn't load the checklist: ${esc(state.checklistError)}
      <button style="margin-left:8px" onclick="loadChecklistItems()">Try again</button></div>`;
  }
  if(state.checklistItems === null) return `<div class="banner neutral">Loading checklist…</div>`;
  const items = state.checklistItems;
  if(items.length === 0){
    return `<div class="banner neutral">No pre-run checklist is set up${atLeast(state.user.role, 'admin') ? ' (Settings &rarr; Checklist)' : ''}.</div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px">
        ${requireTicket() ? `<button onclick="state.run.step=stepIndex('ticket');render()">Back</button>` : ''}
        <button class="primary" onclick="state.run.checklist=[];goToConfirm()">Continue</button>
      </div>`;
  }
  // Self-heals if items finished loading after startRun() already set
  // r.checklist to [] (the rare fallback case — see startRun()).
  if(r.checklist.length !== items.length) r.checklist = items.map(()=>false);
  const allChecked = r.checklist.every(Boolean);
  return `
    ${items.map((it,i)=>`
      <label class="checklist-item">
        <input type="checkbox" ${r.checklist[i]?'checked':''} onchange="toggleChecklist(${i})">
        <span>${esc(it.text)}</span>
      </label>`).join('')}
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px">
      <span style="font-size:12px;color:var(--text-muted)">${r.checklist.filter(Boolean).length} of ${items.length} confirmed by ${esc(state.user.display_name || state.user.username)}</span>
      <div style="display:flex;gap:8px">
        ${requireTicket() ? `<button onclick="state.run.step=stepIndex('ticket');render()">Back</button>` : ''}
        <button class="primary" ${allChecked ? '' : 'disabled'} onclick="goToConfirm()">Continue</button>
      </div>
    </div>`;
}
function toggleChecklist(i){ state.run.checklist[i] = !state.run.checklist[i]; render(); }
async function goToConfirm(){
  state.run.step = stepIndex('confirm');
  render();
  // what each machine will run: its group's scripts, else its OS family's
  const hosts = (state.run.hosts || [state.run.host]).filter(Boolean);
  if(hosts.length){
    try{
      const seen = new Set();
      state.run.familyScripts = [].concat(...await Promise.all(hosts.map(h => api.scriptsForHost(h.id))))
        .filter(s => { const k = `${s.os_family}/${s.stage_name}`; if(seen.has(k)) return false; seen.add(k); return true; });
    }catch(e){ state.run.familyScripts = []; }
    if(state.run.step===stepIndex('confirm')) render();
  }else state.run.familyScripts = [];
}

function renderUntestedScriptWarning(){
  const fs = state.run.familyScripts;
  if(fs===null || fs===undefined) return `<div class="banner neutral" style="margin-bottom:14px">Checking OS scripts…</div>`;
  const untested = fs.filter(s => !s.tested);
  if(untested.length===0) return '';
  return `<div class="banner warning" style="margin-bottom:14px">
    Untested custom script${untested.length>1?'s':''} for these machines: ${untested.map(s=>`<strong>${stageLabels[s.stage_name]||s.stage_name}</strong> (${esc(s.os_family)})`).join(', ')}.
    This run will be ${untested.length>1?'their':'its'} first real test — proceeding is allowed, just know that going in.
  </div>`;
}

function pad2(n){ return String(n).padStart(2,'0'); }
// The rollback backend a run on this host uses: its own, else the
// Settings default (app/rollback resolve_backend_name).
function hostBackend(h){
  return h.rollback_backend || (state.settings && state.settings.rollback_default_backend) || 'proxmox';
}
// What the confirm page says the snapshot step will do, and whether it will fail.
function snapshotMethod(h){
  const backend = hostBackend(h);
  if(backend === 'dnf_history') return {text: 'Package history (dnf) — the update can be undone, no VM snapshot', fails: false};
  if(backend === 'none') return {text: 'None — this host patches without a safety net', fails: false};
  return h.proxmox_vmid
    ? {text: `Proxmox snapshot of VM ${h.proxmox_vmid}`, fails: false}
    : {text: 'Proxmox — no VM ID set, the snapshot step will fail', fails: true};
}
// A 0–24h bar with the approved maintenance window highlighted and a
// "now" marker, so an out-of-window override is visible, not just stated.
function windowTimeline(startH, endH){
  const now = new Date().getUTCHours() + new Date().getUTCMinutes()/60;
  const nowPct = (now/24*100).toFixed(1);
  const bands = startH <= endH ? [[startH, endH+1]] : [[startH,24],[0,endH+1]];
  const seg = bands.map(([a,b])=>`<div style="position:absolute;left:${a/24*100}%;width:${(b-a)/24*100}%;top:0;bottom:0;background:var(--ok-bg);box-shadow:inset 1px 0 0 var(--ok-border),inset -1px 0 0 var(--ok-border)"></div>`).join('');
  return `<div style="position:relative;height:22px;border-radius:5px;background:#fff;border:1px solid var(--border-strong);overflow:hidden">
    ${seg}
    <div style="position:absolute;left:${nowPct}%;top:0;bottom:0;width:2px;background:var(--urgent)"></div>
    <div style="position:absolute;left:6px;top:5px;font:600 9px/1 var(--font-mono);color:var(--ok-ink)">${pad2(startH)}:00–${pad2(endH)}:00 UTC window &middot; now ${pad2(new Date().getUTCHours())}:${pad2(new Date().getUTCMinutes())} UTC</div>
  </div>`;
}
function renderStepConfirm(){
  const r = state.run;
  const t = r.ticketInfo;
  const now = new Date();
  const needsTicket = requireTicket();
  const inWindow = (needsTicket && t) ? within(now.getUTCHours(), t.window_start, t.window_end) : true;
  const needsOverride = needsTicket && !inWindow;
  const canOverride = atLeast(state.user.role, 'lead');
  const defCount = state.defs ? state.defs.length : '?';
  const scope = state.runScope;
  const scopeLabel = {os:'OS packages', containers:'Containers only', both:'OS packages + containers'}[scope];
  const containersOnly = scope === 'containers';
  return `
    ${renderScopePicker()}
    <div class="card" style="margin-bottom:16px">
      <table class="kv-table">
        <tr><td>Host</td><td>${esc(r.host.hostname)}</td></tr>
        ${needsTicket ? `<tr><td>Ticket</td><td>${esc(r.ticketId)}</td></tr>` : `<tr><td>Ticket</td><td class="muted">not required (disabled in Settings)</td></tr>`}
        <tr><td>Checklist</td><td style="color:var(--success)">${r.checklist.filter(Boolean).length} of ${r.checklist.length} confirmed</td></tr>
        <tr><td>Scope</td><td>${scopeLabel}${scope !== 'containers' && state.runSeverity ? ` &middot; ${esc(state.runSeverity)} only` : ''}</td></tr>
        <tr><td>Snapshot method</td><td>${esc(snapshotMethod(r.host).text)}</td></tr>
        ${containersOnly ? '' : `<tr><td>Excludes applied</td><td>${defCount} rule(s)</td></tr>`}
        <tr><td>Operator</td><td>${esc(state.user.display_name || state.user.username)}</td></tr>
      </table>
    </div>
    ${snapshotMethod(r.host).fails ? `<div class="banner warning" style="margin-bottom:14px">This host has no Proxmox VM ID set — the snapshot stage will fail. Set it via the Fleet host record before running for real.</div>` : ''}
    ${renderUntestedScriptWarning()}
    ${needsOverride ? `
      <div class="banner warning" style="flex-direction:column;align-items:stretch;gap:9px">
        <div>Outside the approved window (${pad2(t.window_start)}:00–${pad2(t.window_end)}:00 UTC). ${canOverride ? 'This is a supervised override — give a reason and confirm below.' : 'Your role cannot override this — ask a Team Lead or Admin.'}</div>
        ${windowTimeline(t.window_start, t.window_end)}
        ${canOverride ? `
          <input id="override-reason" placeholder="Reason for running outside the window" value="${esc(r.windowOverrideReason)}" style="width:100%">
          <div style="font-size:11.5px">Type <span class="mono" style="background:var(--surface-2);border:1px solid var(--border);padding:1px 5px;border-radius:3px">${esc(r.host.hostname)}</span> to confirm this override.</div>
          <input id="confirm-text" placeholder="${esc(r.host.hostname)}" style="width:100%">` : ''}
      </div>` : ''}
    <div id="confirm-error"></div>
    <div style="display:flex;gap:8px;margin-top:10px">
      <button onclick="state.run.step=stepIndex('checklist');render()">Back</button>
      <button class="primary" ${needsOverride && !canOverride ? 'disabled' : ''} onclick="confirmAndRun()">Run patch</button>
    </div>`;
}
async function confirmAndRun(){
  const r = state.run;
  if(r.hosts) return confirmAndRunBatch();
  const t = r.ticketInfo;
  const needsTicket = requireTicket();
  const now = new Date();
  const inWindow = (needsTicket && t) ? within(now.getUTCHours(), t.window_start, t.window_end) : true;
  let overrideReason = null;
  if(needsTicket && !inWindow){
    const reasonInput = document.getElementById('override-reason');
    const reason = reasonInput ? reasonInput.value.trim() : '';
    if(!reason){ reasonInput && reasonInput.focus(); return; }
    // Type-to-confirm, proportional to blast radius: an out-of-window
    // override has to be typed out, not just clicked.
    const confirmInput = document.getElementById('confirm-text');
    if(!confirmInput || confirmInput.value.trim() !== r.host.hostname){
      document.getElementById('confirm-error').innerHTML = errorBanner(`Type the hostname (${r.host.hostname}) to confirm the override.`);
      confirmInput && confirmInput.focus();
      return;
    }
    overrideReason = reason;
  }
  const payload = {
    host_id: r.host.id,
    ticket_id: needsTicket ? r.ticketId : null,
    checklist: (state.checklistItems||[]).map((it,i) => ({ item_index:i, item_text:it.text })),
    window_override_reason: overrideReason,
    scope: state.runScope,
    containers: runScopeIncludesContainers() ? runContainerSelection() : [],
    severity_filter: state.runScope === 'containers' ? '' : (state.runSeverity || ''),
  };
  try{
    const job = await api.startRun(payload);
    r.jobId = job.id; r.job = job;
    state.run.step = stepIndex('progress');
    setHash(`run/job/${job.id}`);
    render();
    pollRun();
  }catch(e){
    document.getElementById('confirm-error').innerHTML = errorBanner(e.message);
  }
}

/* ---------- several machines (a batch) ---------- */
const BATCH_ROLLOUTS = [
  {id:'one_at_a_time', label:'One at a time',
   help:'Each machine starts when the previous one has finished, health check included. If one fails, the rest wait until you continue or stop.'},
  {id:'parallel', label:'In parallel',
   help:'Every machine starts now. A failure on one doesn’t stop the others — fastest, but a bad update reaches all of them.'},
];
function renderStepConfirmBatch(){
  const r = state.run;
  const t = r.ticketInfo;
  const needsTicket = requireTicket();
  const inWindow = (needsTicket && t) ? within(new Date().getUTCHours(), t.window_start, t.window_end) : true;
  const needsOverride = needsTicket && !inWindow;
  const canOverride = atLeast(state.user.role, 'lead');
  const scope = state.runScope;
  const scopeLabel = {os:'OS packages', containers:'Containers only', both:'OS packages + containers'}[scope];
  const noVmid = r.hosts.filter(h => snapshotMethod(h).fails);
  const confirmWord = `${r.hosts.length} machines`;
  return `
    ${renderScopePicker()}
    ${scope !== 'os' ? '<p class="card-help" style="margin:-8px 0 14px">Each machine updates all of its compose-managed containers. To pick containers, patch a machine on its own.</p>' : ''}
    <div class="card" style="margin-bottom:16px">
      <p class="card-title">Machines (${r.hosts.length})</p>
      <div class="batch-hosts">${r.hosts.map((h, i) => `
        <div class="batch-host"><span class="mono muted">${i + 1}</span><span class="mono" style="font-weight:600">${esc(h.hostname)}</span>
          <span class="grow"></span>${h.pending_updates ? sevChip(h.max_severity, h.pending_updates) : '<span class="muted" style="font-size:12px">nothing pending</span>'}
          <span class="topo-safe ${(TOPO_SAFE[h.safety_net] || TOPO_SAFE.none).cls}">${(TOPO_SAFE[h.safety_net] || TOPO_SAFE.none).t}</span></div>`).join('')}</div>
      <table class="kv-table" style="margin-top:10px">
        ${needsTicket ? `<tr><td>Ticket</td><td>${esc(r.ticketId)}</td></tr>` : `<tr><td>Ticket</td><td class="muted">not required (disabled in Settings)</td></tr>`}
        <tr><td>Checklist</td><td style="color:var(--success)">${r.checklist.filter(Boolean).length} of ${r.checklist.length} confirmed</td></tr>
        <tr><td>Scope</td><td>${scopeLabel}${scope !== 'containers' && state.runSeverity ? ` &middot; ${esc(state.runSeverity)} only` : ''}</td></tr>
        <tr><td>Operator</td><td>${esc(state.user.display_name || state.user.username)}</td></tr>
      </table>
    </div>
    <div class="card" style="margin-bottom:16px">
      <p class="card-title">Roll out</p>
      <p class="card-help" style="margin-top:-4px">Choose how these machines are patched.</p>
      <div class="batch-rollouts">${BATCH_ROLLOUTS.map(o => `
        <label class="rb-option ${r.rollout===o.id?'on':''}"><input type="radio" name="batch-rollout" ${r.rollout===o.id?'checked':''} onclick="state.run.rollout='${o.id}';render()">
          <span><strong>${o.label}</strong><br><span class="muted" style="font-size:12px">${o.help}</span></span></label>`).join('')}</div>
    </div>
    ${noVmid.length ? `<div class="banner warning" style="margin-bottom:14px">No Proxmox VM ID on ${noVmid.map(h => esc(h.hostname)).join(', ')} — their snapshot step will fail and stop their run.</div>` : ''}
    ${renderUntestedScriptWarning()}
    ${needsOverride ? `
      <div class="banner warning" style="flex-direction:column;align-items:stretch;gap:9px">
        <div>Outside the approved window (${pad2(t.window_start)}:00–${pad2(t.window_end)}:00 UTC). ${canOverride ? 'This is a supervised override — give a reason and confirm below.' : 'Your role cannot override this — ask a Team Lead or Admin.'}</div>
        ${windowTimeline(t.window_start, t.window_end)}
        ${canOverride ? `
          <input id="override-reason" placeholder="Reason for running outside the window" value="${esc(r.windowOverrideReason)}" style="width:100%">
          <div style="font-size:11.5px">Type <span class="mono" style="background:var(--surface-2);border:1px solid var(--border);padding:1px 5px;border-radius:3px">${esc(confirmWord)}</span> to confirm this override.</div>
          <input id="confirm-text" placeholder="${esc(confirmWord)}" style="width:100%">` : ''}
      </div>` : ''}
    <div id="confirm-error"></div>
    <div style="display:flex;gap:8px;margin-top:10px;align-items:center">
      <button onclick="state.run.step=stepIndex('checklist');render()">Back</button>
      <button class="primary" ${!r.rollout || (needsOverride && !canOverride) ? 'disabled' : ''} onclick="confirmAndRun()">Patch ${r.hosts.length} machines</button>
      ${r.rollout ? '' : '<span class="muted" style="font-size:12px">Choose how to roll out first.</span>'}
    </div>`;
}
async function confirmAndRunBatch(){
  const r = state.run;
  if(!r.rollout) return;
  const t = r.ticketInfo;
  const needsTicket = requireTicket();
  const inWindow = (needsTicket && t) ? within(new Date().getUTCHours(), t.window_start, t.window_end) : true;
  let overrideReason = null;
  if(needsTicket && !inWindow){
    const reasonInput = document.getElementById('override-reason');
    const reason = reasonInput ? reasonInput.value.trim() : '';
    if(!reason){ reasonInput && reasonInput.focus(); return; }
    const confirmInput = document.getElementById('confirm-text');
    const word = `${r.hosts.length} machines`;
    if(!confirmInput || confirmInput.value.trim() !== word){
      document.getElementById('confirm-error').innerHTML = errorBanner(`Type “${word}” to confirm the override.`);
      confirmInput && confirmInput.focus();
      return;
    }
    overrideReason = reason;
  }
  try{
    const batch = await api.startBatch({
      host_ids: r.hosts.map(h => h.id), rollout: r.rollout,
      ticket_id: needsTicket ? r.ticketId : null,
      checklist: (state.checklistItems||[]).map((it,i) => ({ item_index:i, item_text:it.text })),
      window_override_reason: overrideReason, scope: state.runScope,
      severity_filter: state.runScope === 'containers' ? '' : (state.runSeverity || ''),
    });
    r.batchId = batch.id; r.batch = batch;
    setHash(`run/batch/${batch.id}`);
    render();
    pollBatch();
    loadFleet();
  }catch(e){
    document.getElementById('confirm-error').innerHTML = errorBanner(e.message);
  }
}
const BATCH_STATE = {
  done: ['success', '&#10003;', 'done'], failed: ['danger', '&#10007;', 'failed'], cancelled: ['warning', '&#10007;', 'stopped'],
  running: ['info', '', 'running'], queued: ['info', '', 'starting'], waiting: ['neutral', '&#183;', 'waiting'],
  skipped: ['unknown', '&minus;', 'skipped'], 'not started': ['neutral', '&minus;', 'not started'],
};
// A big batch is filtered by state and shown BATCH_SHOWN at a time, so the
// failed or running machines aren't buried among hundreds of others.
const BATCH_SHOWN = 30;
const BATCH_FILTERS = [['all', 'All'], ['problem', 'Failed / stopped / skipped'], ['active', 'Running'], ['waiting', 'Waiting'], ['done', 'Done']];
function batchFilterOf(h){
  return ['failed', 'cancelled', 'skipped', 'not started'].includes(h.state) ? 'problem'
    : ['running', 'queued'].includes(h.state) ? 'active' : h.state === 'done' ? 'done' : 'waiting';
}
function batchFilterTabs(b){
  if(b.hosts.length <= BATCH_SHOWN) return '';
  const counts = {all: b.hosts.length};
  b.hosts.forEach(h => { const f = batchFilterOf(h); counts[f] = (counts[f] || 0) + 1; });
  const cur = state.batchFilter || 'all';
  return `<div class="fleet-tabs" style="margin-top:14px">${BATCH_FILTERS.map(([id, label]) =>
    `<button class="fleet-tab ${cur===id?'active':''}" onclick="state.batchFilter='${id}';state.batchShowAll=false;render()">${label}<span class="n ${id==='problem'&&counts[id]?'danger':''}">${counts[id] || 0}</span></button>`).join('')}</div>`;
}
function batchRowsMatching(b){
  const cur = state.batchFilter || 'all';
  return b.hosts.filter(h => cur === 'all' || batchFilterOf(h) === cur);
}
function batchRowsShown(b){
  const rows = batchRowsMatching(b);
  return state.batchShowAll ? rows : rows.slice(0, BATCH_SHOWN);
}
function batchMore(b){
  const n = batchRowsMatching(b).length;
  if(n <= BATCH_SHOWN) return '';
  return `<div class="pager"><span>${state.batchShowAll ? n : BATCH_SHOWN} of ${n}</span><span class="grow"></span>
    <button onclick="state.batchShowAll=!state.batchShowAll;render()">${state.batchShowAll ? 'Show fewer' : `Show all ${n}`}</button></div>`;
}
function renderBatchProgress(){
  const r = state.run, b = r.batch;
  if(!b) return `<div class="banner neutral">Loading batch…</div>`;
  const canAct = atLeast(state.user.role, 'operator');
  const rollout = b.rollout === 'parallel' ? 'in parallel' : 'one at a time';
  const c = b.counts;
  const head = {
    running: `<div class="banner info"><span class="pm-spin"></span><strong>Patching ${b.hosts.length} machines ${rollout}.</strong> ${c.done} done${c.failed ? `, ${c.failed} failed` : ''}.</div>`,
    paused: `<div class="banner warning" style="display:block"><strong>Paused: ${esc(b.paused_reason)}.</strong> The remaining machines wait for you.
      ${canAct ? `<div style="display:flex;gap:8px;margin-top:8px"><button class="primary" onclick="batchAction('continue')">Continue with the next machine</button><button onclick="batchAction('stop')">Stop the rest</button></div>` : ''}</div>`,
    stopped: `<div class="banner warning"><strong>Stopped.</strong> ${c.done} of ${b.hosts.length} patched; nothing more starts. Runs already going carry on.</div>`,
    done: `<div class="banner ${c.done === b.hosts.length ? 'success' : 'warning'}"><strong>Batch finished:</strong> ${c.done} of ${b.hosts.length} patched${c.failed ? `, ${c.failed} failed` : ''}${c.cancelled ? `, ${c.cancelled} stopped` : ''}${c.skipped ? `, ${c.skipped} skipped` : ''}.</div>`,
  }[b.status] || '';
  return `
    <div class="view-header">
      <p style="margin:0 0 8px"><a href="#" onclick="navHome('run');return false">&larr; Run patching</a></p>
      <h1 class="view-title">Batch ${b.id} <span class="mono" style="color:var(--text-secondary);font-weight:400;font-size:15px">/ ${b.hosts.length} machines, ${rollout}</span></h1>
      <p class="view-sub">Started by ${esc(b.operator)} &middot; ${esc(relTime(b.created_at))}</p>
    </div>
    ${head}
    ${batchFilterTabs(b)}
    <div class="panel" style="margin-top:${b.hosts.length > BATCH_SHOWN ? 0 : 14}px">${batchRowsShown(b).map(h => {
      const [cls, glyph, label] = BATCH_STATE[h.state] || BATCH_STATE.waiting;
      return `<div class="batch-row ${h.job_id ? 'link' : ''}" ${h.job_id ? `onclick="openJobProgress(${h.job_id})"` : ''}>
        <span class="mono muted">${h.order}</span>
        <span class="mono" style="font-weight:600">${esc(h.hostname)}</span>
        <span class="badge ${cls}">${glyph ? `<span class="g">${glyph}</span>` : (h.state === 'running' || h.state === 'queued') ? '<span class="pm-spin"></span>' : ''}${label}</span>
        <span class="muted" style="font-size:12px">${h.stage ? `${esc(stageLabels[h.stage] || h.stage)} &middot; ${h.stage_index + 1}/${h.stage_count}` : h.skipped ? esc(h.skipped) : ''}</span>
        <span class="grow"></span>${h.job_id ? `<span class="mono muted" style="font-size:11.5px">run ${h.job_id} &rarr;</span>` : ''}
      </div>`;
    }).join('') || '<div class="section-empty">No machine in this batch is in that state.</div>'}
    ${batchMore(b)}</div>
    ${canAct && b.status === 'running' && b.rollout === 'one_at_a_time' ? `<div style="margin-top:14px"><button onclick="batchAction('stop')">Stop after the current machine</button></div>` : ''}`;
}
async function batchAction(what){
  const r = state.run;
  if(what === 'stop'){
    const ok = await confirmDialog({title: 'Stop the batch', confirmLabel: 'Stop', danger: true,
      message: 'No more machines start. A run already going carries on — force-stop it from its own page if needed.'});
    if(!ok) return;
  }
  try{ r.batch = await (what === 'stop' ? api.stopBatch(r.batchId) : api.continueBatch(r.batchId)); render(); pollBatch(); }
  catch(e){ toast(e.message, 'danger'); }
}
function pollBatch(){
  const r = state.run;
  if(r.pollHandle) clearInterval(r.pollHandle);
  r.pollHandle = setInterval(async () => {
    try{
      r.batch = await api.getBatch(r.batchId);
      if(state.nav === 'run' && state.run === r) render();
      if(r.batch.status === 'done' || (r.batch.status === 'stopped' && r.batch.finished_at)){
        clearInterval(r.pollHandle); r.pollHandle = null; loadFleet();
      }
    }catch(e){ /* transient — next tick will retry */ }
  }, 3000);
}

function renderStepProgress(){
  const r = state.run;
  if(!r.job) return `<div class="banner neutral">Starting run…</div>`;
  const job = r.job;
  const stageByName = Object.fromEntries(job.stages.map(s => [s.name, s]));
  const done = job.status === 'done';
  const failed = job.status === 'failed';
  const cancelled = job.status === 'cancelled';
  const active = job.status === 'running' || job.status === 'queued';
  const canForceStop = atLeast(state.user.role, 'lead');
  return `
    ${r.host ? '' : `<div class="banner neutral" style="margin-bottom:12px">Restored from a link/reload — host details unavailable, showing job ${job.id} directly.</div>`}
    ${stageDefs.map(name=>{
      const s = stageByName[name] || {status:'pending', executor:'agent', output:''};
      const st = s.status==='done' ? 'done' : s.status==='running' ? 'running' : s.status==='failed' ? 'failed' : 'waiting';
      const glyph = st==='done' ? '&#10003;' : st==='failed' ? '&#10007;' : st==='waiting' ? '&#183;' : '';
      const waitingOnAgent = s.status==='running' && s.executor==='agent';
      return `<div class="stage-row ${st==='waiting'?'waiting':''}" style="flex-direction:column;align-items:stretch;gap:2px">
        <div style="display:flex;gap:11px;align-items:center">
          <span class="stage-icon ${st}">${glyph}</span>
          <span style="font-weight:${st==='running'?600:400};color:${st==='waiting'?'var(--text-muted)':'var(--text-primary)'}">${stageLabels[name]}</span>
          ${waitingOnAgent ? `<span style="font-size:11px;color:var(--text-muted);margin-left:auto">waiting for agent…</span>` : ''}
        </div>
        ${s.output ? `<div class="log-tail ${st==='failed' ? 'full' : ''}" style="margin-left:28px">${esc(st==='failed' ? s.output : s.output.slice(0,400))}</div>` : ''}
      </div>`;
    }).join('')}
    ${runPackageProblems(job)}
    ${runAptHeldBack(job)}
    ${runRestoreOffer(job)}
    ${done ? `<div class="banner success" style="margin-top:16px">Run complete. Logged to the audit trail.</div>
      <button style="margin-top:4px" onclick="navigate('fleet')">Back to fleet</button>` : ''}
    ${failed ? `<div class="banner danger" style="margin-top:16px">Run failed — see stage output above for the reason.</div>
      <button style="margin-top:4px" onclick="navigate('fleet')">Back to fleet</button>` : ''}
    ${cancelled ? `<div class="banner warning" style="margin-top:16px">Run was force-stopped. This does <strong>not</strong> guarantee any command actually executing on the host was interrupted — kite just stopped tracking it. Check the host directly if you're unsure what state it's in.</div>
      <button style="margin-top:4px" onclick="navigate('fleet')">Back to fleet</button>` : ''}
    ${active ? `
      <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border)">
        ${canForceStop
          ? `<button class="danger-ghost" style="border:1px solid var(--danger)" onclick="forceStopRun(${job.id})">Force stop</button>
             <span style="font-size:11px;color:var(--text-muted);margin-left:8px">Stops tracking only — won't kill a command actually running on the host.</span>`
          : `<span style="font-size:11px;color:var(--text-muted)">Force-stopping a run requires lead role or higher.</span>`}
      </div>` : ''}
  `;
}
async function forceStopRun(jobId){
  const ok = await confirmDialog({
    title: 'Force stop this run?',
    message:
      "This stops kite from tracking the job and unlocks the host. " +
      "It does NOT send a stop signal to the agent — if a command (like dnf update) " +
      "is actually still executing on the host, it will keep running in the background.\n\n" +
      "Only do this if the agent appears unresponsive (host shows Offline) or you're " +
      "otherwise confident nothing is really still executing.",
    confirmLabel: 'Force stop', danger: true,
  });
  if(!ok) return;
  try{
    const job = await api.cancelRun(jobId);
    state.run.job = job;
    render();
    loadFleet();
    toast('Run force-stopped.', 'warning');
  }catch(e){
    state.loadError = e.message;
    render();
    toast(e.message, 'danger');
  }
}
function pollRun(){
  const r = state.run;
  if(r.pollHandle) clearInterval(r.pollHandle);
  r.pollHandle = setInterval(async () => {
    try{
      const job = await api.getRun(r.jobId);
      r.job = job;
      if(state.nav==='run' && r.step===stepIndex('progress')) render();
      if(job.status==='done' || job.status==='failed' || job.status==='cancelled'){
        clearInterval(r.pollHandle); r.pollHandle = null;
        loadFleet();
      }
    }catch(e){ /* transient — next tick will retry */ }
  }, 1500);
}
