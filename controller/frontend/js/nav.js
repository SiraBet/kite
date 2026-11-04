/*
 * The sidebar, and navigate() — which owns which data each tab needs.
 */
/* ============================== NAV ============================== */
const ICONS = {
  home: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 13h4v8H3zM10 8h4v13h-4zM17 3h4v18h-4z"/></svg>',
  fleet: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
  topology: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-3h14v3"/></svg>',
  run: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>',
  defs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h9a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H9"/><path d="M9 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h3"/><path d="M13 8h4M13 12h4M13 16h4"/></svg>',
  scripts: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>',
  audit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v4l3 2"/><circle cx="12" cy="12" r="9"/></svg>',
  schedules: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18M8 15h.01M12 15h.01M16 15h.01"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
};
const LOCK_ICON = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/></svg>';
const navItems = {
  home:      {label:'Overview'},
  fleet:     {label:'Fleet'},
  topology:  {label:'Topology'},
  run:       {label:'Run patching', minRole:'operator'},
  defs:      {label:'Update rules'},
  scripts:   {label:'Per-system scripts'},
  schedules: {label:'Schedules'},
  audit:     {label:'Activity log'},
  settings:  {label:'Settings'},  // non-admins see only API tokens there -- see renderSettings()
};
// Grouped exactly as the console's information architecture: the daily
// working surfaces first, then policy, then the record.
const navGroups = [
  {label:'',       ids:['home','fleet','topology','run']},
  {label:'Policy', ids:['defs','scripts','schedules']},
  {label:'Record', ids:['audit','settings']},
];
function renderNav(){
  if(!state.user || state.user.must_change_password){ document.getElementById('nav').innerHTML = ''; return; }
  const effectiveNav = state.nav === 'host' ? 'fleet' : state.nav; // host detail lives under Fleet
  // Live-run count, for the badge on the Run tab.
  const live = state.dashboard?.runs?.active || (state.dashboard?.active_runs||[]).length || 0;
  const total = state.dashboard?.fleet?.total ?? (state.fleet ? state.fleet.length : null);
  const env = `
    <div class="env-chip">
      <div class="lbl">Environment</div>
      <div class="val"><span class="dot"></span>controller${total!=null?`<span class="n">${total} host${total===1?'':'s'}</span>`:''}</div>
    </div>`;
  const groupHtml = g => {
    const rows = g.ids
      .filter(id => !navItems[id].minRole || atLeast(state.user.role, navItems[id].minRole))
      .map(id => {
        const n = navItems[id];
        let badge = '';
        if(id==='run' && live) badge = `<span class="nav-badge live">${live} live</span>`;
        else if(id==='audit' && state.auditLog) badge = `<span class="nav-badge">${state.auditLog.length}</span>`;
        return `<div class="nav-item ${effectiveNav===id?'active':''}" onclick="navClick('${id}')" title="${effectiveNav===id ? 'Click again for the main page' : ''}">
          <span class="nav-icon">${ICONS[id]}</span><span class="grow">${n.label}</span>${badge}
        </div>`;
      }).join('');
    if(!rows) return '';
    return (g.label ? `<div class="nav-section-label">${g.label}</div>` : '') + rows;
  };
  document.getElementById('nav').innerHTML = env + navGroups.map(groupHtml).join('');
}
function renderUserBox(){
  const box = document.getElementById('user-box');
  if(!state.user || state.user.must_change_password){ box.innerHTML = ''; return; }
  box.innerHTML = `
    <div class="role-label">Signed in as</div>
    <div class="who">${esc(state.user.display_name || state.user.username)}</div>
    <div class="role">${esc(state.user.role === 'viewer' ? 'read-only' : state.user.role)}</div>
    <button onclick="doLogout()">Log out</button>`;
}
// Tabs remember where you were (a run's progress, Coverage, a settings
// tab). Clicking the tab you're already on -- so also a double-click --
// takes you to its main page instead.
function navClick(id){
  const current = state.nav === 'host' ? 'fleet' : state.nav;
  if(current === id) navHome(id);
  else navigate(id);
}
function navHome(id){
  if(id === 'run'){
    if(state.run.pollHandle){ clearInterval(state.run.pollHandle); state.run.pollHandle = null; }
    state.run = {...state.run, step: 0, host: null, hosts: null, jobId: null, job: null, batchId: null, batch: null};
    setHash('run');
    loadDashboard();   // the runs listed on the tab's page
    loadBatchesRecent();
  }
  if(id === 'fleet'){ state.fleetSection = 'hosts'; state.hostDetailId = null; }
  if(id === 'topology'){ state.topo.sel = null; state.topo.expanded = null; }
  if(id === 'settings') state.settingsTab = atLeast(state.user.role, 'admin') ? 'policy' : 'tokens';
  navigate(id);
}
function navigate(id){
  // Stop polling if we're leaving the Run tab — otherwise a forgotten
  // background poll keeps hitting the API every 1.5s indefinitely.
  if(state.nav==='run' && id!=='run' && state.run.pollHandle){
    clearInterval(state.run.pollHandle);
    state.run.pollHandle = null;
  }
  state.nav = id; render();
  // Only plain-tab hashes here — 'run' sets its own #run/job|host/<id>
  // hash elsewhere (startRun, confirmAndRun, openJobProgress), since it
  // needs to carry which job/host, not just the tab name.
  if(id!=='run') setHash(id);
  if(id==='home') loadDashboard();
  if(id==='run' && !state.run.host && !state.run.jobId){ loadDashboard(); loadBatchesRecent(); }
  if(id==='run' && state.defs===null) loadDefs();   // which uninstallable packages already have a skip rule
  if(id==='fleet') loadFleet();   // always fresh on arrival, whatever was kept from earlier
  if(id==='fleet') loadAgentUpdates();
  if(id==='fleet' && state.fleetSection==='coverage') loadCoverage();
  if(id==='fleet' && state.fleetSection==='vulns') loadVulns();
  if(id==='topology') loadTopology();
  // A still-open Add-machine drawer had its check-in poll stopped when we
  // navigated away; restart it now that the fleet view is back.
  if(id==='fleet') resumeAddMachinePoll();
  if(id==='defs' && state.defs===null) loadDefs();
  if(id==='defs' && state.fleet===null) loadFleet();
  if(id==='scripts' && state.osScripts===null) loadOsScripts();
  if(['scripts', 'defs', 'host', 'run'].includes(id)) loadGroups();
  // renderScripts() derives the family list and per-family host counts from
  // the fleet, so it needs it too, not just the scripts themselves.
  if(id==='scripts' && state.fleet===null) loadFleet();
  if(id==='audit') loadAudit();
  if(id==='settings'){
    if(!atLeast(state.user.role, 'admin')) state.settingsTab = 'tokens';
    if(state.settingsTab==='tokens') loadApiTokens();
    if(atLeast(state.user.role, 'admin')){ loadSettings(); loadUsers(); loadProxmoxConnections(); loadAgentUpdates(); loadDbBackups(); if(state.checklistItems===null) loadChecklistItems(); }
  }
  if(id==='schedules'){
    if(state.schedules===null) loadSchedules();
    if(state.tickets===null) loadTickets();
    if(state.fleet===null) loadFleet();  // powers the Team select's option list
    state.showNewTicketForm = false;
  }
}
