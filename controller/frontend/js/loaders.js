/*
 * Data fetchers. Each one owns a slice of `state` and re-renders only
 * if its own tab is still the one on screen.
 */
/* ============================== DATA LOADERS ============================== */
// Views that read state.fleet and so need repainting when it lands. The
// Schedules "Hosts" column and the Scripts family host counts are both
// derived from the fleet: re-rendering only on 'fleet' left them reading a
// flat 0 — a schedule targeting the whole fleet looked like it targeted
// nothing — until some unrelated re-render happened to come along.
const FLEET_DEPENDENT_VIEWS = ['fleet', 'schedules', 'scripts'];

// Each host is stamped with when it was fetched: connectivity is judged
// as of then (see connectivityTier), so a list kept in the page while you
// were elsewhere doesn't turn every host "unreachable" as it ages -- it's
// re-fetched whenever Fleet is opened or the browser tab comes back.
async function loadFleet(){
  state.fleetRefreshing = true;
  try{
    const hosts = await api.listHosts();
    const at = Date.now();
    hosts.forEach(h => { h._fetched_at = at; });
    state.fleet = hosts; state.fleetFetchedAt = at; state.loadError = null;
  }
  catch(e){ state.loadError = `Couldn't load fleet: ${e.message}`; if(state.fleet === null) state.fleet = []; }
  state.fleetRefreshing = false;
  if(FLEET_DEPENDENT_VIEWS.includes(state.nav)) render();
}
async function loadAgentUpdates(){
  try{ state.agentUpdates = await api.agentUpdates(); }
  catch(e){ state.agentUpdates = null; }   // the banner just doesn't show
  if(state.nav === 'fleet' || state.nav === 'host' || state.nav === 'settings') render();
}
async function loadBatchesRecent(){
  try{ state.batchesRecent = await api.listBatches(); }catch(e){ state.batchesRecent = []; }
  if(state.nav === 'run' && !state.run.host && !state.run.jobId && !state.run.hosts && !state.run.batchId) render();
}
async function loadDashboard(){
  try{ state.dashboard = await api.getDashboard(); state.loadError = null; }
  catch(e){ state.loadError = `Couldn't load dashboard: ${e.message}`; }
  if(state.nav==='home' || (state.nav==='run' && !state.run.host && !state.run.jobId)) render();
}
// Loaded lazily, only once the Windows tab of the enrolment panel is
// opened -- it is the only view that needs it, and a controller that has
// not built the agent should say so there rather than on every page load.
async function loadAgentDownloads(){
  try{ state.agentDownloads = await api.listAgentDownloads(); }
  catch(e){ state.agentDownloads = {error: e.message}; }
  // The root CA the enrol commands pin (app/controller_ca.py); without one
  // they fall back to turning certificate checks off.
  try{ state.controllerCa = await api.controllerCa(); }
  catch(e){ state.controllerCa = {available: false, sha256: ''}; }
  render();
}
async function loadDefs(){
  try{ state.defs = await api.listDefs(); state.loadError = null; }
  catch(e){ state.loadError = `Couldn't load definitions: ${e.message}`; state.defs = []; }
  if(state.nav==='defs' || state.nav==='run') render();
}
async function loadAudit(){
  try{ state.auditLog = await api.listAudit(); }
  catch(e){ state.loadError = `Couldn't load audit log: ${e.message}`; state.auditLog = []; }
  if(state.nav==='audit') render();
}
async function loadGroups(){
  try{ state.groups = await api.listGroups(); }
  catch(e){ state.groups = state.groups || []; }
  if(['scripts', 'defs', 'host', 'fleet', 'run'].includes(state.nav)) render();
}
async function loadOsScripts(){
  try{ state.osScripts = await api.listOsScripts(); state.loadError = null; }
  catch(e){ state.loadError = `Couldn't load OS scripts: ${e.message}`; state.osScripts = []; }
  if(state.nav==='scripts') render();
}
async function loadSettings(){
  try{
    const rows = await api.listSettings();
    state.settings = Object.fromEntries(rows.map(r => [r.key, r.value]));
  }catch(e){ state.loadError = e.message; }
  if(state.nav==='settings') render();
}
async function loadUsers(){
  try{ state.users = await api.listUsers(); }
  catch(e){ state.loadError = e.message; }
  if(state.nav==='settings') render();
}
async function loadChecklistItems(){
  state.checklistError = '';
  try{ state.checklistItems = await api.listChecklistItems(); }
  catch(e){ state.checklistError = e.message; }
  render();
}
async function loadSchedules(){
  try{ state.schedules = await api.listSchedules(); }
  catch(e){ state.loadError = e.message; state.schedules = []; }
  if(state.nav==='schedules') render();
}
// Powers the ticket-ID suggestion list on both the Run page and the
// Schedules "create" form — loaded once, quietly, wherever either might
// be reached, rather than duplicating the fetch in both places.
async function loadTickets(){
  try{ state.tickets = await api.listTickets(); }
  catch(e){ state.tickets = []; }
  render();
}
async function loadProxmoxConnections(){
  try{ state.pmConnections = await api.listProxmoxConnections(); }
  catch(e){ state.loadError = `Couldn't load Proxmox connections: ${e.message}`; state.pmConnections = []; }
  if(state.nav==='settings' || state.nav==='host') render();
}
async function loadApiTokens(){
  try{ state.apiTokens = await api.listTokens(state.apiTokensAll); }
  catch(e){ state.loadError = `Couldn't load API tokens: ${e.message}`; state.apiTokens = []; }
  if(state.nav==='settings') render();
}
// Coverage and topology both read Proxmox through the controller, which
// answers from its last fetch straight away; `refresh` waits for a new
// one. While a refresh is in flight the old numbers stay on screen under
// a "Fetching…" bar rather than blanking the page.
//
// When the controller is fetching a newer list in the background
// (proxmox.refreshing), ask again a little later -- quietly, no bar --
// and stop after a few tries: a Proxmox that's down is reported, not
// waited on.
const INVENTORY_RECHECK_MS = 4000, INVENTORY_RECHECKS = 5;
function recheckInventory(data, page, load, tries){
  if(!(data && data.proxmox && data.proxmox.refreshing) || tries >= INVENTORY_RECHECKS) return;
  setTimeout(() => {
    if(state.nav === page && (page !== 'fleet' || state.fleetSection === 'coverage')) load(false, tries + 1);
  }, INVENTORY_RECHECK_MS);
}
async function loadCoverage(refresh, recheck){
  const quiet = recheck !== undefined;
  if(!quiet){ state.coverageLoading = true; if(state.nav==='fleet') render(); }
  try{ state.coverage = await api.getCoverage(refresh); state.loadError = null; }
  catch(e){ state.loadError = `Couldn't load Proxmox coverage: ${e.message}`; }
  state.coverageLoading = false;
  if(state.nav==='fleet') render();
  recheckInventory(state.coverage, 'fleet', loadCoverage, recheck || 0);
}
async function loadTopology(refresh, recheck){
  if(recheck !== undefined){
    // A quiet re-read once the controller's background fetch is in: the
    // map keeps its expanded nodes and containers.
    try{ state.topology = await api.getTopology(false); state.loadError = null; }
    catch(e){ return; }
    if(state.nav==='topology') render();
    recheckInventory(state.topology, 'topology', loadTopology, recheck);
    return;
  }
  state.topologyLoading = true;
  state.topoContainers = {};  // re-fetched on the next expand, so a refresh shows current containers
  if(state.nav==='topology') render();
  try{
    // A manual refresh re-reads bridges and NICs too, rather than waiting
    // for the background pass. Best-effort: the map still refreshes if it fails.
    if(refresh && atLeast(state.user.role, 'operator')){ try{ await api.refreshNetwork(); }catch(e){} }
    state.topology = await api.getTopology(refresh); state.loadError = null;
  }
  catch(e){ state.loadError = `Couldn't load topology: ${e.message}`; }
  state.topologyLoading = false;
  if(state.nav==='topology') render();
  recheckInventory(state.topology, 'topology', loadTopology, 0);
}
// settings needed outside the Settings tab too (run flow) — load quietly once at boot
async function preloadSettingsQuietly(){
  try{
    const rows = await api.listSettings();
    state.settings = Object.fromEntries(rows.map(r => [r.key, r.value]));
  }catch(e){ /* fall back to default (require_ticket) */ }
}
