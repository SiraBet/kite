/*
 * The single mutable `state` object every view renders from, plus the
 * client-side role helpers. Nothing here enforces anything — the server
 * does that (see app/auth.py); this only shapes what the UI offers.
 */
/* ============================== ROLE HINTS (client-side UX only — server enforces for real) ============================== */
const ROLE_RANK = {viewer:-1, operator:0, lead:1, admin:2};  // viewer = read-only, see app/auth.py
function atLeast(role, min){ return (ROLE_RANK[role] ?? -1) >= (ROLE_RANK[min] ?? 99); }

const state = {
  user: null,           // null = not logged in. {username, role, display_name}
  authChecked: false,   // avoids flashing the login screen before we've asked /auth/me
  loginError: '',
  nav: 'home',
  dashboard: null,      // aggregated home-page payload, GET /dashboard
  fleetTeamFilter: 'all',
  fleetTab: 'all',        // saved-view tab: all | needs | unreachable | current
  fleetSearch: '',        // query string (free text + field:value tokens)
  fleetPage: 0,           // client-side pagination
  fleetSort: {key: null, dir: 1},
  fleetSelected: new Set(),
  fleet: null,
  addMachine: null,       // {platform, hostname, team, role, result, pollHandle, connected, since} when the Add-machine drawer is open
  hostDetail: null,     // {host, runs} for the currently open host detail page
  hostContainers: null, // container inventory for the open host; null until fetched, [] = none reported
  hostUpdates: null,    // pending package updates for the open host; null until fetched
  hostNetwork: null,    // GET /hosts/{id}/network; null until fetched (operator+ only)
  hostShowContainerIfaces: false,
  runSeverity: '',      // '' = every update, 'security', or a severity list
  runScope: 'os',       // 'os' | 'containers' | 'both' -- what the next run may touch
  runContainers: null,  // updatable containers on the run's host; null until fetched
  runContainerPick: null, // Set of selected names; null means "all of them"
  hostDetailId: null,
  defs: null,
  defsHistoryOpen: {},
  defsHistoryData: {},
  auditLog: null,
  auditResult: 'all',   // activity-log result filter (tone)
  auditActor: 'all',    // activity-log actor filter: all | people | auto
  osScripts: null,
  osScriptsHistoryOpen: {},
  osScriptsHistoryData: {},
  osScriptsGroupOpen: {},
  scriptsFamily: null,      // selected family in the master-detail scripts view
  agentUpdateMode: null,    // Settings → Agent updates: the choice not yet saved (latest | pin | off)
  agentUpdatePin: null,
  coveragePage: 0,          // Fleet → Coverage: which page of 50
  vulnsPage: 0,             // Fleet → Vulnerabilities: which page of 50
  vulnsHostsOpen: {},       // CVE -> list every machine, not the first five
  hostVulnsPage: 0,
  defsPage: 0,              // Update rules: which page of 25
  defsTargetsOpen: {},      // rule id -> show every target, not the first three
  batchFilter: 'all',       // batch page: which machines to list
  batchShowAll: false,
  runHomeAllActive: false,  // Run patching: list every run in progress, not the first 10
  groups: null,             // machine groups (GET /groups): [{id, name, description, host_ids}]
  scriptsListQ: '',         // Per-system scripts: search over families and groups
  scriptsMemberQ: '',       // search within the selected group's machines
  scriptsPick: [],          // machines ticked to add to the selected group
  groupEdit: null,          // the group whose name/description is being edited, or 'new'
  newRuleKeys: [],          // the new rule's targets, as defTargets keys; [] = every machine
  newRule: {pkg: '', mode: 'skip', version: '', reason: ''},
  defTargets: null,         // Update rules: {id: 'new' | rule id, keys: ['os:rocky9', 'group:3', 'host:7'], q: ''}
  scriptsPickQ: '',         // filter for that list
  scriptsCodeOpen: {},      // family/stage -> bool (inline code viewer)
  scriptsCodeData: {},      // family/stage -> fetched script text
  users: null,
  passwordResetResult: null,  // {username, new_password} shown once after a reset
  passwordResetDialog: null,  // {id, username} while the reset dialog is open
  choosePasswordError: '',
  checklistItems: null,       // [{id, text, created_by}], admin-editable template
  schedules: null,
  tickets: null,               // [{ticket_id, status, ...}] -- powers the ticket-ID suggestion list on the Run and Schedules pages
  showNewTicketForm: false,
  settings: null,       // {require_ticket: 'true'|'false'}
  settingsTab: 'policy',  // policy | connections | notifications | access | tokens
  pmTest: null,           // last Proxmox "Test connection" result, shown under the form
  pmTesting: false,
  pmForm: null,           // the connection form's in-progress values
  pmConnections: null,    // GET /settings/proxmox-connections; null until loaded
  pmEditing: null,        // id of the connection being edited; null = the form adds a new one
  pmRowTest: null,        // {id, result} for a Test pressed on a saved connection
  fleetSection: 'hosts',  // hosts | coverage -- the two pages under Fleet
  apiTokens: null,        // GET /tokens (or ?all=true); null until fetched
  apiTokensAll: false,    // admin "All users" toggle
  tokenForm: {name: '', days: 90},
  tokenCreated: null,     // the create response, holding the full token -- shown once, cleared on close
  tokenRevoking: null,    // id of the row whose inline revoke confirm is open
  coverage: null,         // GET /proxmox/coverage
  coverageLoading: false,
  coverageFilter: 'all',  // all | unmanaged | name_match | ignored | managed
  coverageShowTemplates: false,
  coverageIgnoring: null, // {vmid, name} while the Ignore dialog is open
  hostSnapshots: null,
  hostSoftware: null,     // GET /hosts/{id}/software for the open machine page
  hostSoftwareQ: '',      // its search box
  hostVulns: null,        // GET /hosts/{id}/vulnerabilities for the open machine page
  hostVulnsQ: '',
  vulns: null,            // GET /vulnerabilities for Fleet -> Vulnerabilities
  vulnsQ: '',
  vulnsSeverity: '',      // '' = every level
  vulnStatus: null,       // GET /vulnerabilities/status for Settings -> Vulnerabilities
  hostTab: 'updates',     // machine page: which tab is open (kept across machines)
  hostPortsTable: false,  // machine page Network tab: full table instead of chips
  hostUpdatesAll: {},     // machine page: update groups expanded past the first ten    // GET /hosts/{id}/snapshots for the open machine page
  batchesRecent: null,    // GET /batches for the Run patching page
  fleetFetchedAt: null,   // when state.fleet was last fetched (ms)
  fleetRefreshing: false,
  agentUpdates: null,     // GET /agents/updates: published agent versions and who's behind
  topology: null,         // GET /topology
  topologyLoading: false,
  topo: {k: 0.6, tx: 20, ty: 20, fitted: false, sel: null, colorBy: 'severity', filter: 'all',
         q: '', showTemplates: false, collapsed: {}, expanded: null,
         full: false,        // full-screen map
         portsOpen: false,   // a bridge's "Listening on this bridge" list, folded by default
         moved: null},       // {card key: [dx, dy]} -- loaded from localStorage on first use
  topoContainers: {},     // host id -> its containers for Topology's VM -> runtime -> container chain; null while loading
  loadError: null,
  dbBackups: null,        // Settings → Policy: {keep, dir, backups: [{name, size_bytes, taken_at}]}
  controllerCa: null,     // {available, sha256}: the root CA enrol commands pin; from /download/ca
  agentDownloads: null,   // [{platform, available, sha256, ...}] from /download/agents; null until asked for
  run: {
    step: 0,
    host: null,
    ticketId: '',
    ticketInfo: null,
    ticketError: '',
    windowOverrideReason: '',
    checklist: [],  // sized to state.checklistItems by startRun() once a wizard actually opens
    jobId: null,
    job: null,
    pollHandle: null,
    familyScripts: null,
  },
};

// Used to be a hardcoded 4-item array here: now admin-editable,
// see state.checklistItems / Settings -> Checklist items / api.listChecklistItems).
const stageDefs = ['preflight','snapshot','excludes','patch','reboot','healthcheck','soak'];
const stageLabels = {
  preflight:'Pre-flight & lock', excludes:'Exclude / pin list', snapshot:'Snapshot',
  patch:'Patch', reboot:'Reboot logic', healthcheck:'Health check', soak:'Soak & final check',
};
const scriptableStages = ['preflight','excludes','patch']; // 'reboot' deliberately excluded — see controller's models.py comment
