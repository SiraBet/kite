/*
 * Everything that talks to the controller. One place to look for the
 * HTTP contract, and the only place `fetch` appears.
 */
/* ============================== API LAYER ============================== */
// `asText` is for the endpoints that return a file body rather than JSON
// (a stage script's source). They still need the 401 handling below, which
// is the whole reason they go through here instead of calling fetch directly.
async function apiCall(method, path, body, isForm, asText){
  const opts = { method, headers: {} };
  if(body !== undefined){
    if(isForm){ opts.body = body; }
    else { opts.headers['content-type'] = 'application/json'; opts.body = JSON.stringify(body); }
  }
  const res = await fetch(path, opts);
  if(res.status === 401){
    // Stop the polls first: each would otherwise get its own 401 and
    // re-render, wiping whatever is being typed into the login form.
    stopPolls();
    const wasSignedIn = !!state.user;
    state.user = null;
    if(wasSignedIn) render();
    throw new Error('Session expired — please log in again.');
  }
  if(!res.ok){
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.detail || detail; } catch(e){}
    if(res.status === 403 && detail === 'password_change_required' && state.user){
      state.user.must_change_password = true;
      render();
      throw new Error('Choose your own password to continue.');
    }
    throw new Error(detail);
  }
  if(res.status === 204) return null;
  const text = await res.text();
  if(asText) return text;
  return text ? JSON.parse(text) : null;
}
const api = {
  me: () => apiCall('GET', '/auth/me'),
  login: (username, password) => apiCall('POST', '/auth/login', {username, password}),
  logout: () => apiCall('POST', '/auth/logout'),
  changePassword: (current_password, new_password) => apiCall('POST', '/auth/change-password', {current_password, new_password}),

  listUsers: () => apiCall('GET', '/users'),
  createUser: (body) => apiCall('POST', '/users', body),
  deleteUser: (id) => apiCall('DELETE', `/users/${id}`),
  resetPassword: (id, temporary_password) => apiCall('POST', `/users/${id}/reset-password`, {temporary_password: temporary_password || ''}),
  patchUser: (id, body) => apiCall('PATCH', `/users/${id}`, body),

  listChecklistItems: () => apiCall('GET', '/checklist-items'),
  addChecklistItem: (text) => apiCall('POST', '/checklist-items', {text}),
  deleteChecklistItem: (id) => apiCall('DELETE', `/checklist-items/${id}`),

  listSchedules: () => apiCall('GET', '/schedules'),
  createSchedule: (body) => apiCall('POST', '/schedules', body),
  updateSchedule: (id, body) => apiCall('PATCH', `/schedules/${id}`, body),
  deleteSchedule: (id) => apiCall('DELETE', `/schedules/${id}`),

  listSettings: () => apiCall('GET', '/settings'),
  updateSetting: (key, value) => apiCall('PUT', `/settings/${key}`, {value}),
  setRollbackProxmoxSecret: (value) => apiCall('PUT', '/settings/rollback-proxmox-secret', {value}),
  setSecretSetting: (name, value) => apiCall('PUT', `/settings/secret/${name}`, {value}),
  testProxmox: (body) => apiCall('POST', '/settings/proxmox-test', body),
  listProxmoxConnections: () => apiCall('GET', '/settings/proxmox-connections'),
  createProxmoxConnection: (body) => apiCall('POST', '/settings/proxmox-connections', body),
  updateProxmoxConnection: (id, body) => apiCall('PATCH', `/settings/proxmox-connections/${id}`, body),
  deleteProxmoxConnection: (id) => apiCall('DELETE', `/settings/proxmox-connections/${id}`),

  listHosts: () => apiCall('GET', '/hosts'),
  getHost: (id) => apiCall('GET', `/hosts/${id}`),
  patchHost: (id, body) => apiCall('PATCH', `/hosts/${id}`, body),
  deleteHost: (id) => apiCall('DELETE', `/hosts/${id}`),
  resolveVmid: (id) => apiCall('POST', `/hosts/${id}/resolve-vmid`),
  createEnrollToken: (body) => apiCall('POST', '/enroll/tokens', body),
  listAgentDownloads: () => apiCall('GET', '/download/agents'),
  controllerCa: () => apiCall('GET', '/download/ca'),
  listBackups: () => apiCall('GET', '/backups'),
  backupNow: () => apiCall('POST', '/backups'),

  getTicket: (id) => apiCall('GET', `/tickets/${encodeURIComponent(id)}`),
  createTicket: (body) => apiCall('POST', '/tickets', body),
  listTickets: () => apiCall('GET', '/tickets'),

  listDefs: () => apiCall('GET', '/defs'),
  addDef: (body) => apiCall('POST', '/defs', body),
  delDef: (id) => apiCall('DELETE', `/defs/${id}`),
  defHistory: (id) => apiCall('GET', `/defs/${id}/history`),

  startRun: (body) => apiCall('POST', '/runs', body),
  getRun: (id) => apiCall('GET', `/runs/${id}`),
  listRunsForHost: (hostId) => apiCall('GET', `/runs?host_id=${hostId}`),
  cancelRun: (id) => apiCall('POST', `/runs/${id}/cancel`),

  listAudit: () => apiCall('GET', '/audit?limit=200'),

  listTokens: (all) => apiCall('GET', all ? '/tokens?all=true' : '/tokens'),
  createToken: (name, expires_in_days) => apiCall('POST', '/tokens', {name, expires_in_days}),
  revokeToken: (id) => apiCall('DELETE', `/tokens/${id}`),

  getCoverage: (refresh) => apiCall('GET', refresh ? '/proxmox/coverage?refresh=true' : '/proxmox/coverage'),
  ignoreGuest: (vmid, reason, connection_id) => apiCall('POST', '/proxmox/ignored', {vmid, reason, connection_id: connection_id ?? null}),
  unignoreGuest: (vmid, connection_id) => apiCall('DELETE', `/proxmox/ignored/${vmid}${connection_id != null ? `?connection_id=${connection_id}` : ''}`),
  setGateway: (vmid, connection_id, gateway) => apiCall('POST', '/proxmox/gateway', {vmid, connection_id: connection_id ?? null, gateway}),
  clearGateway: (vmid, connection_id) => apiCall('DELETE', `/proxmox/gateway/${vmid}${connection_id != null ? `?connection_id=${connection_id}` : ''}`),
  hostSoftware: (id) => apiCall('GET', `/hosts/${id}/software`),
  hostVulns: (id) => apiCall('GET', `/hosts/${id}/vulnerabilities`),
  fleetVulns: () => apiCall('GET', '/vulnerabilities?limit=5000'),
  vulnStatus: () => apiCall('GET', '/vulnerabilities/status'),
  refreshVulns: () => apiCall('POST', '/vulnerabilities/refresh'),
  hostSnapshots: (id) => apiCall('GET', `/hosts/${id}/snapshots`),
  keepSnapshot: (id, name, keep) => apiCall('POST', `/hosts/${id}/snapshots/${encodeURIComponent(name)}/keep`, {keep}),
  deleteSnapshot: (id, name) => apiCall('DELETE', `/hosts/${id}/snapshots/${encodeURIComponent(name)}`),
  restoreSnapshot: (id, name, confirm, start=true) => apiCall('POST', `/hosts/${id}/snapshots/${encodeURIComponent(name)}/restore`, {confirm, start}),
  startBatch: (body) => apiCall('POST', '/batches', body),
  getBatch: (id) => apiCall('GET', `/batches/${id}`),
  listBatches: () => apiCall('GET', '/batches'),
  continueBatch: (id) => apiCall('POST', `/batches/${id}/continue`),
  stopBatch: (id) => apiCall('POST', `/batches/${id}/stop`),
  agentUpdates: () => apiCall('GET', '/agents/updates'),
  setAgentUpdate: (version, host_id) => apiCall('POST', '/agents/updates', {version, host_id: host_id ?? null}),
  cancelAgentUpdate: (host_id) => apiCall('DELETE', `/agents/updates${host_id != null ? `?host_id=${host_id}` : ''}`),
  getTopology: (refresh) => apiCall('GET', refresh ? '/topology?refresh=true' : '/topology'),
  refreshNetwork: () => apiCall('POST', '/network/refresh'),
  hostNetwork: (id) => apiCall('GET', `/hosts/${id}/network`),
  getDashboard: () => apiCall('GET', '/dashboard'),
  hostContainers: (id) => apiCall('GET', `/hosts/${id}/containers`),
  hostUpdates: (id) => apiCall('GET', `/hosts/${id}/updates`),
  rollbackContainer: (hostId, name, ticket = {}) => apiCall('POST', '/runs', {host_id: hostId, scope: 'containers', container_action: 'rollback', containers: [name], checklist: [{item_index: 0, item_text: 'Container rollback requested from host detail'}], ...ticket}),

  listOsScripts: () => apiCall('GET', '/os-scripts'),
  scriptsForFamily: (family) => apiCall('GET', `/os-scripts/family/${encodeURIComponent(family)}`),
  scriptsForHost: (hostId) => apiCall('GET', `/os-scripts/host/${hostId}`),
  listGroups: () => apiCall('GET', '/groups'),
  createGroup: (body) => apiCall('POST', '/groups', body),
  editGroup: (id, body) => apiCall('PATCH', `/groups/${id}`, body),
  deleteGroup: (id) => apiCall('DELETE', `/groups/${id}`),
  addGroupMembers: (id, host_ids) => apiCall('POST', `/groups/${id}/members`, {host_ids}),
  removeGroupMembers: (id, host_ids) => apiCall('POST', `/groups/${id}/members/remove`, {host_ids}),
  setDefTargets: (id, targets) => apiCall('PUT', `/defs/${id}/targets`, {targets}),
  osScriptHistory: (family, stage) => apiCall('GET', `/os-scripts/${encodeURIComponent(family)}/${stage}/history`),
  osScriptContent: (family, stage) => apiCall('GET', `/os-scripts/${encodeURIComponent(family)}/${stage}/download`, undefined, false, true),
  deleteOsScript: (family, stage) => apiCall('DELETE', `/os-scripts/${encodeURIComponent(family)}/${stage}`),
  async uploadOsScript(family, stage, file){
    const fd = new FormData();
    fd.append('file', file);
    return apiCall('POST', `/os-scripts/${encodeURIComponent(family)}/${stage}/upload`, fd, true);
  },
};
