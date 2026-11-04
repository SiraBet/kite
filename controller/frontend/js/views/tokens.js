/*
 * Settings → API tokens: read-only bearer tokens for scripts and the local
 * MCP server (tools/kite_mcp.py). Every role manages its own; admins
 * can list and revoke everyone's. The full token exists in the browser
 * exactly once — in state.tokenCreated, until the dialog is closed.
 */
/* ============================== API TOKENS ============================== */
const TOKEN_EXPIRY_CHOICES = [7, 30, 90, 180, 365];
const TOKEN_EXPIRING_SOON_DAYS = 7;

function daysUntil(iso){
  const d = parseUTC(iso);
  return d ? Math.ceil((d.getTime() - Date.now()) / 86400000) : null;
}
function tokenExpiryCell(t){
  if(t.expired) return `<span class="badge danger"><span class="g">&#9650;</span>Expired</span>`;
  const days = daysUntil(t.expires_at);
  const soon = days !== null && days <= TOKEN_EXPIRING_SOON_DAYS;
  return `<span class="mono" style="font-size:11.5px;${soon?'color:var(--due);font-weight:600':''}" title="${fmtTs(t.expires_at)} UTC">in ${days} d</span>`;
}
function renderApiTokens(){
  const isAdmin = atLeast(state.user.role, 'admin');
  const all = isAdmin && state.apiTokensAll;
  const tokens = state.apiTokens;
  const f = state.tokenForm;
  const cols = all ? '1.4fr 1.1fr 0.9fr 0.7fr 0.8fr 0.8fr 150px' : '1.6fr 0.9fr 0.7fr 0.8fr 0.8fr 150px';
  return `
    <div class="tok-head">
      <div>
        <p class="card-title" style="margin:0">API tokens</p>
        <p class="card-help" style="margin:2px 0 0">For scripts and MCP clients (AI assistants). A token acts as its owner, with the owner's role — never more — and is always <strong>read-only</strong>.</p>
      </div>
      ${isAdmin ? `<label class="tok-toggle"><input type="checkbox" ${all?'checked':''} onchange="toggleAllTokens(this.checked)"> All users <span class="tok-admin">ADMIN</span></label>` : ''}
    </div>

    <div class="card tok-form">
      <label class="grow">
        <span class="tok-lbl">Token name</span>
        <input id="tok-name" class="mono" placeholder="e.g. laptop-assistant" maxlength="64" value="${esc(f.name)}" oninput="state.tokenForm.name=this.value" onkeydown="if(event.key==='Enter') createApiToken()">
      </label>
      <label>
        <span class="tok-lbl">Expires after</span>
        <select id="tok-days" onchange="state.tokenForm.days=+this.value">
          ${TOKEN_EXPIRY_CHOICES.map(d=>`<option value="${d}" ${f.days===d?'selected':''}>${d} days${d===90?' (default)':''}</option>`).join('')}
        </select>
      </label>
      <button class="primary" onclick="createApiToken()">Create token</button>
    </div>

    ${tokens===null ? '<div class="loading-rows"><div class="skeleton" style="height:38px"></div><div class="skeleton" style="height:38px"></div></div>' : `
    <div class="panel">
      <div class="panel-head" style="grid-template-columns:${cols}">
        <div>Name</div>${all?'<div>Owner</div>':''}<div>Prefix</div><div>Created</div><div>Expires</div><div>Last used</div><div></div>
      </div>
      ${tokens.length===0 ? `<div class="section-empty" style="padding:22px 16px">No tokens${all?'':' yet'}. Create one above to connect the MCP server or a script.</div>` : tokens.map(t => {
        const soon = !t.expired && (daysUntil(t.expires_at) ?? 99) <= TOKEN_EXPIRING_SOON_DAYS;
        const mine = t.username === state.user.username;
        return `
        <div class="panel-row ${t.expired ? 'rail-unknown' : soon ? 'rail-due' : ''}" style="grid-template-columns:${cols}">
          <div class="mono" style="font-weight:500;font-size:12.5px;${t.expired?'text-decoration:line-through;color:var(--text-muted)':''}">${esc(t.name)}</div>
          ${all ? `<div class="secondary" style="font-size:12px">${esc(t.username)}${mine?' <span class="muted">(you)</span>':''}</div>` : ''}
          <div class="mono secondary" style="font-size:11.5px">${esc(t.prefix)}&hellip;</div>
          <div class="mono secondary" style="font-size:11.5px" title="${fmtTs(t.created_at)} UTC">${fmtDate(t.created_at)}</div>
          <div>${tokenExpiryCell(t)}</div>
          <div class="mono" style="font-size:11.5px">${t.last_used_at ? relTime(t.last_used_at) : '<i class="muted">never</i>'}</div>
          <div style="text-align:right">${state.tokenRevoking===t.id ? '' : t.expired
            ? `<button style="padding:4px 10px;font-size:11.5px" onclick="askRevokeToken(${t.id})">Remove</button>`
            : `<button class="danger-outline" style="padding:4px 10px;font-size:11.5px" onclick="askRevokeToken(${t.id})">Revoke</button>`}</div>
        </div>
        ${state.tokenRevoking===t.id ? renderRevokeConfirm(t, mine) : ''}`;
      }).join('')}
      <div class="pager"><span>Only the prefix is stored in readable form. A lost token can't be recovered — revoke it and create a new one.</span></div>
    </div>`}
    ${state.tokenCreated ? renderTokenCreated() : ''}`;
}
function renderRevokeConfirm(t, mine){
  const who = mine ? 'Yours' : `Owned by ${esc(t.username)}`;
  const used = t.last_used_at ? `last used <strong>${relTime(t.last_used_at)}</strong>` : 'never used';
  return `
    <div class="tok-revoke">
      <p class="modal-title" style="font-size:13.5px;margin:0 0 4px">${t.expired?'Remove':'Revoke'} <span class="mono">${esc(t.name)}</span>?</p>
      <p class="modal-message" style="margin:0 0 12px">${who} &middot; ${used}. ${t.expired ? 'It has already expired; this removes it from the list.' : 'Anything using it stops working immediately. This can’t be undone.'}</p>
      <div class="modal-actions">
        <button onclick="state.tokenRevoking=null;render()">Cancel</button>
        <button class="danger" onclick="revokeApiToken(${t.id})">${t.expired?'Remove':'Revoke token'}</button>
      </div>
    </div>`;
}
// What to run, then the server entry for an MCP client's configuration:
// the JSON shape most clients take (some add it with a command instead).
function mcpSetupCommand(token){
  const origin = `${location.protocol}//${location.host}`;
  const entry = {mcpServers: {kite: {command: 'python3', args: ['/path/to/kite_mcp.py'],
                                     env: {KITE_URL: origin, KITE_TOKEN: token}}}};
  return [
    `curl -fsSLo ~/kite_mcp.py ${origin}/download/mcp-server`,
    ``,
    `# then, in your MCP client's configuration (use the file's full path):`,
    JSON.stringify(entry, null, 2),
  ].join('\n');
}
function renderTokenCreated(){
  const t = state.tokenCreated;
  const cmd = mcpSetupCommand(t.token);
  return `
    <div class="modal-backdrop">
      <div class="modal tok-created">
        <div class="tok-created-head">
          <span class="tok-ok">&#10003;</span>
          <span class="modal-title" style="margin:0">Token <span class="mono">${esc(t.name)}</span> created</span>
          <span class="grow"></span>
          <span class="mono muted" style="font-size:11px">expires ${fmtDate(t.expires_at)}</span>
        </div>
        <div class="tok-created-body">
          <div class="banner warning" style="margin:0"><strong>This won't be shown again.</strong> Copy it now and store it somewhere safe.</div>
          <div>
            <span class="tok-lbl">Token</span>
            <div class="tok-copy">
              <input id="tok-created-value" class="mono" readonly value="${esc(t.token)}" onclick="this.select()">
              <button class="primary" onclick="copyTokenField('tok-created-value', this)">Copy</button>
            </div>
          </div>
          <div>
            <div style="display:flex;align-items:baseline;gap:8px">
              <span class="tok-lbl" style="margin:0">Add to an MCP client</span>
              <span class="muted" style="font-size:11px">runs locally — this controller's URL and the token are filled in</span>
              <span class="grow"></span>
              <a href="#" onclick="copyTokenField('tok-created-cmd', this);return false" style="font-size:11.5px;font-weight:600">Copy command</a>
            </div>
            <pre id="tok-created-cmd" class="cmd-block" style="margin-top:6px">${esc(cmd)}</pre>
            <p class="card-help" style="margin:6px 0 0">Using the default self-signed certificate? Add <code>"KITE_CA_FILE": "/path/to/root.crt"</code> to <code>env</code> (download it from <code>/download/ca.crt</code>). Check the setup with <code>python3 ~/kite_mcp.py --check</code>.</p>
          </div>
        </div>
        <div class="tok-created-foot">
          <label style="display:flex;align-items:center;gap:7px;font-size:12.5px"><input type="checkbox" id="tok-copied" onchange="document.getElementById('tok-done').disabled=!this.checked"> I've copied the token</label>
          <span class="grow"></span>
          <button id="tok-done" class="primary" disabled onclick="closeTokenCreated()">Done</button>
        </div>
      </div>
    </div>`;
}
function toggleAllTokens(on){ state.apiTokensAll = on; state.apiTokens = null; render(); loadApiTokens(); }
async function createApiToken(){
  const name = (document.getElementById('tok-name')||{}).value?.trim() || state.tokenForm.name.trim();
  if(!name){ toast('Give the token a name first.', 'warning'); return; }
  try{
    state.tokenCreated = await api.createToken(name, state.tokenForm.days);
    state.tokenForm = {name: '', days: state.tokenForm.days};
    await loadApiTokens();
  }catch(e){ toast(e.message, 'danger'); }
}
function closeTokenCreated(){ state.tokenCreated = null; render(); }
function askRevokeToken(id){ state.tokenRevoking = id; render(); }
async function revokeApiToken(id){
  try{
    await api.revokeToken(id);
    state.tokenRevoking = null;
    await loadApiTokens();
    toast('Token revoked.', 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
function copyTokenField(id, btn){
  const el = document.getElementById(id);
  const text = el.value !== undefined && el.tagName === 'INPUT' ? el.value : el.textContent;
  copyTextToClipboard(text).then(() => {
    const original = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = original; }, 1500);
  }).catch(() => toast('Could not copy automatically — select the text and copy manually.', 'warning'));
}
