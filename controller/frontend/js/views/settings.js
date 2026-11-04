/*
 * Users, checklist template, rollback, notifications, LDAP (admin only),
 * plus API tokens, which every role manages for itself (views/tokens.js).
 */
/* ============================== SETTINGS ============================== */
const ROLLBACK_BACKENDS = [
  {id:'proxmox', label:'Proxmox snapshot'},
  {id:'dnf_history', label:'dnf history'},
  {id:'none', label:'None — no safety net'},
];
function rollbackBackendLabel(id){
  const b = ROLLBACK_BACKENDS.find(b => b.id === id);
  return b ? b.label : (id || 'proxmox');
}
function cfgBadge(isSet){
  // A secret shows a STATE, never a value — "Configured" or "Not set".
  return isSet
    ? `<span class="badge success"><span class="g">&#10003;</span>Configured</span>`
    : `<span class="badge neutral">Not set</span>`;
}
const SETTINGS_TABS = [
  {id:'policy', label:'Policy'},
  {id:'connections', label:'Connections'},
  {id:'notifications', label:'Notifications'},
  {id:'vulns', label:'Vulnerabilities'},
  {id:'access', label:'Users & roles'},
  {id:'tokens', label:'API tokens', anyRole:true},
];
const USER_ROLES = [
  {id:'viewer', label:'Read-only'},
  {id:'operator', label:'Operator'},
  {id:'lead', label:'Team Lead'},
  {id:'admin', label:'Admin'},
];
function setSettingsTab(id){
  state.settingsTab = id;
  state.tokenRevoking = null;
  state.pmTest = null;
  state.pmForm = null;
  state.pmEditing = null;
  state.pmRowTest = null;
  if(id==='tokens') loadApiTokens();
  if(id==='connections' || id==='policy') loadProxmoxConnections();
  if(id==='vulns') loadVulnStatus();
  render();
}
function renderSettings(){
  const isAdmin = atLeast(state.user.role, 'admin');
  // Everyone may hold API tokens; everything else here is admin-only.
  if(!isAdmin || state.settingsTab==='tokens'){
    const tabs = SETTINGS_TABS.filter(t => isAdmin || t.anyRole);
    return `
      <div class="view-header"><h1 class="view-title">Settings</h1><p class="view-sub">${isAdmin ? 'Tokens for scripts and MCP clients (AI assistants).' : 'Your API tokens. Everything else here is admin-only.'}</p></div>
      ${state.loadError ? errorBanner(state.loadError) : ''}
      <div class="fleet-tabs">
        ${tabs.map(t=>`<button class="fleet-tab ${t.id==='tokens'?'active':''}" onclick="setSettingsTab('${t.id}')">${t.label}</button>`).join('')}
      </div>
      ${renderApiTokens()}`;
  }
  const ticketOn = requireTicket();
  const skipOn = !!state.settings && state.settings.patch_skip_uninstallable === 'true';
  const snapOn = !state.settings || state.settings.snapshot_cleanup !== 'false';
  const s = state.settings || {};
  const tab = state.settingsTab || 'policy';
  const sub = {policy:'Ticket policy, the run checklist, the rollback safety net, and agent self-update.',
    connections:'Proxmox connections — secrets are shown as a state, never a value.',
    notifications:'Where the controller tells people what happened.',
    vulns:'Which CVEs each machine is exposed to, from the distributions’ own advisories.',
    access:'Who can sign in and what each role can do.'}[tab];
  const T = id => tab===id;
  return `
    <div class="view-header">
      <h1 class="view-title">Settings</h1>
      <p class="view-sub">${sub}</p>
    </div>
    ${state.loadError ? errorBanner(state.loadError) : ''}
    <div class="fleet-tabs">
      ${SETTINGS_TABS.map(t=>`<button class="fleet-tab ${tab===t.id?'active':''}" onclick="setSettingsTab('${t.id}')">${t.label}</button>`).join('')}
    </div>

    ${T('policy') ? `
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <p style="font-weight:500;margin:0 0 4px">Require an approved ticket to run a patch</p>
          <p style="font-size:12px;color:var(--text-secondary);margin:0">When off, the Ticket step is skipped entirely and runs need only checklist confirmation.</p>
        </div>
        <button class="${ticketOn?'primary':''}" onclick="toggleRequireTicket(${!ticketOn})">${ticketOn ? 'Enabled' : 'Disabled'} — click to ${ticketOn?'disable':'enable'}</button>
      </div>
    </div>
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:16px">
        <div>
          <p style="font-weight:500;margin:0 0 4px">Skip updates that can't be installed</p>
          <p style="font-size:12px;color:var(--text-secondary);margin:0">An update built for a newer OS, or from a repository missing a dependency, normally fails the whole patch step with nothing installed. When on, everything else is installed and the run lists what was left at its current version. Applies to dnf hosts; apt already holds such packages back.</p>
        </div>
        <button class="${skipOn?'primary':''}" style="flex:none" onclick="toggleSkipUninstallable(${!skipOn})">${skipOn ? 'Enabled' : 'Disabled'} — click to ${skipOn?'disable':'enable'}</button>
      </div>
    </div>
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:16px">
        <div>
          <p style="font-weight:500;margin:0 0 4px">Clean up old snapshots</p>
          <p style="font-size:12px;color:var(--text-secondary);margin:0">The Proxmox snapshot taken before each run is a way back from a bad patch, not a backup — kept around, each one holds on to disk space and long chains slow the VM's disk. kite removes its own older ones after each successful run and once a day. Never touched: snapshots it didn't take, ones from failed or stopped runs, and ones marked Keep on the machine page.</p>
        </div>
        <button class="${snapOn?'primary':''}" style="flex:none" onclick="setSnapshotSetting('snapshot_cleanup', '${snapOn ? 'false' : 'true'}')">${snapOn ? 'Enabled' : 'Disabled'} — click to ${snapOn?'disable':'enable'}</button>
      </div>
      ${snapOn ? `<div class="field-row" style="margin-top:12px;align-items:center;gap:10px;font-size:13px">
        Keep the newest <input id="snap-keep-count" type="number" min="0" max="1000" style="width:72px" value="${esc((state.settings||{}).snapshot_keep_count || '2')}"> per machine,
        none older than <input id="snap-keep-days" type="number" min="0" max="1000" style="width:72px" value="${esc((state.settings||{}).snapshot_keep_days || '7')}"> days
        <button onclick="saveSnapshotLimits()">Save</button>
        <span class="muted" style="font-size:11.5px">0 = no limit</span>
      </div>` : ''}
    </div>
    ${renderDbBackups()}

    <div class="view-header"><h1 class="view-title" style="font-size:16px">Checklist items</h1></div>
    <div class="card" style="margin-bottom:20px">
      <p class="card-help">Shown on every run's checklist step. At least one item is required — a run can't start without something to confirm.</p>` : ''}
    ${T('policy') ? `
      ${state.checklistItems===null ? '<div class="banner neutral">Loading…</div>' : `
      <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:12px">
        ${state.checklistItems.map(i=>`
          <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:7px 10px;background:var(--surface-0);border-radius:var(--radius)">
            <span style="font-size:13px">${esc(i.text)}</span>
            <button class="danger-ghost" title="Remove" ${state.checklistItems.length<=1?'disabled':''} onclick="removeChecklistItem(${i.id})">✕</button>
          </div>`).join('') || '<div class="banner neutral" style="margin:0">No checklist items yet.</div>'}
      </div>`}
      <div class="field-row">
        <input id="new-checklist-item" placeholder="New checklist item text">
        <button class="primary" onclick="addChecklistItemHandler()">Add</button>
      </div>
      <div id="checklist-item-error"></div>
    </div>` : ''}

    ${T('vulns') ? renderVulnSettings() : ''}

    ${T('connections') ? `
    <div class="banner neutral" style="margin-bottom:16px">Agents <strong>pull</strong> from this controller — there's no inbound SSH or WinRM to configure, and nothing here holds a credential to your hosts. The one outbound connection is to Proxmox — and, if vulnerability data is turned on, to OSV, NVD and Microsoft for it.</div>
    ${renderProxmoxConnection(s)}` : ''}

    ${T('notifications') ? `
    <div class="view-header"><h1 class="view-title" style="font-size:16px">Notifications</h1></div>
    <div class="card" style="margin-bottom:20px">
      <p class="card-help">
        Sent on a stage failure, a stuck stage, a host going offline, or a schedule skipped for a missing/unapproved ticket. Job completion is opt-in below — noisy at fleet scale otherwise. Any channel left blank is simply not used; all three can be on at once.
      </p>
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-secondary);margin-bottom:16px">
        <input type="checkbox" id="notify-on-success" ${s.notify_on_success==='true'?'checked':''} onchange="updateSetting_notifyOnSuccess(this.checked)"> Also notify on successful run completion
      </label>

      <p class="card-title" style="display:flex;align-items:center;gap:8px">Generic webhook ${cfgBadge(s.notify_generic_webhook_set==='true')}</p>
      <div class="field-row" style="margin-bottom:14px">
        <input id="notify-generic-url" type="password" placeholder="${s.notify_generic_webhook_set==='true' ? 'Already set — leave blank to keep' : 'https://…'}" class="grow">
        <button onclick="saveNotifySecret('notify_generic_webhook','notify-generic-url')">Save</button>
      </div>

      <p class="card-title" style="display:flex;align-items:center;gap:8px">Slack incoming webhook ${cfgBadge(s.notify_slack_webhook_set==='true')}</p>
      <div class="field-row" style="margin-bottom:14px">
        <input id="notify-slack-url" type="password" placeholder="${s.notify_slack_webhook_set==='true' ? 'Already set — leave blank to keep' : 'https://hooks.slack.com/services/…'}" class="grow">
        <button onclick="saveNotifySecret('notify_slack_webhook','notify-slack-url')">Save</button>
      </div>
      <p style="font-size:11px;color:var(--text-muted);margin:-8px 0 14px">No first-class Microsoft Teams integration — Teams retired its old incoming-webhook connectors; point the generic webhook above at a Teams "when a webhook request is received" flow instead.</p>

      <p class="card-title" style="display:flex;align-items:center;gap:8px">Email (SMTP) <span style="font-weight:400;font-size:11px;color:var(--text-muted)">password</span> ${cfgBadge(s.notify_smtp_password_set==='true')}</p>
      <div class="field-row" style="margin-bottom:8px">
        <input id="notify-smtp-host" placeholder="smtp host" value="${esc(s.notify_smtp_host||'')}" style="flex:1.3">
        <input id="notify-smtp-port" placeholder="port (587)" value="${esc(s.notify_smtp_port||'')}" style="flex:0.6">
      </div>
      <div class="field-row" style="margin-bottom:8px">
        <input id="notify-smtp-user" placeholder="username (optional)" value="${esc(s.notify_smtp_username||'')}" class="grow">
        <input id="notify-smtp-pass" type="password" placeholder="${s.notify_smtp_password_set==='true' ? 'Already set — leave blank to keep' : 'password (optional)'}" class="grow">
      </div>
      <div class="field-row" style="margin-bottom:8px">
        <input id="notify-smtp-from" placeholder="from address" value="${esc(s.notify_smtp_from||'')}" class="grow">
        <input id="notify-smtp-to" placeholder="to address(es), comma-separated" value="${esc(s.notify_smtp_to||'')}" class="grow">
      </div>
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-secondary);margin-bottom:12px">
        <input type="checkbox" id="notify-smtp-tls" ${s.notify_smtp_use_tls!=='false'?'checked':''}> Use STARTTLS
      </label>
      <button class="primary" onclick="saveNotifySmtp()">Save email settings</button>
      <div id="notify-settings-error"></div>
    </div>

    <div class="view-header"><h1 class="view-title" style="font-size:16px">ITSM ticket webhook</h1></div>
    <div class="card" style="margin-bottom:20px">
      <p class="card-help">
        Lets a real ITSM system (ServiceNow, Jira, or any script) push ticket approvals into kite instead of an admin creating them by hand — see the controller README for example configurations. Set a secret here, then have your ITSM system <code>POST /tickets/webhook</code> with header <code>X-Kite-Webhook-Secret</code> matching it.
      </p>
      <div class="field-row">
        <input id="notify-ticket-webhook-secret" type="password" placeholder="${s.ticket_webhook_secret_set==='true' ? 'Already set — leave blank to keep' : 'Shared secret'}" class="grow">
        <button onclick="saveNotifySecret('ticket_webhook_secret','notify-ticket-webhook-secret')">Save</button>
      </div>
      <div style="margin-top:8px;font-size:11.5px;color:var(--text-secondary);display:flex;align-items:center;gap:8px">Webhook secret ${cfgBadge(s.ticket_webhook_secret_set==='true')}</div>
    </div>` : ''}

    ${T('policy') ? renderRollbackPolicy(s) : ''}

    ${T('policy') ? renderAgentUpdatePolicy(s) : ''}

    ${T('access') ? `
    <div class="card" style="margin-bottom:20px">
      <p class="card-title">What each role can do</p>
      <table class="kv-table">
        <tr><td style="width:110px"><span class="badge neutral" style="text-transform:uppercase;background:#fff">Read-only</span></td><td style="text-align:left;font-family:var(--font-ui)">See everything — fleet, runs, coverage, topology, activity — and hold their own read-only API tokens. Can't start or stop a run or change anything.</td></tr>
        <tr><td style="width:110px"><span class="badge neutral" style="text-transform:uppercase">Operator</span></td><td style="text-align:left;font-family:var(--font-ui)">Run patching, view the fleet and activity. Can't run outside a ticket's window; a Team Lead or Admin can.</td></tr>
        <tr><td><span class="badge info" style="text-transform:uppercase">Lead</span></td><td style="text-align:left;font-family:var(--font-ui)">Everything an operator can, plus approve a window override and force-stop a run.</td></tr>
        <tr><td><span class="badge danger" style="text-transform:uppercase">Admin</span></td><td style="text-align:left;font-family:var(--font-ui)">Everything, plus manage users, update rules, per-system scripts, and these settings.</td></tr>
      </table>
      <p class="card-help" style="margin:10px 0 0">Enforced server-side on every endpoint — this just names the roles in the same verbs the rest of the console uses.</p>
    </div>
    <div class="view-header"><h1 class="view-title" style="font-size:16px">SSO / LDAP</h1></div>
    <div class="card" style="margin-bottom:20px">
      <p class="card-help">
        "Search + bind" against an LDAP or Active Directory server. A user who successfully binds and doesn't already have a local kite account is provisioned automatically on first login, at the default role below — an admin adjusts their role afterward from the Users list. Accounts created directly in kite (like the bootstrap admin) always use their local password regardless of this setting, so LDAP being down can't lock out local admin access.
      </p>
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-secondary);margin-bottom:14px">
        <input type="checkbox" id="ldap-enabled" ${s.ldap_enabled==='true'?'checked':''}> Enabled
      </label>
      <div class="field-row" style="margin-bottom:8px">
        <input id="ldap-server-uri" placeholder="ldaps://dc.example.com:636" value="${esc(s.ldap_server_uri||'')}" style="flex:1.4">
        <input id="ldap-user-base-dn" placeholder="user base DN, e.g. ou=people,dc=example,dc=com" value="${esc(s.ldap_user_base_dn||'')}" style="flex:1.6">
      </div>
      <div class="field-row" style="margin-bottom:8px">
        <input id="ldap-bind-dn" placeholder="search account DN (blank = anonymous search)" value="${esc(s.ldap_bind_dn||'')}" class="grow">
        <input id="ldap-bind-password" type="password" placeholder="${s.ldap_bind_password_set==='true' ? 'search account password — leave blank to keep' : 'search account password (optional)'}" class="grow">
      </div>
      <div style="margin-bottom:12px;font-size:11.5px;color:var(--text-secondary);display:flex;align-items:center;gap:8px">Search-account password ${cfgBadge(s.ldap_bind_password_set==='true')}</div>
      <div class="field-row" style="margin-bottom:12px">
        <input id="ldap-user-filter" placeholder="(uid={username})" value="${esc(s.ldap_user_filter||'(uid={username})')}" class="grow">
        <select id="ldap-default-role" style="background:var(--surface-0);border:1px solid var(--border);color:var(--text-primary);padding:9px 11px;border-radius:var(--radius)">
          ${USER_ROLES.map(r=>`<option value="${r.id}" ${(s.ldap_default_role||'operator')===r.id?'selected':''}>${r.label}</option>`).join('')}
        </select>
      </div>
      <p style="font-size:11px;color:var(--text-muted);margin:-4px 0 12px">'{username}' in the filter is escaped before use — safe against directory-side filter injection. Group-to-role mapping isn't built yet; every LDAP login provisions at the default role above.</p>
      <button class="primary" onclick="saveLdapSettings()">Save</button>
      <div id="ldap-settings-error"></div>
    </div>

    <div class="view-header"><h1 class="view-title" style="font-size:16px">Users</h1></div>
    ${state.users===null ? '<div class="banner neutral">Loading…</div>' : `
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head" style="grid-template-columns:1.1fr 1fr 1fr 70px 150px 40px">
        <div>Username</div><div>Display name</div><div>Role</div><div>Source</div><div></div><div></div>
      </div>
      ${state.users.map(u=>`
        <div class="panel-row" style="grid-template-columns:1.1fr 1fr 1fr 70px 150px 40px">
          <div class="mono">${esc(u.username)}</div>
          <div class="secondary">${esc(u.display_name||'—')}</div>
          <div>
            <select style="background:var(--surface-0);border:1px solid var(--border);color:var(--text-primary);padding:4px 8px;border-radius:var(--radius);font-size:12px;text-transform:capitalize" onchange="updateUserRole(${u.id}, this.value)"
              ${u.username === state.user.username ? 'disabled title="Another admin changes your role"' : ''}>
              ${USER_ROLES.map(r=>`<option value="${r.id}" ${u.role===r.id?'selected':''}>${r.label}</option>`).join('')}
            </select>
          </div>
          <div><span class="badge ${u.auth_source==='ldap'?'info':'neutral'}" style="text-transform:uppercase;font-size:10px">${u.auth_source==='ldap'?'LDAP':'Local'}</span></div>
          <div>${u.auth_source==='ldap'
            ? `<span style="font-size:11px;color:var(--text-muted)">Managed by LDAP</span>`
            : `<button style="padding:5px 10px;font-size:11px" onclick="openPasswordReset(${u.id},'${jsq(u.username)}')">Reset password</button>${u.must_change_password ? '<div class="muted" style="font-size:10.5px;margin-top:3px">must choose a password</div>' : ''}`}</div>
          <div>${u.username !== state.user.username ? `<button class="danger-ghost" onclick="removeUser(${u.id})">✕</button>` : ''}</div>
        </div>`).join('')}
    </div>
    ${state.passwordResetResult ? `
    <div class="card" style="margin-bottom:14px;background:var(--surface-0)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <p style="font-size:12px;color:var(--text-secondary);margin:0">Temporary password for <strong>${esc(state.passwordResetResult.username)}</strong> — shown once. Every session they had was signed out; when they sign in with this, they choose their own password before anything else:</p>
        <button style="padding:5px 10px;font-size:11px;flex-shrink:0;margin-left:10px" onclick="copyPasswordReset(this)">Copy</button>
      </div>
      <pre id="password-reset-value" class="mono" style="font-size:12.5px;background:var(--surface-1);padding:10px;border-radius:var(--radius);overflow-x:auto">${esc(state.passwordResetResult.new_password)}</pre>
    </div>` : ''}`}
    <div class="card">
      <p class="card-help">Add a user</p>
      <div class="field-row" style="margin-bottom:8px">
        <input id="new-user-username" placeholder="username">
        <input id="new-user-displayname" placeholder="display name">
      </div>
      <div class="field-row">
        <input id="new-user-password" type="password" placeholder="password (min 12 chars)">
        <select id="new-user-role" style="background:var(--surface-0);border:1px solid var(--border);color:var(--text-primary);padding:9px 11px;border-radius:var(--radius)">
          ${USER_ROLES.map(r=>`<option value="${r.id}" ${r.id==='operator'?'selected':''}>${r.label}</option>`).join('')}
        </select>
        <button class="primary" onclick="addUser()">Add</button>
      </div>
      <label class="tok-toggle" style="border:none;padding:0;margin-top:8px;font-size:12px"><input type="checkbox" id="new-user-must-change" checked> They choose their own password at first sign-in</label>
      <div id="user-form-error"></div>
      ${state.passwordResetDialog ? renderPasswordResetDialog() : ''}
    </div>` : ''}
  `;
}
async function toggleRequireTicket(newValueOn){
  try{
    await api.updateSetting('require_ticket', newValueOn ? 'true' : 'false');
    await loadSettings();
    toast(`Ticket requirement ${newValueOn ? 'enabled' : 'disabled'}.`, 'success');
  }catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function setSnapshotSetting(key, value){
  try{ await api.updateSetting(key, value); await loadSettings(); toast('Snapshot cleanup updated.', 'success'); }
  catch(e){ toast(e.message, 'danger'); }
}
// Daily database backups (app/db_backups.py): how many to keep, the list,
// and a download. Restoring is a manual step on the host, on purpose.
function renderDbBackups(){
  const B = state.dbBackups;
  const keep = B ? B.keep : +((state.settings||{}).db_backup_keep || 7);
  const fmtSize = n => n >= 1048576 ? `${(n/1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n/1024))} KB`;
  return `<div class="card" style="margin-bottom:20px">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
      <div>
        <p style="font-weight:500;margin:0 0 4px">Database backups</p>
        <p style="font-size:12px;color:var(--text-secondary);margin:0">A compressed copy of kite's database — machines, run history, rules, scripts, users and settings — taken once a day. Older ones are deleted so only the newest are kept. They're stored on this controller (in <span class="mono">backups/</span> beside its database), so download one now and then to keep a copy elsewhere. Restoring is done on the controller itself; see the README.</p>
      </div>
      <button style="flex:none" ${keep ? '' : 'disabled'} onclick="backupNow()">Back up now</button>
    </div>
    <div class="field-row" style="margin-top:12px;align-items:center;gap:10px;font-size:13px">
      Keep the newest <input id="db-backup-keep" type="number" min="0" max="365" style="width:72px" value="${keep}"> daily backups
      <button onclick="saveBackupKeep()">Save</button>
      <span class="muted" style="font-size:11.5px">0 = no backups</span>
    </div>
    <div class="field-row" style="margin-top:8px;align-items:center;gap:10px;font-size:13px">
      Keep the activity log for <input id="audit-keep-days" type="number" min="0" max="3650" style="width:72px" value="${esc((state.settings||{}).audit_keep_days || '365')}"> days
      <button onclick="saveAuditKeep()">Save</button>
      <span class="muted" style="font-size:11.5px">older entries are removed daily, after the backup · 0 = keep all</span>
    </div>
    ${B === null || B === undefined ? '<p class="card-help" style="margin:10px 0 0">Loading backups…</p>'
      : B.error ? `<div class="banner danger" style="margin-top:10px">${esc(B.error)}</div>`
      : B.backups.length ? `<div class="panel" style="margin-top:12px;max-height:260px;overflow:auto">${B.backups.map(b => `
        <div class="panel-row" style="grid-template-columns:minmax(0,1fr) 90px 110px auto;align-items:center">
          <span class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(b.name)}</span>
          <span class="muted" style="font-size:12px">${fmtSize(b.size_bytes)}</span>
          <span class="muted" style="font-size:12px">${esc(relTime(b.taken_at))}</span>
          <a class="chip" href="/backups/${encodeURIComponent(b.name)}" download style="text-decoration:none">Download</a>
        </div>`).join('')}</div>`
      : `<p class="card-help" style="margin:10px 0 0">${keep ? 'No backup yet — the first is taken ten minutes after the controller starts, or press Back up now.' : 'Backups are off.'}</p>`}
  </div>`;
}
async function loadDbBackups(){
  try{ state.dbBackups = await api.listBackups(); }
  catch(e){ state.dbBackups = {error: e.message, backups: []}; }
  if(state.nav === 'settings') render();
}
async function backupNow(){
  try{
    const r = await api.backupNow();
    toast(`Backed up: ${r.name}${r.removed.length ? ` (removed ${r.removed.length} older)` : ''}.`, 'success');
    loadDbBackups();
  }catch(e){ toast(e.message, 'danger'); }
}
async function saveBackupKeep(){
  const keep = (document.getElementById('db-backup-keep') || {}).value || '';
  if(!/^\d+$/.test(keep) || +keep > 365){ toast('A whole number from 0 to 365.', 'danger'); return; }
  try{
    await api.updateSetting('db_backup_keep', keep);
    await loadSettings();
    loadDbBackups();
    toast(keep === '0' ? 'Daily backups are off.' : `Keeping the newest ${keep} daily backups.`, 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function saveAuditKeep(){
  const days = (document.getElementById('audit-keep-days') || {}).value || '';
  if(!/^\d+$/.test(days) || +days > 3650){ toast('A whole number of days from 0 to 3650.', 'danger'); return; }
  try{
    await api.updateSetting('audit_keep_days', days);
    await loadSettings();
    toast(days === '0' ? 'The activity log is kept in full.' : `Activity older than ${days} days is removed daily.`, 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function saveSnapshotLimits(){
  const count = (document.getElementById('snap-keep-count') || {}).value || '0';
  const days = (document.getElementById('snap-keep-days') || {}).value || '0';
  if(!/^\d+$/.test(count) || !/^\d+$/.test(days)){ toast('Whole numbers only (0 = no limit).', 'danger'); return; }
  try{
    await api.updateSetting('snapshot_keep_count', count);
    await api.updateSetting('snapshot_keep_days', days);
    await loadSettings();
    toast(`Keeping the newest ${count === '0' ? 'any number' : count}${days === '0' ? '' : `, none older than ${days} days`}.`, 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function toggleSkipUninstallable(on){
  try{
    await api.updateSetting('patch_skip_uninstallable', on ? 'true' : 'false');
    await loadSettings();
    toast(on ? 'Updates that can’t be installed will be skipped and listed.' : 'An update that can’t be installed fails the patch step again.', 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function addChecklistItemHandler(){
  const input = document.getElementById('new-checklist-item');
  const text = input.value.trim();
  const errEl = document.getElementById('checklist-item-error');
  errEl.innerHTML = '';
  if(!text) return;
  try{
    await api.addChecklistItem(text);
    await loadChecklistItems();
    input.value = '';
    toast('Checklist item added.', 'success');
  }catch(e){ errEl.innerHTML = errorBanner(e.message); }
}
async function removeChecklistItem(id){
  try{ await api.deleteChecklistItem(id); await loadChecklistItems(); toast('Checklist item removed.', 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function updateRollbackDefault(value){
  try{
    await api.updateSetting('rollback_default_backend', value);
    await loadSettings();
    toast('Default rollback backend updated.', 'success');
  }catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
/* ---------- Connections → Proxmox ---------- */
// A list of connections -- clusters and standalone hosts, each with its
// own API token -- and one form below it. The form adds a new connection
// (and clears, ready for the next) or, after Edit, changes one in place.
const PROXMOX_TOKEN_COMMANDS = [
  '# On the Proxmox host (any node, for a cluster), as root:',
  'pveum role add KiteAccess -privs "VM.Audit Sys.Audit SDN.Audit VM.Snapshot VM.PowerMgmt"',
  'pveum user add kite@pve --comment "kite controller"',
  'pveum acl modify / --users kite@pve --roles KiteAccess',
  'pveum user token add kite@pve kite --privsep 0',
].join('\n');
// Accept what people actually paste: a URL from the browser bar, with
// scheme, the :8006 port, or a path. kite wants just the host.
function normalizeProxmoxHost(v){
  return (v||'').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:8006$/, '');
}
const PROXMOX_TOKEN_ID_RE = /^[^@\s!]+@[^@\s!]+![^@\s!]+$/;
// Unknown until the list has loaded: don't warn about a missing
// connection before we know there isn't one.
function proxmoxConfigured(){
  return state.pmConnections === null || state.pmConnections.length > 0;
}
const PM_BLANK = () => ({name: '', host: '', token_id: '', token_secret: '', node: '', verify_ssl: false});
// What's typed into the form, kept in state while editing: the page
// re-renders on every state change (a test result arriving, a toast), and
// without this each re-render would wipe the edits.
function pmForm(){
  if(!state.pmForm) state.pmForm = PM_BLANK();
  return state.pmForm;
}
function pmField(k, v){ pmForm()[k] = v; }
function editProxmoxConnection(id){
  const c = (state.pmConnections || []).find(x => x.id === id);
  if(!c) return;
  state.pmEditing = id;
  state.pmForm = {name: c.name, host: c.host, token_id: c.token_id, token_secret: '', node: c.node || '', verify_ssl: !!c.verify_ssl};
  state.pmTest = null;
  render();
  const el = document.getElementById('pm-form');
  if(el && el.scrollIntoView) el.scrollIntoView({behavior: 'smooth'});
}
function cancelProxmoxEdit(){ state.pmEditing = null; state.pmForm = PM_BLANK(); state.pmTest = null; render(); }
function renderProxmoxConnection(s){
  const conns = state.pmConnections;
  const editing = state.pmEditing != null ? (conns || []).find(c => c.id === state.pmEditing) : null;
  const t = state.pmTest;
  const f = pmForm();
  return `
    <div class="card pm-conn">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <p class="card-title" style="margin:0;font-size:15px">Proxmox connections</p>
        ${conns && conns.length ? `<span class="badge success"><span class="g">&#10003;</span>${conns.length} connected</span>` : `<span class="badge neutral">None yet</span>`}
      </div>
      <p class="card-help">One connection per <strong>cluster</strong> (any node's address reaches all of it — a node that joins later appears by itself) or per <strong>standalone host</strong>. Each uses its own read-mostly API token for:</p>
      <ul class="pm-uses">
        <li><strong>Snapshots before a patch</strong> — when the rollback safety net is <em>Proxmox snapshot</em> (Settings &rarr; Policy)</li>
        <li><strong>Fleet &rarr; Coverage</strong> — which VMs have no agent</li>
        <li><strong>Topology</strong> — nodes, bridges, and which VM is on which</li>
      </ul>
      <p class="card-help">kite never starts, stops or changes a VM. Taking a snapshot is the only thing it can do there, and only if you grant it.</p>

      ${conns === null ? '<div class="loading-rows"><div class="skeleton" style="height:38px"></div></div>' : conns.length ? `
      <div class="panel" style="margin:6px 0 4px">
        <div class="panel-head pm-conn-grid" style="grid-template-columns:1fr 1fr 1.4fr 0.9fr 1fr 200px">
          <div>Name</div><div>Address</div><div>Token ID</div><div>Secret</div><div>VMs</div><div></div>
        </div>
        ${conns.map(c => `
          <div class="panel-row pm-conn-grid ${state.pmEditing === c.id ? 'rail-info' : ''}" style="grid-template-columns:1fr 1fr 1.4fr 0.9fr 1fr 200px">
            <div style="font-weight:600;font-size:12.5px">${esc(c.name)}</div>
            <div class="mono" style="font-size:12px">${esc(c.host)}</div>
            <div class="mono secondary" style="font-size:11.5px">${esc(c.token_id)}</div>
            <div>${c.secret_set ? cfgBadge(true) : c.secret_from_env ? '<span class="badge neutral">from .env</span>' : cfgBadge(false)}</div>
            <div style="font-size:12px" title="VMs and containers on this connection, and how many have a kite agent"><span class="mono">${c.guests}</span> VM${c.guests===1?'':'s'} &middot; <span class="mono">${c.linked_hosts}</span> enrolled</div>
            <div style="display:flex;gap:6px;justify-content:flex-end">
              <button style="padding:4px 9px;font-size:11.5px" onclick="testSavedProxmoxConnection(${c.id})">Test</button>
              <button style="padding:4px 9px;font-size:11.5px" onclick="editProxmoxConnection(${c.id})">Edit</button>
              <button class="danger-outline" style="padding:4px 9px;font-size:11.5px" onclick="removeProxmoxConnection(${c.id})">Remove</button>
            </div>
          </div>
          ${state.pmRowTest && state.pmRowTest.id === c.id ? `<div style="padding:0 12px 10px">${renderProxmoxTestResult(state.pmRowTest.result)}</div>` : ''}`).join('')}
      </div>` : '<div class="banner neutral" style="margin:6px 0 4px">No connections yet. Add your cluster or standalone host below.</div>'}

      <div id="pm-form"></div>
      <div class="pm-step">
        <div class="pm-step-n">1</div>
        <div class="grow" style="min-width:0">
          <p class="pm-step-title">Create an API token on the Proxmox host</p>
          <p class="card-help" style="margin-bottom:8px">Each connection needs a token made on <em>that</em> cluster or host. Already have one from an earlier version? Add any privilege it's missing, e.g. <span class="mono">pveum role modify KiteAccess --privs VM.PowerMgmt --append 1</span> — <strong>Test connection</strong> below says which ones it has. Otherwise run these; the last command prints the <strong>token ID</strong> (<span class="mono">kite@pve!kite</span>) and the <strong>secret</strong>, shown only once.</p>
          <div style="position:relative">
            <pre id="pm-cmds" class="cmd-block">${esc(PROXMOX_TOKEN_COMMANDS)}</pre>
            <button class="pm-copy" onclick="copyTokenField('pm-cmds', this)">Copy</button>
          </div>
          <details class="pm-more">
            <summary>What these privileges are for, and how to narrow them</summary>
            <ul>
              <li><span class="mono">VM.Audit</span> — read guests and their config (including NICs): Coverage, Topology, VM-id lookup.</li>
              <li><span class="mono">Sys.Audit</span> — read node status and network config for Topology.</li>
              <li><span class="mono">SDN.Audit</span> — see the bridges in that config. Since Proxmox 8 bridges are SDN resources, and without it every <span class="mono">vmbr</span> is silently left out.</li>
              <li><span class="mono">VM.Snapshot</span> — take the pre-patch snapshot, and restore one from the machine page.</li>
              <li><span class="mono">VM.PowerMgmt</span> — start a VM again after a restore (kite's snapshots hold no memory, so Proxmox leaves it off). Without it, start it in Proxmox yourself.</li>
              <li>Only want Coverage and Topology? Leave out <span class="mono">VM.Snapshot</span> and <span class="mono">VM.PowerMgmt</span>.</li>
              <li>To allow snapshots on specific VMs only, grant the role on <span class="mono">/vms/&lt;vmid&gt;</span> instead of <span class="mono">/</span>. Coverage only shows guests the token can see.</li>
              <li>Prefer the web UI? Datacenter &rarr; Permissions: create the role, the user, a permission on <span class="mono">/</span>, then API Tokens &rarr; Add with <em>Privilege Separation</em> unticked.</li>
            </ul>
          </details>
        </div>
      </div>

      <div class="pm-step">
        <div class="pm-step-n">2</div>
        <div class="grow" style="min-width:0">
          <p class="pm-step-title">${editing ? `Edit <span class="mono">${esc(editing.name)}</span>` : 'Add the connection'}</p>
          <div class="pm-fields">
            <label>
              <span class="tok-lbl">Name</span>
              <input id="pm-name" placeholder="e.g. Main cluster" maxlength="64" value="${esc(f.name)}" oninput="pmField('name',this.value)">
              <span class="pm-hint">How this connection shows in Topology and Coverage.</span>
            </label>
            <label>
              <span class="tok-lbl">Proxmox address</span>
              <input id="pm-host" placeholder="pve1.example.lan" value="${esc(f.host)}" oninput="pmField('host',this.value)">
              <span class="pm-hint">Hostname or IP of the host (any node, for a cluster). Port 8006 is assumed — no <span class="mono">https://</span> needed.</span>
            </label>
            <label>
              <span class="tok-lbl">API token ID</span>
              <input id="pm-token-id" class="mono" placeholder="kite@pve!kite" value="${esc(f.token_id)}" oninput="pmField('token_id',this.value)">
              <span class="pm-hint">Format <span class="mono">user@realm!tokenname</span>, as printed in step 1.</span>
            </label>
            <label>
              <span class="tok-lbl">Token secret ${editing ? (editing.secret_set ? cfgBadge(true) : editing.secret_from_env ? '<span class="badge neutral">from .env</span>' : cfgBadge(false)) : ''}</span>
              <input id="pm-token-secret" type="password" autocomplete="new-password" value="${esc(f.token_secret)}" oninput="pmField('token_secret',this.value)" placeholder="${editing ? 'Saved — leave blank to keep it' : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'}">
              <span class="pm-hint">The UUID from step 1. Stored encrypted and never shown again.</span>
            </label>
            <label class="pm-check">
              <input type="checkbox" id="pm-verify-ssl" ${f.verify_ssl?'checked':''} onchange="pmField('verify_ssl',this.checked)">
              <span><strong>Verify TLS certificate</strong><br><span class="pm-hint">Proxmox ships a self-signed certificate. Leave this off unless you've installed a trusted one.</span></span>
            </label>
          </div>
          <details class="pm-more" ${f.node ? 'open' : ''}>
            <summary>Advanced</summary>
            <label style="display:block;margin-top:8px">
              <span class="tok-lbl">Node name <span class="muted" style="font-weight:400">(optional)</span></span>
              <input id="pm-node" placeholder="leave blank" value="${esc(f.node)}" oninput="pmField('node',this.value)" style="max-width:280px">
              <span class="pm-hint">kite finds each VM's node itself. Only set this if the token can't read the cluster view — it's then used for every VM on this connection.</span>
            </label>
          </details>
          <div style="display:flex;gap:8px;margin-top:14px">
            <button onclick="testProxmoxConnection()" ${state.pmTesting?'disabled':''}>${state.pmTesting ? 'Testing…' : 'Test connection'}</button>
            <button class="primary" onclick="saveProxmoxConnection()">${editing ? 'Save changes' : 'Add connection'}</button>
            ${editing ? '<button onclick="cancelProxmoxEdit()">Cancel</button>' : ''}
          </div>
          ${t ? renderProxmoxTestResult(t) : ''}
          <div id="pm-error"></div>
        </div>
      </div>
    </div>`;
}
function renderProxmoxTestResult(t){
  if(!t.ok) return `<div class="banner danger" style="margin:12px 0 0"><strong>Connection failed.</strong> ${esc(t.error)}</div>`;
  const uses = t.uses ? `<ul class="pm-uses" style="margin:8px 0 0">${t.uses.map(u =>
    `<li>${u.granted ? '<span style="color:var(--ok)">&#10003;</span>' : '<span style="color:var(--urgent)">&#10007;</span>'} <span class="mono">${esc(u.privilege)}</span> — ${esc(u.use)}${u.granted ? '' : ' <strong>won’t work</strong>'}</li>`).join('')}</ul>`
    : '<div class="pm-hint" style="margin-top:6px">Couldn’t read the token’s permissions, so which uses it covers is unknown.</div>';
  const overlap = (t.overlaps || []).map(o =>
    `<div class="banner warning" style="margin:8px 0 0"><strong>Already connected.</strong> ${o.nodes.map(esc).join(', ')} ${o.nodes.length===1?'is':'are'} also seen through <strong>${esc(o.connection)}</strong> — likely a host that joined that cluster. Keep one of the two, or its VMs show twice.</div>`).join('');
  return `<div class="banner success" style="margin:12px 0 0;display:block"><strong>Connected.</strong> ${t.nodes} node${t.nodes===1?'':'s'}, ${t.guests} guest${t.guests===1?'':'s'} visible to this token.${uses}</div>${overlap}`;
}
function proxmoxFormValues(){
  const f = pmForm();
  return {name: (f.name || '').trim(), host: normalizeProxmoxHost(f.host), token_id: (f.token_id || '').trim(),
          token_secret: f.token_secret || '', node: (f.node || '').trim(), verify_ssl: !!f.verify_ssl};
}
function proxmoxFormError(f, adding){
  if(adding && !f.name) return 'Give the connection a name, e.g. "Main cluster".';
  if(adding && !f.host) return 'Enter the Proxmox address.';
  if(f.token_id && !PROXMOX_TOKEN_ID_RE.test(f.token_id))
    return 'The token ID should look like kite@pve!kite — user, @realm, then !tokenname.';
  if(adding && !f.token_secret) return 'Paste the token secret from step 1.';
  return '';
}
async function testProxmoxConnection(){
  const f = proxmoxFormValues();
  const err = proxmoxFormError(f, false);
  if(err){ state.pmTest = {ok: false, error: err}; render(); return; }
  state.pmTesting = true; state.pmTest = null; render();
  try{ state.pmTest = await api.testProxmox({connection_id: state.pmEditing, host: f.host, token_id: f.token_id,
                                             token_secret: f.token_secret, verify_ssl: f.verify_ssl}); }
  catch(e){ state.pmTest = {ok: false, error: e.message}; }
  state.pmTesting = false;
  render();
}
async function testSavedProxmoxConnection(id){
  state.pmRowTest = {id, result: {ok: true, nodes: '…', guests: '…', uses: null}};
  try{ state.pmRowTest = {id, result: await api.testProxmox({connection_id: id})}; }
  catch(e){ state.pmRowTest = {id, result: {ok: false, error: e.message}}; }
  render();
}
async function saveProxmoxConnection(){
  const f = proxmoxFormValues();
  const adding = state.pmEditing == null;
  const errEl = document.getElementById('pm-error');
  if(errEl) errEl.innerHTML = '';
  const err = proxmoxFormError(f, adding);
  if(err){ if(errEl) errEl.innerHTML = errorBanner(err); return; }
  try{
    if(adding) await api.createProxmoxConnection(f);
    else {
      const body = {...f};
      if(!body.token_secret) delete body.token_secret;   // blank keeps the saved one
      await api.updateProxmoxConnection(state.pmEditing, body);
    }
    toast(adding ? `Connection ${f.name} added.` : 'Connection saved.', 'success');
    // Clear for the next one.
    state.pmEditing = null; state.pmForm = PM_BLANK(); state.pmTest = null;
    await loadProxmoxConnections();
  }catch(e){ if(errEl) errEl.innerHTML = errorBanner(e.message); }
}
async function removeProxmoxConnection(id){
  const c = (state.pmConnections || []).find(x => x.id === id);
  if(!c) return;
  const ok = await confirmDialog({
    title: `Remove ${c.name}?`,
    message: `kite stops reading this Proxmox connection.${c.linked_hosts ? ` ${c.linked_hosts} machine${c.linked_hosts===1?'':'s'} linked to VMs on it will be unlinked — their history stays, and they re-link on their own if their VM turns up on another connection.` : ''}`,
    confirmLabel: 'Remove', danger: true,
  });
  if(!ok) return;
  try{
    await api.deleteProxmoxConnection(id);
    if(state.pmEditing === id) cancelProxmoxEdit();
    toast(`Connection ${c.name} removed.`, 'success');
    await loadProxmoxConnections();
  }catch(e){ toast(e.message, 'danger'); }
}

/* ---------- Policy → Rollback safety net ---------- */
const ROLLBACK_HELP = {
  proxmox: 'A full VM snapshot just before patching — the whole disk can be put back. Needs the Proxmox connection, and each machine linked to its VM id.',
  dnf_history: 'Records the package transaction so it can be undone. RHEL-family only, no hypervisor needed. Restores packages, not the disk.',
  none: 'Skip the snapshot stage. A patch that goes wrong has no automatic way back.',
};
function renderRollbackPolicy(s){
  const current = s.rollback_default_backend || 'proxmox';
  const needsConn = current === 'proxmox' && !proxmoxConfigured();
  return `
    <div class="view-header"><h1 class="view-title" style="font-size:16px">Rollback safety net</h1></div>
    <div class="card" style="margin-bottom:20px">
      <p class="card-help">What kite does just before installing updates, so a bad patch can be undone. This is the default for every machine — a single machine can use something else from its own page (Fleet &rarr; machine &rarr; Rollback backend).</p>
      <div class="rb-options">
        ${ROLLBACK_BACKENDS.map(b => `
          <label class="rb-option ${current===b.id?'on':''}">
            <input type="radio" name="rb-default" value="${b.id}" ${current===b.id?'checked':''} onchange="updateRollbackDefault(this.value)">
            <span><strong>${esc(b.label)}</strong><br><span class="pm-hint">${ROLLBACK_HELP[b.id]}</span></span>
          </label>`).join('')}
      </div>
      ${needsConn ? `<div class="banner warning" style="margin:12px 0 0">Proxmox isn't connected yet, so snapshots will fail. <a href="#" onclick="setSettingsTab('connections');return false">Set up the connection &rarr;</a></div>` : ''}
    </div>`;
}
async function updateSetting_notifyOnSuccess(checked){
  try{ await api.updateSetting('notify_on_success', checked ? 'true' : 'false'); await loadSettings(); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function saveNotifySecret(name, inputId){
  const input = document.getElementById(inputId);
  const value = input.value;
  if(!value) return;  // blank = "leave unchanged", nothing to save
  try{
    await api.setSecretSetting(name, value);
    await loadSettings();
    input.value = '';
    toast('Saved.', 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function saveNotifySmtp(){
  const host = document.getElementById('notify-smtp-host').value.trim();
  const port = document.getElementById('notify-smtp-port').value.trim();
  const username = document.getElementById('notify-smtp-user').value.trim();
  const password = document.getElementById('notify-smtp-pass').value;
  const from = document.getElementById('notify-smtp-from').value.trim();
  const to = document.getElementById('notify-smtp-to').value.trim();
  const useTls = document.getElementById('notify-smtp-tls').checked;
  const errEl = document.getElementById('notify-settings-error');
  errEl.innerHTML = '';
  try{
    await api.updateSetting('notify_smtp_host', host);
    await api.updateSetting('notify_smtp_port', port);
    await api.updateSetting('notify_smtp_username', username);
    await api.updateSetting('notify_smtp_from', from);
    await api.updateSetting('notify_smtp_to', to);
    await api.updateSetting('notify_smtp_use_tls', useTls ? 'true' : 'false');
    if(password) await api.setSecretSetting('notify_smtp_password', password);
    await loadSettings();
    toast('Email notification settings saved.', 'success');
  }catch(e){ errEl.innerHTML = errorBanner(e.message); }
}
function newerVersionFirst(a, b){
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for(let i = 0; i < Math.max(x.length, y.length); i++) if((y[i]||0) !== (x[i]||0)) return (y[i]||0) - (x[i]||0);
  return 0;
}
// How agents update: always to the newest build this controller holds,
// to one chosen version, or not at all. Agents update themselves when
// idle, never mid-run (app/agent_releases.py).
function renderAgentUpdatePolicy(s){
  const U = state.agentUpdates;
  const target = s.agent_target_version || '';
  const current = !target ? 'off' : target === 'latest' ? 'latest' : 'pin';
  const mode = state.agentUpdateMode || current;
  const versions = U ? [...new Set([...(U.published||[]), U.bundle, U.windows].filter(Boolean))]
    .sort(newerVersionFirst) : [];
  const pinned = state.agentUpdatePin || (current === 'pin' ? target : versions[0] || '');
  const hosts = U ? U.hosts || [] : [];
  const behind = hosts.filter(h => h.behind).length, updating = hosts.filter(h => h.updating_to).length;
  const opt = (id, title, help, extra='') => `
    <label class="rb-option ${mode===id?'on':''}">
      <input type="radio" name="agent-update-mode" value="${id}" ${mode===id?'checked':''} onchange="chooseAgentUpdateMode('${id}')">
      <span><strong>${title}</strong>${current===id?' <span class="badge success" style="margin-left:6px">Current</span>':''}<br><span class="pm-hint">${help}</span>${extra}</span>
    </label>`;
  return `
    <div class="view-header"><h1 class="view-title" style="font-size:16px">Agent updates</h1></div>
    <div class="card" style="margin-bottom:20px">
      <p class="card-help">Agents update themselves from this controller the next time they're idle — never during a run. ${U
        ? `This controller has ${U.latest ? `Linux agent <span class="mono">${esc(U.latest)}</span>` : 'no Linux agent'}${U.windows ? ` and Windows agent <span class="mono">${esc(U.windows)}</span>` : ''}. ${behind ? `<strong>${behind}</strong> agent${behind===1?' is':'s are'} behind${updating ? `, ${updating} updating` : ''}.` : hosts.length ? 'Every agent is up to date.' : ''}`
        : 'Loading versions…'}</p>
      <div class="rb-options">
        ${opt('latest', 'Keep agents up to date (recommended)',
          'Each agent moves to the newest version this controller has for its OS, now and whenever a newer one is published.')}
        ${opt('pin', 'Update to a specific version',
          'Agents older than the version you choose move to it, and stay there. Debian/Ubuntu and Windows agents can only move to the one build this controller holds for them.',
          mode==='pin' ? `<span style="display:flex;gap:8px;margin-top:8px">
            <select id="agent-target-pin" style="min-width:140px" onchange="state.agentUpdatePin=this.value">
              ${versions.map(v=>`<option value="${esc(v)}" ${v===pinned?'selected':''}>${esc(v)}</option>`).join('') || '<option value="">No published versions</option>'}
            </select>
            <button class="primary" ${current==='pin' && pinned===target ? 'disabled' : ''} onclick="event.preventDefault();saveAgentUpdatePolicy('pin')">Apply</button>
          </span>` : '')}
        ${opt('off', 'Don’t update agents', 'Agents stay on the version they have. You can still update one machine from its page.')}
      </div>
    </div>`;
}
function chooseAgentUpdateMode(mode){
  state.agentUpdateMode = mode;
  if(mode === 'pin') render();
  else saveAgentUpdatePolicy(mode);
}
async function saveAgentUpdatePolicy(mode){
  const pinEl = document.getElementById('agent-target-pin');
  const version = mode === 'latest' ? 'latest' : mode === 'pin' ? (pinEl ? pinEl.value : state.agentUpdatePin) : '';
  try{
    if(mode === 'off') state.agentUpdates = await api.cancelAgentUpdate();
    else{
      if(!version) throw new Error('Choose a version first.');
      state.agentUpdates = await api.setAgentUpdate(version);
    }
    state.agentUpdateMode = null; state.agentUpdatePin = null;
    await loadSettings();
    toast(mode === 'latest' ? 'Agents will keep themselves up to date.' : mode === 'pin' ? `Agents will update to ${version}.`
          : 'Agents won’t update automatically.', 'success');
  }catch(e){ state.agentUpdateMode = null; render(); toast(e.message, 'danger'); }
}
async function saveLdapSettings(){
  const enabled = document.getElementById('ldap-enabled').checked;
  const serverUri = document.getElementById('ldap-server-uri').value.trim();
  const userBaseDn = document.getElementById('ldap-user-base-dn').value.trim();
  const bindDn = document.getElementById('ldap-bind-dn').value.trim();
  const bindPassword = document.getElementById('ldap-bind-password').value;
  const userFilter = document.getElementById('ldap-user-filter').value.trim();
  const defaultRole = document.getElementById('ldap-default-role').value;
  const errEl = document.getElementById('ldap-settings-error');
  errEl.innerHTML = '';
  try{
    await api.updateSetting('ldap_enabled', enabled ? 'true' : 'false');
    await api.updateSetting('ldap_server_uri', serverUri);
    await api.updateSetting('ldap_user_base_dn', userBaseDn);
    await api.updateSetting('ldap_bind_dn', bindDn);
    await api.updateSetting('ldap_user_filter', userFilter || '(uid={username})');
    await api.updateSetting('ldap_default_role', defaultRole);
    if(bindPassword) await api.setSecretSetting('ldap_bind_password', bindPassword);
    await loadSettings();
    toast('LDAP settings saved.', 'success');
  }catch(e){ errEl.innerHTML = errorBanner(e.message); }
}
async function updateUserRole(id, role){
  try{ await api.patchUser(id, {role}); await loadUsers(); toast('Role updated.', 'success'); }
  catch(e){ toast(e.message, 'danger'); await loadUsers(); }   // reload: the select shows the role it still has
}
async function addUser(){
  const username = document.getElementById('new-user-username').value.trim();
  const display_name = document.getElementById('new-user-displayname').value.trim();
  const password = document.getElementById('new-user-password').value;
  const role = document.getElementById('new-user-role').value;
  const errEl = document.getElementById('user-form-error');
  if(!username || !password){ errEl.innerHTML = errorBanner('Username and password are required.'); return; }
  try{
    const must_change_password = !!(document.getElementById('new-user-must-change') || {checked: true}).checked;
    await api.createUser({username, password, role, display_name, must_change_password});
    await loadUsers();
    toast(`User ${username} created.`, 'success');
  }catch(e){ errEl.innerHTML = errorBanner(e.message); }
}
async function removeUser(id){
  const ok = await confirmDialog({title:'Remove user', message:'Remove this user? They will no longer be able to sign in.', confirmLabel:'Remove', danger:true});
  if(!ok) return;
  try{ await api.deleteUser(id); await loadUsers(); toast('User removed.', 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
function openPasswordReset(id, username){ state.passwordResetDialog = {id, username}; render(); }
function renderPasswordResetDialog(){
  const d = state.passwordResetDialog;
  return `
    <div class="modal-backdrop" onclick="if(event.target===this){state.passwordResetDialog=null;render()}">
      <div class="modal" style="max-width:440px">
        <p class="modal-title">Reset ${esc(d.username)}'s password</p>
        <p class="modal-message">They're signed out everywhere, and their API tokens stop working. The password below only gets them signed in: they choose their own straight away.</p>
        <label class="tok-lbl" for="reset-temp">Temporary password</label>
        <input id="reset-temp" type="text" style="width:100%" placeholder="leave blank to generate one" autocomplete="off">
        <div class="muted" style="font-size:11px;margin-top:4px">At least 12 characters if you type one.</div>
        <div id="reset-error"></div>
        <div class="modal-actions">
          <button onclick="state.passwordResetDialog=null;render()">Cancel</button>
          <button class="danger" onclick="resetUserPassword()">Reset password</button>
        </div>
      </div>
    </div>`;
}
async function resetUserPassword(){
  const d = state.passwordResetDialog;
  if(!d) return;
  const typed = ((document.getElementById('reset-temp') || {}).value || '').trim();
  if(typed && typed.length < 12){
    document.getElementById('reset-error').innerHTML = errorBanner('Type at least 12 characters, or leave it blank to generate one.');
    return;
  }
  try{
    state.passwordResetResult = await api.resetPassword(d.id, typed);
    state.passwordResetDialog = null;
    await loadUsers();
    render();
    toast(`${d.username} has a temporary password.`, 'success');
  }catch(e){ document.getElementById('reset-error').innerHTML = errorBanner(e.message); }
}
function copyPasswordReset(btn){
  const text = document.getElementById('password-reset-value').textContent;
  copyTextToClipboard(text).then(()=>{
    const original = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(()=>{ btn.textContent = original; }, 1500);
  }).catch(()=>{
    toast('Could not copy automatically — select the text and copy manually.', 'warning');
  });
}
