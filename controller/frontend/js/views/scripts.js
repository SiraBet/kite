/*
 * Per-OS-family script overrides for the scriptable stages.
 */
/* ============================== OS SCRIPTS ============================== */
// The group a name belongs to, or undefined for an OS family.
function groupByName(name){ return (state.groups || []).find(g => g.name === name); }
function groupsOf(host){ return (state.groups || []).filter(g => (host.group_ids || []).includes(g.id)); }
// Where a machine's scripts are managed: the group that supplies one, else its first group, else its OS family.
function scriptHomeFor(host, scripts){
  const supplying = (scripts || []).map(sc => groupByName(sc.os_family)).find(Boolean);
  const first = groupsOf(host)[0];
  return supplying ? supplying.name : first ? first.name : host.os_family;
}
function renderScripts(){
  const can = atLeast(state.user.role, 'admin');
  if(state.osScripts===null) return `<div class="view-header"><h1 class="view-title">Per-system scripts</h1></div><div class="loading-rows"><div class="skeleton"></div><div class="skeleton"></div></div>`;

  const fleet = state.fleet || [];
  const byKey = {};
  state.osScripts.forEach(s => { byKey[`${s.os_family}/${s.stage_name}`] = s; });
  const groups = (state.groups || []).map(g => g.name);
  const isGroup = name => groups.includes(name);
  // OS families: the fleet's, and any name holding scripts that isn't a group (a family not enrolled yet)
  const families = [...new Set([...fleet.map(f=>f.os_family), ...state.osScripts.map(s=>s.os_family)].filter(n => n && !isGroup(n)))].sort();
  const members = name => isGroup(name) ? fleet.filter(f => (f.group_ids||[]).includes(groupByName(name).id)) : fleet.filter(f=>f.os_family===name);
  const stats = name => {
    const scripts = scriptableStages.map(st=>byKey[`${name}/${st}`]).filter(Boolean);
    return {count: scripts.length, untested: scripts.filter(s=>!s.tested).length, hosts: members(name).length};
  };
  const all = [...families, ...groups];
  const selected = state.scriptsFamily && all.includes(state.scriptsFamily) ? state.scriptsFamily : all[0];

  const header = `
    <div class="view-header">
      <h1 class="view-title">Per-system scripts</h1>
      <p class="view-sub">Custom steps per OS family, or per group of machines you choose — which version is live, whether it's been tested, what changed. For each stage a machine runs its group's script, else its OS family's, else the agent's built-in default. Groups are also what update rules can apply to.</p>
    </div>
    ${state.loadError ? errorBanner(state.loadError) : ''}
    ${!can ? `<div class="rbac-lock" style="margin-bottom:14px">${LOCK_ICON} Uploading/removing requires Admin role. You're signed in as ${esc(state.user.role)}.</div>` : ''}`;

  const newGroup = can ? `<div style="padding:11px 13px;border-top:1px solid var(--border)">
        ${state.groupEdit === 'new' ? renderGroupForm(null) : `<button style="width:100%" onclick="state.groupEdit='new';render()">+ New group</button>`}
      </div>` : '';
  if(all.length===0){
    return header + `<div class="banner neutral">No OS families seen yet — enroll a host first and its family shows up here.</div>`
      + (can ? `<div class="panel" style="max-width:300px;margin-top:14px">${newGroup}</div>` : '');
  }

  const item = name => {
    const st = stats(name);
    const active = name===selected;
    const tone = st.untested ? 'color:var(--due-ink)' : 'color:var(--text-muted)';
    return `<div class="panel-row" style="grid-template-columns:1fr;cursor:pointer;${active?'background:var(--rail);':''}" onclick="selectScriptFamily('${jsq(name)}')">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="mono" style="font-weight:500;font-size:12px;min-width:0;overflow-wrap:anywhere;${active?'color:#fff':''}">${esc(name)}</span>
        <span class="grow"></span>
        <span class="mono" style="font-size:10px;${active?'color:#9BA5A3':'color:var(--text-muted)'}" title="machines">${st.hosts}</span>
      </div>
      <div style="font-size:10.5px;margin-top:3px;${active?'color:#9BA5A3':tone}">${st.count} script${st.count===1?'':'s'} ${st.count?(st.untested?`· ${st.untested} untested`:'· all tested'):(isGroup(name)?'· none yet':'· built-in defaults')}</div>
    </div>`;
  };
  // Long lists scroll inside the panel, and a search narrows both, so the page stays one screen tall.
  const lq = (state.scriptsListQ || '').trim().toLowerCase();
  const match = n => !lq || n.toLowerCase().includes(lq) || n === selected;
  const shownFamilies = families.filter(match), shownGroups = groups.filter(match);
  const sidebar = `
    <div class="panel" style="align-self:start">
      ${all.length > 8 ? `<div style="padding:9px 11px;border-bottom:1px solid var(--border)">
        <input id="scripts-list-q" placeholder="Find a family or group" value="${esc(state.scriptsListQ||'')}" style="width:100%;font-size:12px"
          oninput="state.scriptsListQ=this.value;render();const e=document.getElementById('scripts-list-q');e.focus();e.setSelectionRange(e.value.length,e.value.length)"></div>` : ''}
      <div class="panel-head" style="grid-template-columns:1fr">OS families${families.length > 8 ? ` · ${families.length}` : ''}</div>
      <div style="max-height:340px;overflow:auto">${shownFamilies.map(item).join('') || `<div class="section-empty">${lq ? 'None match.' : 'None enrolled yet.'}</div>`}</div>
      <div class="panel-head" style="grid-template-columns:1fr;border-top:1px solid var(--border)">Groups${groups.length > 8 ? ` · ${groups.length}` : ''}</div>
      <div style="max-height:420px;overflow:auto">${shownGroups.map(item).join('') || `<div class="section-empty" style="font-size:11.5px">${lq ? 'None match.' : 'None yet. A group is any set of machines you pick: for their own scripts, and for update rules.'}</div>`}</div>
      ${newGroup}
    </div>`;

  const group = isGroup(selected);
  const inGroup = members(selected);
  const grouped = group ? [] : inGroup.filter(f => (f.group_ids||[]).length);
  const familyNote = grouped.length ? ` · ${grouped.length} of them in a group, whose scripts come first` : '';
  const g = group ? groupByName(selected) : null;
  const detail = `
    <div style="min-width:0;display:flex;flex-direction:column;gap:12px">
      ${g && state.groupEdit === g.id ? `<div class="panel" style="padding:12px 14px">${renderGroupForm(g)}</div>` : `
      <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">${group ? '<span class="badge neutral">Group</span>' : osBadge(selected)}<span class="mono" style="font-weight:600;font-size:14px">${esc(selected)}</span>
        ${g && can ? `<button class="history-toggle" onclick="state.groupEdit=${g.id};render()">rename</button><button class="history-toggle" onclick="deleteGroup(${g.id})">delete group</button>` : ''}
        <span class="grow"></span><span class="secondary" style="font-size:11.5px">${inGroup.length} machine${inGroup.length===1?'':'s'} ${group?'in this group':'in this family'}${familyNote}</span></div>
      ${g && g.description ? `<p class="card-help" style="margin:0">${esc(g.description)}</p>` : ''}`}
      ${g ? renderScriptGroupMembers(g, inGroup, can) : ''}
      ${scriptableStages.map(stage=>{
        const key = `${selected}/${stage}`;
        const s = byKey[key];
        return `<div class="panel">
          <div style="display:flex;align-items:center;gap:10px;padding:11px 14px;border-bottom:1px solid var(--border)">
            <div class="grow"><div style="font-weight:600;font-size:13px">${stageLabels[stage]||stage}</div>
              <div class="mono" style="font-size:11px;color:var(--text-muted);margin-top:2px">${s ? esc(s.filename) : group ? 'not set — each machine uses its OS family’s script or the built-in default' : 'built-in agent default'}</div></div>
            ${s ? `<span class="badge ${s.tested?'success':'warning'}"><span class="g">${s.tested?'&#10003;':'&#9679;'}</span>${s.tested?'Tested':'Untested'}</span>` : `<span class="badge neutral">${group?'Not set':'Default'}</span>`}
            ${s ? `<button class="history-toggle" onclick="viewScriptCode('${jsq(selected)}','${stage}')">${state.scriptsCodeOpen[key]?'hide code':'view code'}</button>` : ''}
            ${s ? `<button class="history-toggle" onclick="toggleScriptHistory('${jsq(selected)}','${stage}')">${state.osScriptsHistoryOpen[key]?'hide history':'history'}</button>` : ''}
            ${can ? `<label class="history-toggle" style="cursor:pointer">${s?'replace':'upload'}<input type="file" style="display:none" onchange="uploadScript('${jsq(selected)}','${stage}',this)"></label>` : ''}
            ${can && s ? `<button class="danger-ghost" title="Remove — ${group?'machines fall back to their OS family’s script':'reverts to built-in default'}" onclick="removeScript('${jsq(selected)}','${stage}')">✕</button>` : ''}
          </div>
          ${s ? `<div style="padding:9px 14px;font-size:11px;color:var(--text-muted)">Uploaded ${fmtDate(s.uploaded_at)} by <span class="mono">${esc(s.uploaded_by)}</span> &middot; runs as root on the agent; a failure here halts the run before patching.</div>` : ''}
          ${s && state.scriptsCodeOpen[key] ? `<pre class="log-tail" style="margin:0 14px 12px;max-height:220px">${state.scriptsCodeData[key]!==undefined ? esc(state.scriptsCodeData[key]) : 'Loading…'}</pre>` : ''}
          ${s && state.osScriptsHistoryOpen[key] ? `<div class="history-panel" style="border-top:1px solid var(--border)">
            ${(state.osScriptsHistoryData[key]||[]).map(h=>`<div class="history-entry"><span class="ts">${fmtTs(h.uploaded_at)}</span><span>${esc(h.uploaded_by)} — ${esc(h.note)} (${esc(h.filename)})</span></div>`).join('') || '<span class="muted">No previous versions.</span>'}
          </div>` : ''}
        </div>`;
      }).join('')}
      <p class="card-help" style="margin:0">Live, tested and current are separate claims: a freshly uploaded or replaced script comes back <strong>untested</strong> until you confirm it, and its predecessor is kept in history so you can see what changed.</p>
    </div>`;

  return header + `<div style="display:grid;grid-template-columns:266px minmax(0,1fr);gap:16px;align-items:start">${sidebar}${detail}</div>`;
}
// Create (g = null) or rename/describe a group.
function renderGroupForm(g){
  return `<div style="display:flex;flex-direction:column;gap:7px">
    <div style="font-size:11px;font-weight:600;color:var(--text-secondary)">${g ? 'Rename group' : 'New group'}</div>
    <input id="group-name" placeholder="name, e.g. db-servers" value="${esc(g ? g.name : '')}" style="font-size:12px">
    <input id="group-desc" placeholder="description (optional)" value="${esc(g ? g.description || '' : '')}" style="font-size:12px">
    <div style="display:flex;gap:6px;justify-content:flex-end">
      <button onclick="state.groupEdit=null;render()">Cancel</button>
      <button class="primary" onclick="saveGroup(${g ? g.id : 'null'})">${g ? 'Save' : 'Create'}</button>
    </div>
  </div>`;
}
async function saveGroup(id){
  const name = document.getElementById('group-name').value.trim();
  const description = document.getElementById('group-desc').value.trim();
  if(!name){ toast('Give the group a name.', 'danger'); return; }
  try{
    const g = id == null ? await api.createGroup({name, description}) : await api.editGroup(id, {name, description});
    state.groupEdit = null; state.scriptsFamily = g.name;
    await Promise.all([loadGroups(), loadOsScripts()]);
    toast(id == null ? `Group ${g.name} created — add machines to it.` : `Group saved.`, 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function deleteGroup(id){
  const g = (state.groups || []).find(x => x.id === id);
  if(!g) return;
  const ok = await confirmDialog({title: `Delete group ${g.name}?`, confirmLabel: 'Delete group',
    message: `Its ${g.host_ids.length} machine${g.host_ids.length===1?'':'s'} stay as they are, just no longer in it, and go back to their OS family's scripts. Its own scripts are kept in history.`});
  if(!ok) return;
  try{ await api.deleteGroup(id); state.scriptsFamily = null; await Promise.all([loadGroups(), loadOsScripts(), loadFleet()]); toast(`Group ${g.name} deleted.`, 'success'); }
  catch(e){ toast(e.message, 'danger'); }
}
// A group's machines, and (admin) a picker to add more -- one or many at once.
function renderScriptGroupMembers(g, inGroup, can){
  const q = (state.scriptsPickQ || '').trim().toLowerCase();
  const others = (state.fleet||[]).filter(f => !(f.group_ids||[]).includes(g.id))
    .filter(f => !q || `${f.hostname} ${f.os_family} ${f.team||''} ${f.role||''}`.toLowerCase().includes(q))
    .sort((a,b) => a.hostname.localeCompare(b.hostname));
  const picked = new Set(state.scriptsPick);
  const n = others.filter(f => picked.has(f.id)).length;
  const otherGroups = f => groupsOf(f).filter(x => x.id !== g.id).map(x => x.name);
  const mq = (state.scriptsMemberQ || '').trim().toLowerCase();
  const members = inGroup.filter(f => !mq || `${f.hostname} ${f.os_family} ${f.team||''} ${f.role||''}`.toLowerCase().includes(mq))
    .sort((a,b) => a.hostname.localeCompare(b.hostname));
  return `<div class="panel">
    <div class="panel-head" style="grid-template-columns:1fr auto;align-items:center">Machines in this group${inGroup.length ? ` · ${inGroup.length}` : ''}
      ${inGroup.length > 10 ? `<input id="scripts-member-q" placeholder="Find in this group" value="${esc(state.scriptsMemberQ||'')}" style="font-size:11.5px;width:180px;text-transform:none;letter-spacing:0;font-family:var(--font-ui)"
        oninput="state.scriptsMemberQ=this.value;render();const e=document.getElementById('scripts-member-q');e.focus();e.setSelectionRange(e.value.length,e.value.length)">` : '<span></span>'}</div>
    <div style="max-height:380px;overflow:auto">
    ${members.map(f => `<div class="panel-row" style="grid-template-columns:minmax(150px,1.1fr) minmax(0,1fr) auto;gap:10px;align-items:center">
        <a href="#" class="mono" style="font-size:12px;min-width:0;overflow-wrap:anywhere" onclick="openHostDetail(${f.id});return false">${esc(f.hostname)}</a>
        <span class="secondary mono" style="font-size:11px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(otherGroups(f).length ? `also in ${otherGroups(f).join(', ')}` : '')}">${esc(f.os_family||'')}${otherGroups(f).length ? ` · also ${esc(otherGroups(f).join(', '))}` : ''}</span>
        ${can ? `<button class="danger-ghost" title="Take ${esc(f.hostname)} out of this group" onclick="removeFromGroup(${g.id}, [${f.id}])">✕</button>` : '<span></span>'}
      </div>`).join('') || `<div class="section-empty">${mq ? 'No machine in this group matches.' : `No machine in this group yet${can ? ' — add some below' : ''}.`}</div>`}
    </div>
    ${can ? `<div style="padding:11px 14px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px">
      <div style="display:flex;gap:8px;align-items:center">
        <span style="font-weight:600;font-size:12px">Add machines</span><span class="grow"></span>
        <input id="scripts-pick-q" placeholder="Filter by name, OS, team" value="${esc(state.scriptsPickQ||'')}" oninput="state.scriptsPickQ=this.value;render();const e=document.getElementById('scripts-pick-q');e.focus();e.setSelectionRange(e.value.length,e.value.length)" style="font-size:12px;width:200px">
      </div>
      <div style="max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px">
        ${others.map(f => `<label style="display:flex;gap:8px;align-items:center;padding:6px 10px;cursor:pointer;font-size:12px">
          <input type="checkbox" ${picked.has(f.id)?'checked':''} onchange="toggleScriptPick(${f.id}, this.checked)">
          <span class="mono" style="min-width:0;overflow-wrap:anywhere;flex:1 1 50%">${esc(f.hostname)}</span>
          <span class="secondary mono" style="font-size:11px;min-width:0;flex:1 1 50%;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(otherGroups(f).join(', '))}">${esc(f.os_family||'')}${otherGroups(f).length ? ` · in ${esc(otherGroups(f).join(', '))}` : ''}</span>
        </label>`).join('') || '<div class="section-empty">No other machines match.</div>'}
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        ${others.length ? `<button onclick="pickAllScriptMachines([${others.map(f=>f.id).join(',')}])">Select all shown</button>` : ''}
        <span class="grow"></span>
        <button class="primary" ${n?'':'disabled'} onclick="addToGroup(${g.id}, state.scriptsPick)">Add ${n||''} machine${n===1?'':'s'}</button>
      </div>
      <div style="font-size:10.5px;color:var(--text-muted)">A machine can be in several groups. If this group has scripts, a machine can't also be in another group with a script for the same stage, and Windows and Linux machines can't share it.</div>
    </div>` : ''}
  </div>`;
}
function toggleScriptPick(id, on){
  const s = new Set(state.scriptsPick); on ? s.add(id) : s.delete(id);
  state.scriptsPick = [...s]; render();
}
function pickAllScriptMachines(ids){ state.scriptsPick = [...new Set([...state.scriptsPick, ...ids])]; render(); }
async function afterMembershipChange(ids){
  await Promise.all([loadGroups(), loadFleet()]);
  if(state.nav === 'host' && ids.includes(state.hostDetailId)) await openHostDetail(state.hostDetailId);
  render();
}
async function addToGroup(groupId, ids){
  if(!ids.length) return;
  try{
    const g = await api.addGroupMembers(groupId, ids);
    state.scriptsPick = [];
    await afterMembershipChange(ids);
    toast(`${ids.length} machine${ids.length===1?'':'s'} added to ${g.name}.`, 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
async function removeFromGroup(groupId, ids){
  try{
    const g = await api.removeGroupMembers(groupId, ids);
    await afterMembershipChange(ids);
    toast(`Taken out of ${g.name}.`, 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
function selectScriptFamily(family){ state.scriptsFamily = family; state.scriptsPick = []; state.scriptsPickQ = ''; state.scriptsMemberQ = ''; render(); }
async function viewScriptCode(family, stage){
  const key = `${family}/${stage}`;
  state.scriptsCodeOpen[key] = !state.scriptsCodeOpen[key];
  render();
  if(state.scriptsCodeOpen[key] && state.scriptsCodeData[key]===undefined){
    try{
      // Via the api layer, not fetch(): that is what turns an expired
      // session into a bounce to the login screen instead of a code pane
      // quietly reading "(could not load script content)" on a console that
      // can no longer talk to the server at all.
      state.scriptsCodeData[key] = await api.osScriptContent(family, stage);
    }catch(e){ state.scriptsCodeData[key] = `(could not load script content: ${e.message})`; }
    render();
  }
}
async function toggleScriptHistory(family, stage){
  const key = `${family}/${stage}`;
  state.osScriptsHistoryOpen[key] = !state.osScriptsHistoryOpen[key];
  render();
  if(state.osScriptsHistoryOpen[key] && !state.osScriptsHistoryData[key]){
    try{ state.osScriptsHistoryData[key] = await api.osScriptHistory(family, stage); render(); }
    catch(e){ /* leave as loading */ }
  }
}
async function uploadScript(family, stage, inputEl){
  const file = inputEl.files[0];
  if(!file) return;
  try{
    await api.uploadOsScript(family, stage, file);
    delete state.osScriptsHistoryData[`${family}/${stage}`];
    delete state.scriptsCodeData[`${family}/${stage}`];
    await loadOsScripts();
    toast(`Script uploaded for ${family}/${stage}.`, 'success');
  }catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function removeScript(family, stage){
  const fallback = groupByName(family) ? `their OS family's ${stage} script, or the built-in step` : `the built-in ${stage} step`;
  const ok = await confirmDialog({
    title: `Remove ${family}'s ${stage} script?`,
    message: `Machines it applies to run ${fallback} from their next run.`,
    confirmLabel: 'Remove script', danger: true,
  });
  if(!ok) return;
  try{ await api.deleteOsScript(family, stage); await loadOsScripts(); toast(`Script removed — machines now run ${fallback}.`, 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
