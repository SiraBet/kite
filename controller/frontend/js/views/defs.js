/*
 * Patch definitions: the skip/pin rules sent to agents.
 */
/* ============================== DEFINITIONS ============================== */
const DEFS_PAGE = 25;
function renderDefs(){
  const can = atLeast(state.user.role, 'admin');
  if(state.defs===null) return `<div class="view-header"><h1 class="view-title">Patch definitions</h1></div><div class="loading-rows"><div class="skeleton"></div><div class="skeleton"></div></div>`;
  const defs = state.defs;
  const holds = defs.filter(d=>d.mode!=='pin').length;
  const pins = defs.filter(d=>d.mode==='pin').length;
  const unreviewed = defs.filter(d=>(d.reviewed||'').toLowerCase().includes('not')).length;
  const N = state.newRule;   // the add form, kept across re-renders while targets are picked
  return `
    <div class="view-header">
      <h1 class="view-title">Update rules</h1>
      <p class="view-sub">Holds and pins — what we deliberately don't patch, and why. Every rule needs a reason; the list is audited.</p>
    </div>
    ${state.loadError ? errorBanner(state.loadError) : ''}
    ${!can ? `<div class="rbac-lock" style="margin-bottom:14px">${LOCK_ICON} Editing requires Admin role. You're signed in as ${esc(state.user.role)}.</div>` : ''}
    <div class="stat-grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
      <div class="stat-card"><div class="stat-label">Active rules</div><div class="stat-value">${defs.length}</div></div>
      <div class="stat-card"><div class="stat-label">Holds</div><div class="stat-value">${holds}</div><div class="stat-sub">package skipped entirely</div></div>
      <div class="stat-card"><div class="stat-label">Pins</div><div class="stat-value">${pins}</div><div class="stat-sub">held at a version</div></div>
      <div class="stat-card ${unreviewed?'tone-unknown':''}"><div class="stat-label">Not yet reviewed</div><div class="stat-value">${unreviewed}</div></div>
    </div>
    ${state.defs.length>3 ? `<div class="toolbar" style="justify-content:flex-end"><input id="defs-search" placeholder="Filter by package…" style="max-width:220px" value="${esc(state.defsSearch||'')}" oninput="state.defsPage=0;liveFilter(this,'defsSearch')"></div>` : ''}
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-head" style="grid-template-columns:1.1fr 130px 1.4fr 1.2fr 100px 80px 36px">
        <div>Package</div><div>Action</div><div>Applies to</div><div>Reason</div><div>Reviewed</div><div>History</div><div></div>
      </div>
      ${(()=>{ const q=(state.defsSearch||'').trim().toLowerCase(); const all = !q ? state.defs : state.defs.filter(d=>d.pkg_pattern.toLowerCase().includes(q));
        const pages = Math.max(1, Math.ceil(all.length / DEFS_PAGE)), page = Math.min(state.defsPage || 0, pages - 1);
        const list = all.slice(page * DEFS_PAGE, (page + 1) * DEFS_PAGE);
        const pager = pages > 1 ? `<div class="pager"><span>${page * DEFS_PAGE + 1}–${page * DEFS_PAGE + list.length} of ${all.length}</span><span class="grow"></span>
          <button ${page===0?'disabled':''} onclick="state.defsPage=${page-1};render()">&larr; Prev</button><button ${page>=pages-1?'disabled':''} onclick="state.defsPage=${page+1};render()">Next &rarr;</button></div>` : '';
        return list.length ? list.map(d=>`
        <div class="panel-row" style="grid-template-columns:1.1fr 130px 1.4fr 1.2fr 100px 80px 36px">
          <div class="mono" style="font-weight:500;font-size:12px;min-width:0;overflow-wrap:anywhere">${esc(d.pkg_pattern)}</div>
          <div style="min-width:0">${d.mode==='pin'
              ? `<span class="badge neutral" style="max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle" title="Pin${d.version?` ≤ ${esc(d.version)}`:''}">Pin${d.version?` &le; ${esc(d.version)}`:''}</span>`
              : `<span class="badge unknown">Hold</span>`}</div>
          <div style="font-size:11px;min-width:0">${ruleTargetsHtml(d.targets, d.id)}${can ? ` <button class="history-toggle" onclick="editRuleTargets(${d.id})">change</button>` : ''}</div>
          <div class="secondary" style="font-size:11.5px">${esc(d.reason||'—')}</div>
          <div class="mono muted" style="font-size:10.5px">${esc(d.reviewed)}</div>
          <div><button class="history-toggle" onclick="toggleHistory(${d.id})">${state.defsHistoryOpen[d.id]?'hide':'view'}</button></div>
          <div>${can ? `<button class="danger-ghost" title="Remove" onclick="delDef(${d.id})">✕</button>` : ''}</div>
        </div>
        ${state.defTargets && state.defTargets.id === d.id ? `<div class="history-panel">${renderTargetPicker()}
          <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px"><button onclick="state.defTargets=null;render()">Cancel</button><button class="primary" onclick="saveRuleTargets(${d.id})">Save</button></div></div>` : ''}
        ${state.defsHistoryOpen[d.id] ? `<div class="history-panel">
          ${(state.defsHistoryData[d.id]||[]).map(h=>`<div class="history-entry"><span class="ts">${fmtTs(h.at)}</span><span>${esc(h.by)} — ${esc(h.change)}</span></div>`).join('') || '<span class="muted">Loading…</span>'}
        </div>` : ''}
      `).join('') + pager : `<div class="panel-row muted">${q ? `No rules match "${esc(state.defsSearch)}".` : 'No rules yet. Add one below to hold a package back or pin it to a version.'}</div>`; })()}
      ${state.defs.length ? `<div class="pager" style="justify-content:flex-start"><span style="font-family:var(--font-ui);color:var(--text-secondary)">A machine gets <b>every</b> rule that applies to it: rules for every machine, and those naming its OS family, one of its groups, or the machine itself. Each hold keeps that package off the machine until the rule is removed.</span></div>` : ''}
    </div>
    ${can ? `
      <div style="display:flex;flex-direction:column;gap:8px">
        <div class="field-row">
          <input id="new-pkg" placeholder="package-name*" style="flex:1.3" value="${esc(N.pkg)}" oninput="state.newRule.pkg=this.value">
          <select id="new-mode" onchange="state.newRule.mode=this.value;onDefModeChange()" class="grow">
            <option value="skip" ${N.mode!=='pin'?'selected':''}>Skip entirely</option>
            <option value="pin" ${N.mode==='pin'?'selected':''}>Pin to version, until further notice</option>
          </select>
          <input id="new-version" placeholder="version, e.g. 8.x" style="flex:0.7;display:${N.mode==='pin'?'block':'none'}" value="${esc(N.version)}" oninput="state.newRule.version=this.value">
        </div>
        <div class="field-row" style="align-items:center">
          <span class="secondary" style="font-size:12px;flex:none">Applies to</span>
          <span style="font-size:12px;min-width:0" class="grow">${ruleTargetsHtml(newRuleTargets())}
            <button class="history-toggle" onclick="editRuleTargets('new')">${state.defTargets && state.defTargets.id === 'new' ? 'done' : 'choose…'}</button></span>
          <input id="new-reason" placeholder="Reason (required)" style="flex:1.5" value="${esc(N.reason)}" oninput="state.newRule.reason=this.value">
          <button class="primary" onclick="addDef()">Add</button>
        </div>
        ${state.defTargets && state.defTargets.id === 'new' ? `<div class="panel" style="padding:12px 14px">${renderTargetPicker()}</div>` : ''}
        <div id="def-form-error" style="display:none" class="banner danger"></div>
      </div>` : ''}
  `;
}
function onDefModeChange(){
  const mode = document.getElementById('new-mode').value;
  document.getElementById('new-version').style.display = mode==='pin' ? 'block' : 'none';
}
function showDefFormError(msg){
  const el = document.getElementById('def-form-error');
  el.textContent = msg; el.style.display = 'flex';
}
async function toggleHistory(id){
  state.defsHistoryOpen[id] = !state.defsHistoryOpen[id];
  render();
  if(state.defsHistoryOpen[id] && !state.defsHistoryData[id]){
    try{ state.defsHistoryData[id] = await api.defHistory(id); render(); }
    catch(e){ /* leave as loading */ }
  }
}
async function addDef(){
  const pkg = document.getElementById('new-pkg').value.trim();
  const mode = document.getElementById('new-mode').value;
  const version = document.getElementById('new-version').value.trim();
  const targets = newRuleTargets();
  const reason = document.getElementById('new-reason').value.trim();
  if(!pkg){ showDefFormError('Package pattern is required.'); return; }
  if(mode==='pin' && !version){ showDefFormError('Enter the version to pin to, e.g. "8.x" or "6.0".'); return; }
  if(!reason){ showDefFormError('A reason is required — this list is audited.'); return; }
  try{
    await api.addDef({ pkg_pattern: pkg, mode, version, targets, reason });
    state.defTargets = null; state.newRuleKeys = []; state.newRule = {pkg: '', mode: 'skip', version: '', reason: ''};
    await loadDefs();
    toast(`${pkg} added to definitions.`, 'success');
  }catch(e){ showDefFormError(e.message); }
}
async function delDef(id){
  const d = (state.defs || []).find(x => x.id === id);
  const name = d ? d.pkg_pattern : `rule ${id}`;
  const ok = await confirmDialog({
    title: `Remove the rule for ${name}?`,
    message: `Machines stop ${d && d.mode === 'pin' ? 'holding it at its pinned version' : 'skipping it'} from their next run, `
           + `and ${name} is updated like any other package.`,
    confirmLabel: 'Remove rule', danger: true,
  });
  if(!ok) return;
  try{ await api.delDef(id); await loadDefs(); toast(`Rule for ${name} removed.`, 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}

// ---------- what a rule applies to ----------
// A rule with no targets applies to every machine; otherwise to each
// machine an OS family, group or machine target names.
function ruleApplies(d, host){
  const t = d.targets || [];
  if(!t.length) return true;
  return t.some(x => (x.kind === 'os' && x.value === host.os_family)
    || (x.kind === 'group' && (host.group_ids || []).includes(+x.value))
    || (x.kind === 'host' && +x.value === host.id));
}
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
function targetLabel(t){
  if(t.kind === 'os') return {label: t.value, tag: 'OS'};
  if(t.kind === 'group'){ const g = (state.groups || []).find(x => x.id === +t.value); return {label: g ? g.name : `group #${t.value}`, tag: 'group'}; }
  const h = (state.fleet || []).find(x => x.id === +t.value);
  return {label: h ? h.hostname : `removed machine #${t.value}`, tag: 'machine'};
}
// Up to three targets, then "+N more" (all of them once opened); long names end in "…", whole on hover.
function ruleTargetsHtml(targets, ruleId){
  if(!targets || !targets.length) return '<span class="badge neutral">Every machine</span>';
  const open = ruleId != null && state.defsTargetsOpen[ruleId];
  const shown = open ? targets : targets.slice(0, 3);
  const chips = shown.map(t => { const x = targetLabel(t);
    return `<span class="badge neutral" title="${esc(x.tag)} ${esc(x.label)}" style="margin:0 4px 3px 0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle"><span class="muted" style="font-weight:400">${x.tag}</span>&nbsp;${esc(x.label)}</span>`; }).join('');
  const more = targets.length - shown.length;
  return chips + (more > 0 && ruleId != null ? `<button class="history-toggle" onclick="state.defsTargetsOpen[${ruleId}]=true;render()">+${more} more</button>`
    : more > 0 ? `<span class="muted">+${more} more</span>` : open && targets.length > 3 ? `<button class="history-toggle" onclick="state.defsTargetsOpen[${ruleId}]=false;render()">fewer</button>` : '');
}
const keyToTarget = k => { const i = k.indexOf(':'); return {kind: k.slice(0, i), value: k.slice(i + 1)}; };
function newRuleTargets(){ return (state.newRuleKeys || []).map(keyToTarget); }
function editRuleTargets(id){
  if(state.defTargets && state.defTargets.id === id){ state.defTargets = null; render(); return; }
  const d = id === 'new' ? null : (state.defs || []).find(x => x.id === id);
  const keys = id === 'new' ? (state.newRuleKeys || []) : (d.targets || []).map(t => `${t.kind}:${t.value}`);
  state.defTargets = {id, keys: [...keys], q: ''};
  if(state.groups === null) loadGroups();
  render();
}
function toggleRuleTarget(key, on){
  const s = new Set(state.defTargets.keys); on ? s.add(key) : s.delete(key);
  state.defTargets.keys = [...s];
  if(state.defTargets.id === 'new') state.newRuleKeys = [...s];
  render();
}
function renderTargetPicker(){
  const T = state.defTargets, chosen = new Set(T.keys);
  const fleet = state.fleet || [];
  const q = (T.q || '').trim().toLowerCase();
  const families = [...new Set(fleet.map(f => f.os_family).filter(Boolean))].sort();
  const box = (key, label, sub='') => `<label style="display:flex;gap:7px;align-items:center;padding:4px 8px;cursor:pointer;font-size:12px">
      <input type="checkbox" ${chosen.has(key)?'checked':''} onchange="toggleRuleTarget('${jsq(key)}', this.checked)"><span class="mono">${esc(label)}</span>
      ${sub ? `<span class="grow"></span><span class="secondary" style="font-size:10.5px">${esc(sub)}</span>` : ''}</label>`;
  const col = (title, body) => `<div style="min-width:0"><div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:4px">${title}</div>
      <div style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:6px">${body}</div></div>`;
  const hosts = fleet.filter(f => !q || `${f.hostname} ${f.os_family} ${f.team||''} ${f.role||''}`.toLowerCase().includes(q))
    .sort((a,b) => a.hostname.localeCompare(b.hostname));
  return `<div style="font-size:12px;margin-bottom:8px">${chosen.size ? `Applies to any machine matching one of the ${chosen.size} ticked.` : '<strong>Every machine</strong> — tick OS families, groups or machines to narrow it.'}</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">
      ${col('OS families', families.map(f => box(`os:${f}`, f, plural(fleet.filter(x => x.os_family === f).length, 'machine'))).join('') || '<div class="section-empty">None enrolled.</div>')}
      ${col('Groups', (state.groups || []).map(g => box(`group:${g.id}`, g.name, plural(g.host_ids.length, 'machine'))).join('') || '<div class="section-empty" style="font-size:11.5px">None yet — make them on Per-system scripts.</div>')}
      ${col(`Machines <input id="def-target-q" placeholder="filter" value="${esc(T.q||'')}" oninput="state.defTargets.q=this.value;render();const e=document.getElementById('def-target-q');e.focus();e.setSelectionRange(e.value.length,e.value.length)" style="font-size:11px;width:110px;margin-left:6px">`,
        hosts.map(f => box(`host:${f.id}`, f.hostname, f.os_family)).join('') || '<div class="section-empty">No machines match.</div>')}
    </div>
    ${chosen.size ? `<div style="margin-top:6px"><button class="history-toggle" onclick="state.defTargets.keys=[];if(state.defTargets.id==='new')state.newRuleKeys=[];render()">clear — every machine</button></div>` : ''}`;
}
async function saveRuleTargets(id){
  try{
    await api.setDefTargets(id, state.defTargets.keys.map(keyToTarget));
    state.defTargets = null;
    await loadDefs();
    toast('Rule updated.', 'success');
  }catch(e){ toast(e.message, 'danger'); }
}
