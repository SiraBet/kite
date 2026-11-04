/*
 * The full audit trail — filterable by result and actor, built for
 * audits and incident review.
 */
/* ============================== ACTIVITY LOG ============================== */
// tone (from the server) -> one of four result claims, never collapsed to
// pass/fail. A neutral tone is an informational event that simply happened
// (a login, a token issued) — it reads "logged", a calm grey chip. That is
// NOT the hatched "unknown": the design reserves hatching for an outcome we
// could not observe, which here is a 'warning'-toned event like a host
// going silent — so the two stay visually distinct.
const RESULT_STYLE = {
  success: ['success', '&#10003;', 'ok'],
  danger:  ['danger',  '&#9650;',  'failed'],
  warning: ['warning', '&#9679;',  'attention'],
  neutral: ['neutral', '',         'logged'],
};
function auditResultChip(tone){
  const [cls, glyph, label] = RESULT_STYLE[tone] || RESULT_STYLE.neutral;
  return `<span class="badge ${cls}">${glyph ? `<span class="g">${glyph}</span>` : ''}${label}</span>`;
}
const AUTOMATED_ACTORS = new Set(['system','schedule','controller','agent']);
function auditIsAutomated(e){ return AUTOMATED_ACTORS.has((e.actor||'').toLowerCase()) || AUTOMATED_ACTORS.has((e.role||'').toLowerCase()); }
function setAuditResult(v){ state.auditResult = v; render(); }
function setAuditActor(v){ state.auditActor = v; render(); }
function auditExportCsv(){
  const rows = auditFiltered();
  const cols = ['ts','actor','role','action','detail','tone'];
  const csv = [cols.join(',')].concat(rows.map(e=>cols.map(c=>{
    const v = e[c]==null?'':String(e[c]); return /[",\n]/.test(v)?`"${v.replace(/"/g,'""')}"`:v;
  }).join(','))).join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `kite-activity-${new Date().toISOString().slice(0,10)}.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(a.href), 2000);
}
function auditFiltered(){
  const q = (state.auditFilter||'').trim().toLowerCase();
  return (state.auditLog||[]).filter(e =>
    (state.auditResult==='all' || (e.tone||'neutral')===state.auditResult) &&
    (state.auditActor==='all' || (state.auditActor==='auto' ? auditIsAutomated(e) : !auditIsAutomated(e))) &&
    (!q || (e.actor||'').toLowerCase().includes(q) || (e.action||'').toLowerCase().includes(q) || (e.detail||'').toLowerCase().includes(q)));
}
function renderAudit(){
  if(state.auditLog===null) return `<div class="view-header"><h1 class="view-title">Activity log</h1></div><div class="loading-rows"><div class="skeleton" style="height:520px"></div></div>`;
  const all = state.auditLog;
  const rows = auditFiltered();
  const count = tone => all.filter(e => (e.tone||'neutral')===tone).length;
  const resultOption = (v, label) => `<div class="fleet-tab" style="border:none;padding:6px 8px;border-radius:5px;${state.auditResult===v?'background:var(--rail);color:#fff':''}" onclick="setAuditResult('${v}')">${label}<span class="grow"></span><span class="n" style="${state.auditResult===v?'color:#9BA5A3':''}">${v==='all'?all.length:count(v)}</span></div>`;
  const actorOption = (v, label, n) => `<div class="fleet-tab" style="border:none;padding:6px 8px;border-radius:5px;${state.auditActor===v?'background:var(--rail);color:#fff':''}" onclick="setAuditActor('${v}')">${label}<span class="grow"></span><span class="n" style="${state.auditActor===v?'color:#9BA5A3':''}">${n}</span></div>`;
  const people = all.filter(e=>!auditIsAutomated(e)).length;
  return `
    <div class="view-header">
      <h1 class="view-title">Activity log</h1>
      <p class="view-sub">Who did what, when, and what happened — actor identity comes from the session, not client input. Append-only.</p>
    </div>
    <div style="display:grid;grid-template-columns:210px minmax(0,1fr);gap:16px;align-items:start">
      <div class="card" style="padding:0">
        <div style="padding:12px 13px;border-bottom:1px solid var(--border)">
          <div class="step-lbl">Result</div>
          <div style="display:flex;flex-direction:column;gap:2px;margin-top:2px">
            ${resultOption('all','All')}
            ${resultOption('success','Succeeded')}
            ${resultOption('danger','Failed')}
            ${resultOption('warning','Attention')}
            ${resultOption('neutral','Logged')}
          </div>
        </div>
        <div style="padding:12px 13px;border-bottom:1px solid var(--border)">
          <div class="step-lbl">Actor</div>
          <div style="display:flex;flex-direction:column;gap:2px;margin-top:2px">
            ${actorOption('all','Everyone', all.length)}
            ${actorOption('people','People', people)}
            ${actorOption('auto','Automated', all.length-people)}
          </div>
        </div>
        <div style="padding:12px 13px">
          <button style="width:100%" onclick="auditExportCsv()">Export ${rows.length} events</button>
          <div style="font-size:10px;color:var(--text-muted);margin-top:7px;line-height:1.4">CSV of the current filter. The log is append-only.</div>
        </div>
      </div>
      <div style="min-width:0">
        <div class="field-row" style="margin-bottom:12px">
          <input id="audit-filter" placeholder="Filter by actor, action, or detail…" value="${esc(state.auditFilter||'')}" oninput="liveFilter(this,'auditFilter')">
          <span class="secondary" style="font-size:11.5px;white-space:nowrap">${rows.length} of ${all.length}</span>
        </div>
        <div class="panel">
          <div class="panel-head" style="grid-template-columns:96px 110px 1fr 1.5fr 104px">
            <div>Timestamp</div><div>Actor</div><div>Action</div><div>Detail</div><div>Result</div>
          </div>
          ${rows.length===0
            ? `<div class="log-empty">${all.length===0 ? 'No events yet.' : 'No events match this filter.'}</div>`
            : rows.map(e=>`
              <div class="panel-row" style="grid-template-columns:96px 110px 1fr 1.5fr 104px;align-items:start">
                <span class="mono" style="font-size:10.5px;color:var(--text-muted)">${fmtTs(e.ts).slice(5)}</span>
                <span style="font-size:11.5px">${esc(e.actor)}${e.role?`<div class="host-sub">${esc(e.role)}</div>`:''}</span>
                <span class="mono" style="font-size:11px">${esc(e.action)}</span>
                <span class="secondary clamp-3 ${(e.detail||'').length > 240 ? 'clamp-toggle' : ''}" style="font-size:11.5px;min-width:0;overflow-wrap:anywhere" ${(e.detail||'').length > 240 ? `title="Click to show all" onclick="this.classList.toggle('clamp-3')"` : ''}>${esc(e.detail||'—')}</span>
                <span>${auditResultChip(e.tone)}</span>
              </div>`).join('')}
        </div>
      </div>
    </div>`;
}
