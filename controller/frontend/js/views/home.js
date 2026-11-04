/*
 * The landing page. See app/routers/dashboard.py for why its data is
 * aggregated server-side into one call.
 */
/* ============================== HOME ==============================
   The landing page after login. Backed by a single aggregated call
   (GET /dashboard) rather than fanning out to /hosts + /runs + /audit +
   /schedules and reducing them here — see app/routers/dashboard.py for
   why that boundary is drawn there. This function stays a pure
   state -> HTML mapping so tests/test_frontend_render.py can exercise
   it without a browser. */
function relTime(iso){
  if(!iso) return 'never';
  const sec = Math.max(0, (Date.now() - parseUTC(iso).getTime()) / 1000);
  if(sec < 60) return 'just now';
  const mins = Math.floor(sec/60);
  if(mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins/60);
  if(hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours/24)}d ago`;
}
function untilTime(iso){
  // relTime()'s counterpart for timestamps in the FUTURE. Not the same
  // function with a sign flip: relTime clamps at 0 so a clock skew of a
  // few seconds reads "just now" instead of a negative age, and that
  // same clamp would make every upcoming schedule read "just now" too.
  if(!iso) return '—';
  const sec = (parseUTC(iso).getTime() - Date.now()) / 1000;
  if(sec <= 0) return 'due now';
  const mins = Math.round(sec/60);
  if(mins < 60) return `in ${mins}m`;
  const hours = Math.round(mins/60);
  if(hours < 24) return `in ${hours}h`;
  return `in ${Math.round(hours/24)}d`;
}

// The worst-off table's status column, following the same "solid = we
// checked, hatched = we couldn't" rule as the fleet badge.
function woStatusBadge(status){
  if(status === 'no_answer') return `<span class="badge unknown"><span class="g">?</span>No answer</span>`;
  if(status === 'urgent')    return `<span class="badge danger"><span class="g">&#9650;</span>Urgent</span>`;
  return `<span class="badge warning"><span class="g">&#9679;</span>Due</span>`;
}

// A recent run's status pill. Mirrors the job lifecycle in models.Job.
const RUN_BADGE = {
  running:   ['info running', ''],
  queued:    ['neutral', ''],
  done:      ['success', '&#10003;'],
  failed:    ['danger', '&#9650;'],
  cancelled: ['warning', '&#8213;'],
};
const RUN_LABEL = {running:'Running', queued:'Queued', done:'Succeeded', failed:'Failed', cancelled:'Stopped'};
function recentRunBadge(status){
  const [cls, glyph] = RUN_BADGE[status] || ['neutral', ''];
  return `<span class="badge ${cls}">${glyph ? `<span class="g">${glyph}</span>` : `<span class="g"></span>`}${RUN_LABEL[status] || esc(status)}</span>`;
}
function runSummary(run){
  const sev = run.severity_filter ? run.severity_filter.replace(/,/g, ', ') : 'all updates';
  const scope = run.scope === 'containers' ? 'containers' : run.scope === 'both' ? 'OS + containers' : 'OS';
  return `${esc(sev)} &middot; ${esc(run.hostname)} &middot; ${scope}`;
}

function renderHome(){
  const d = state.dashboard;
  if(d === null || d === undefined){
    return `
      <div class="view-header">
        <h1 class="view-title">Overview</h1>
        <p class="view-sub">Loading…</p>
      </div>
      <div class="stat-grid">
        <div class="skeleton" style="height:86px"></div><div class="skeleton" style="height:86px"></div>
        <div class="skeleton" style="height:86px"></div><div class="skeleton" style="height:86px"></div>
      </div>
      <div class="loading-rows"><div class="skeleton" style="height:180px"></div></div>`;
  }

  const f = d.fleet, r = d.runs;
  const greeting = state.user ? esc(state.user.display_name || state.user.username) : '';

  if(f.total === 0){
    return `
      <div class="view-header">
        <h1 class="view-title">Welcome, ${greeting}</h1>
        <p class="view-sub">No hosts enrolled yet — that's the next step.</p>
      </div>
      <div class="section">
        <div class="section-head"><p class="section-title">Get started</p></div>
        <div class="section-body">
          <p style="margin:0 0 14px;font-size:13px;color:var(--text-secondary);line-height:1.6">
            kite needs at least one enrolled host before it can do anything useful.
            Enrolling installs an agent that polls this controller — nothing here ever
            connects into your machines.
          </p>
          <button class="primary" onclick="navigate('fleet')">Enroll your first host</button>
        </div>
      </div>`;
  }

  const risk = d.risk || {};
  const unassessed = risk.unassessed || 0;
  const urgentHosts = (risk.hosts_with_critical || 0) + (risk.hosts_with_important || 0);
  const activeRun = d.active_runs[0];
  const worst = risk.worst_hosts || [];
  const recent = d.recent_runs || [];

  // One banner, the single worst TRUE thing — never a green "all good"
  // bar. Absent when nothing is urgent.
  let banner = '';
  if(risk.hosts_with_critical){
    banner = `
      <div class="banner danger" style="align-items:center">
        <span class="g" style="font:600 13px var(--font-mono);color:var(--urgent)">&#9650;</span>
        <div class="grow">
          <div style="font-weight:600">${risk.hosts_with_critical} host${risk.hosts_with_critical===1?'':'s'} carry a Critical security update</div>
          <div style="margin-top:2px;font-size:11.5px" class="secondary">${risk.security||0} security update${(risk.security||0)===1?'':'s'} pending across the fleet</div>
        </div>
        <button onclick="navigate('fleet')">Review hosts</button>
        ${atLeast(state.user.role, 'operator') ? `<button class="danger" onclick="navigate('run')">Patch now…</button>` : ''}
      </div>`;
  } else if(f.offline){
    banner = `
      <div class="banner warning" style="align-items:center">
        <span class="g" style="font:600 13px var(--font-mono)">?</span>
        <div class="grow"><div style="font-weight:600">${f.offline} host${f.offline===1?'':'s'} unreachable</div>
          <div style="margin-top:2px;font-size:11.5px">status unknown — not confirmed healthy or unhealthy</div></div>
        <button onclick="navigate('fleet')">Review</button>
      </div>`;
  }

  const tile = (label, value, sub, opts={}) => `
    <div class="stat-card ${opts.tone?'tone-'+opts.tone:''} ${opts.onclick?'clickable':''}" ${opts.onclick?`onclick="${opts.onclick}"`:''}>
      <div class="stat-label" ${opts.labelColor?`style="color:${opts.labelColor}"`:''}>${opts.glyph||''}${label}</div>
      <div class="stat-value ${opts.valueTone||''}" ${opts.valueColor?`style="color:${opts.valueColor}"`:''}>${value}</div>
      ${opts.bar||''}
      ${sub?`<div class="stat-sub">${sub}</div>`:''}
    </div>`;

  return `
    <div class="fleet-topbar">
      <div class="fleet-search" onclick="navigate('fleet')" title="Search the fleet">
        <span style="width:11px;height:11px;border:1.5px solid var(--text-muted);border-radius:50%;flex:none"></span>
        <span style="flex:1;font-family:var(--font-mono);font-size:12px;color:var(--text-muted)">Search hosts, packages, runs</span>
        <kbd style="font-family:var(--font-mono);font-size:10px;background:#fff;border:1px solid var(--border-input);border-radius:3px;padding:2px 4px;color:var(--text-secondary)">/</kbd>
      </div>
      <div class="grow"></div>
      <span class="topbar-sweep"><span class="dot"></span>Last full sweep <b>${relTime(d.generated_at)}</b></span>
      <button onclick="loadDashboard()">Refresh</button>
      ${atLeast(state.user.role, 'operator') ? `<button class="primary" onclick="navigate('run')">Run patching</button>` : ''}
    </div>

    ${state.loadError ? errorBanner(state.loadError) : ''}
    ${banner}

    <div class="stat-grid" style="grid-template-columns:repeat(auto-fit,minmax(178px,1fr));margin-top:${banner?'14px':'0'}">
      ${tile('Reachable', `${f.healthy}<span style="font:400 13px var(--font-mono);color:var(--text-muted)"> / ${f.total}</span>`,
        'answered within their poll window', {onclick:"navigate('fleet')",
        bar:`<div class="bar-track" style="margin-top:10px"><span class="bar-seg ok" style="width:${f.compliance_pct}%"></span><span class="bar-seg unknown" style="width:${100-f.compliance_pct}%"></span></div>`})}

      ${tile('Verified current', `${risk.verified_current||0}<span style="font:400 13px var(--font-mono);color:var(--text-muted)"> / ${f.total}</span>`,
        `${f.total?Math.round((risk.verified_current||0)/f.total*100):100}% confirmed up to date`,
        {onclick:"navigate('fleet')", valueTone:'success',
         bar:`<div class="bar-track" style="margin-top:10px"><span class="bar-seg ok" style="width:${f.total?Math.round((risk.verified_current||0)/f.total*100):0}%"></span></div>`})}

      ${tile('Urgent waiting', urgentHosts, '',
        {tone:'danger', onclick:"navigate('fleet')", glyph:`<span class="g" style="color:var(--urgent);margin-right:5px">&#9650;</span>`,
         labelColor:'var(--urgent-ink)', valueTone:'danger',
         bar: urgentHosts ? `<div style="display:flex;gap:4px;margin-top:9px">${risk.hosts_with_critical?sevChip('critical',risk.hosts_with_critical):''}${risk.hosts_with_important?sevChip('important',risk.hosts_with_important):''}</div>` : `<div class="stat-sub">no critical or important updates waiting</div>`})}

      ${tile('Patching now', r.active,
        activeRun ? `${esc(activeRun.hostname)} &middot; ${activeRun.stage_index}/${activeRun.total_stages}` : 'no runs in progress',
        {tone:'info', onclick:"navigate('run')", valueColor:'var(--info)', labelColor:'var(--info)',
         glyph:`<span class="spin" style="margin-right:6px;color:var(--info)"></span>`})}

      ${tile("Couldn't check", unassessed, 'unknown, not zero — excluded from the % at left',
        {tone:'unknown', onclick:"navigate('fleet')", glyph:`<span class="g" style="margin-right:5px">?</span>`})}
    </div>

    <div class="dash-grid" style="margin-top:14px">
      <div class="dash-col">
        <div class="section">
          <div class="section-head">
            <span style="display:flex;align-items:center;gap:9px;min-width:0">
              <span class="section-title">Worst off right now</span>
              <span class="secondary" style="font-size:11px">ranked by severity</span>
            </span>
            <span class="section-link" onclick="navigate('fleet')">All ${f.total} &rarr;</span>
          </div>
          ${worst.length === 0
            ? `<p class="section-empty">Nothing pending — every assessed host is current.</p>`
            : `<div class="wo-head"><span>Host</span><span>Owner</span><span>Pending</span><span>Status</span></div>
               ${worst.map(h => `
                <div class="wo-row ${h.status==='urgent'?'urgent':h.status==='no_answer'?'no-answer':''}">
                  <div style="min-width:0">
                    <a href="#" class="wo-host" onclick="openHostDetail(${h.host_id});return false">${esc(h.hostname)}</a>
                    ${h.os ? `<div class="wo-sub">${esc(h.os)}</div>` : ''}
                  </div>
                  <span class="wo-owner">${esc(h.team||'—')}</span>
                  <span class="wo-pending">
                    ${h.total===null ? '<span class="wo-muted">unknown</span>'
                      : `${h.critical?sevChip('critical',h.critical):''}${h.important?sevChip('important',h.important):''}${(!h.critical&&!h.important)?`<span class="wo-muted">${h.total}</span>`:''}`}
                  </span>
                  ${woStatusBadge(h.status)}
                </div>`).join('')}`}
        </div>

        <div class="section">
          <div class="section-head">
            <p class="section-title">Recent runs</p>
            <span class="section-link" onclick="navigate('audit')">Full history &rarr;</span>
          </div>
          ${recent.length === 0
            ? `<p class="section-empty">No runs yet — nothing has been patched from here.</p>`
            : recent.map(run => `
                <div class="rr-row ${run.status==='running'?'running':''}">
                  <a href="#" class="rr-id ${run.status==='running'?'':'done'}" onclick="openJobProgress(${run.job_id});return false">run-${run.job_id}</a>
                  ${recentRunBadge(run.status)}
                  <span class="rr-sum">${runSummary(run)}</span>
                  <span class="rr-actor">${run.operator ? esc(run.operator) : 'schedule'}</span>
                  <span class="rr-time">${run.status==='running' ? `${run.stage_index}/${run.total_stages}` : relTime(run.updated_at)}</span>
                </div>`).join('')}
        </div>
      </div>

      <div class="dash-col">
        <div class="section">
          <div class="section-head">
            <span style="display:flex;align-items:center;gap:8px">
              <span class="feed-dot success" style="margin:0;animation:pulse 2s ease-in-out infinite"></span>
              <span class="section-title">Activity</span>
            </span>
            <span class="section-link" onclick="navigate('audit')">All &rarr;</span>
          </div>
          ${d.activity.length === 0
            ? `<p class="section-empty">Nothing has happened yet.</p>`
            : `<div class="section-body flush">${d.activity.map(a => `
                <div class="feed-item">
                  <span class="feed-dot ${esc(a.tone)}"></span>
                  <div class="feed-body">
                    <div class="clamp-3" title="${esc(a.detail || '')}"><span class="feed-action">${esc(a.action)}</span>
                    ${a.detail ? ` <span class="feed-detail">${esc(a.detail)}</span>` : ''}</div>
                    <div class="feed-meta">${esc(a.actor)} &middot; ${relTime(a.ts)}</div>
                  </div>
                </div>`).join('')}</div>`}
        </div>
      </div>
    </div>`;
}
