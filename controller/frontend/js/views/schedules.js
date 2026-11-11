/*
 * Recurring runs.
 */
/* ============================== SCHEDULES ============================== */
function scheduleScopeBadge(scope){
  const map = {
    os: ['neutral', 'OS'],
    containers: ['info', 'containers'],
    both: ['info', 'OS + containers'],
  };
  const [tone, label] = map[scope] || map.os;
  return `<span class="badge ${tone}">${label}</span>`;
}
function renderSchedules(){
  const can = atLeast(state.user.role, 'admin');
  if(state.schedules===null) return `<div class="view-header"><h1 class="view-title">Schedules</h1></div><div class="loading-rows"><div class="skeleton"></div><div class="skeleton"></div></div>`;
  return `
    <div class="view-header">
      <h1 class="view-title">Schedules</h1>
      <p class="view-sub">Unattended runs — what fires, when, and on how many machines. Times are UTC; a fired run uses the same readiness gates as a manual one (auto-confirmed and logged as such).</p>
    </div>
    ${state.loadError ? errorBanner(state.loadError) : ''}
    ${!can ? `<div class="rbac-lock" style="margin-bottom:14px">${LOCK_ICON} Editing requires Admin role. You're signed in as ${esc(state.user.role)}.</div>` : ''}
    ${requireTicket() ? `<div class="banner neutral" style="margin-bottom:14px">Ticket requirement is on — a schedule needs an already-Approved ticket to fire, checked fresh every time (not just when the schedule was created).</div>` : ''}
    ${renderScheduleStrip()}
    ${state.schedules.length===0 ? `<div class="banner neutral" style="margin-bottom:14px">No schedules yet.</div>` : `
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-head" style="grid-template-columns:1.4fr 0.95fr 1.1fr 0.6fr 0.95fr 0.95fr 92px 34px">
        <div>Schedule</div><div>Scope</div><div>Fires (UTC)</div><div>Hosts</div><div>Next run</div><div>Last fired</div><div>State</div><div></div>
      </div>
      ${state.schedules.map(s=>{
        const next = scheduleNextFire(s.day_of_week, s.hour);
        const hosts = (state.fleet||[]).filter(f => !s.team || f.team===s.team).length;
        return `
        <div class="panel-row" style="grid-template-columns:1.4fr 0.95fr 1.1fr 0.6fr 0.95fr 0.95fr 92px 34px">
          <div><div class="mono" style="font-weight:500;font-size:12px">${esc(s.name)}</div>
            <div class="host-sub">${esc(s.team||'all teams')} &middot; ${s.severity_filter?esc(s.severity_filter)+' only':'all updates'} &middot; ${s.rollout==='one_at_a_time'?'one machine at a time':'every machine at once'}${s.ticket_id?` &middot; ${esc(s.ticket_id)}`:''}</div></div>
          <div>${scheduleScopeBadge(s.scope)}</div>
          <div class="mono secondary" style="font-size:11.5px">Weekly · ${DAY_NAMES[s.day_of_week]} ${String(s.hour).padStart(2,'0')}:00</div>
          <div class="mono" style="font-size:11.5px">${hosts}</div>
          <div class="mono" style="font-size:11.5px">${s.enabled ? untilTime(next.toISOString()) : '— off'}</div>
          <div class="secondary" style="font-size:11px">${s.last_fired_at ? fmtTs(s.last_fired_at) : 'never'}</div>
          <div>${can
            ? `<span onclick="toggleSchedule(${s.id},${!s.enabled})" title="${s.enabled?'Disable':'Enable'}" style="cursor:pointer;display:inline-flex;align-items:center;gap:6px;font:600 10.5px/1 var(--font-ui);color:${s.enabled?'var(--ok-ink)':'var(--text-muted)'}">
                 <span style="width:26px;height:15px;border-radius:8px;position:relative;background:${s.enabled?'var(--ok)':'#fff'};border:${s.enabled?'1px solid var(--ok)':'1px solid var(--border-input)'}"><span style="position:absolute;top:1px;${s.enabled?'right:2px':'left:2px'};width:11px;height:11px;border-radius:50%;background:${s.enabled?'#fff':'var(--border-input)'}"></span></span>${s.enabled?'On':'Off'}</span>`
            : `<span class="badge ${s.enabled?'success':'neutral'}">${s.enabled?'On':'Off'}</span>`}</div>
          <div>${can ? `<button class="danger-ghost" title="Remove" onclick="deleteScheduleHandler(${s.id})">✕</button>` : ''}</div>
        </div>`;
      }).join('')}
    </div>`}
    ${can ? `
      <div style="display:flex;flex-direction:column;gap:8px">
        <div class="field-row">
          <input id="new-sched-name" placeholder="Name, e.g. Patch Tuesday — Platform" style="flex:1.5">
          <select id="new-sched-team" class="grow">
            <option value="">All teams (no restriction)</option>
            ${scheduleTeamOptions().map(t=>`<option value="${esc(t)}">${esc(t)}</option>`).join('')}
          </select>
        </div>
        <div class="field-row">
          <select id="new-sched-day" class="grow">
            ${DAY_NAMES.map((d,i)=>`<option value="${i}">${d}</option>`).join('')}
          </select>
          <select id="new-sched-hour" class="grow">
            ${Array.from({length:24},(_,h)=>`<option value="${h}">${String(h).padStart(2,'0')}:00 UTC</option>`).join('')}
          </select>
          <select id="new-sched-scope" class="grow" title="What each run this schedule starts may touch">
            <option value="os">OS packages</option>
            <option value="containers">Containers only</option>
            <option value="both">OS packages + containers</option>
          </select>
          <select id="new-sched-severity" class="grow" title="Which OS updates each run installs">
            <option value="">All updates</option>
            <option value="security">Security only</option>
            <option value="critical,important">Critical + Important</option>
            <option value="critical">Critical only</option>
          </select>
          <select id="new-sched-rollout" class="grow" title="How a firing reaches the machines in scope. One at a time starts the next machine only when the one before it finished cleanly, and pauses on a failure.">
            <option value="one_at_a_time">One machine at a time</option>
            <option value="parallel">Every machine at once</option>
          </select>
          <select id="new-sched-ticket" class="grow">
            <option value="">${requireTicket() ? 'Select an approved ticket…' : 'No ticket (optional)'}</option>
            ${(state.tickets||[]).map(t=>`<option value="${esc(t.ticket_id)}">${esc(t.ticket_id)} — ${esc(t.status)}</option>`).join('')}
          </select>
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <button class="primary" onclick="createScheduleHandler()">Add schedule</button>
          ${state.tickets!==null && state.tickets.length===0 ? `<span style="font-size:11.5px;color:var(--text-muted)">No tickets exist yet${atLeast(state.user.role, 'lead') ? ` — <a href="#" onclick="state.showNewTicketForm=true;render();return false">create one</a>` : ' — a Team Lead or Admin creates them'}</span>` : ''}
        </div>
        ${state.showNewTicketForm ? renderNewTicketForm() : ''}
        <div id="schedule-form-error"></div>
      </div>` : ''}
  `;
}
// Existing teams only — a typo'd team here isn't a validation error anywhere
// server-side (Schedule.team is just matched exactly against Host.team at
// fire time, see app/scheduler.py's _hosts_in_scope), so a mistyped value
// doesn't fail loudly, it just silently never matches any host. Sourced
// from the fleet, same convention as the Defs page's os_family select.
function scheduleTeamOptions(){
  return state.fleet ? [...new Set(state.fleet.map(f=>f.team).filter(Boolean))].sort() : [];
}
const DAY_NAMES = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
// Next UTC occurrence of a weekly (day_of_week 0=Mon..6=Sun, hour) slot.
function scheduleNextFire(dow, hour){
  const now = new Date();
  const jsTarget = (dow + 1) % 7;   // Mon(0)->1 … Sun(6)->0, matching getUTCDay
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hour, 0, 0));
  let add = (jsTarget - d.getUTCDay() + 7) % 7;
  if(add === 0 && d.getTime() <= now.getTime()) add = 7;
  d.setUTCDate(d.getUTCDate() + add);
  return d;
}
// "Cron as a picture": every enabled schedule firing within 24h, placed
// on a now→+24h strip. (Per-schedule change-window bands aren't modelled
// in kite, so the strip shows the fires themselves, not windows.)
function renderScheduleStrip(){
  const now = Date.now();
  const soon = (state.schedules||[]).filter(s=>s.enabled)
    .map(s => ({s, at: scheduleNextFire(s.day_of_week, s.hour)}))
    .filter(x => x.at.getTime() - now <= 24*3600*1000)
    .sort((a,b) => a.at - b.at);
  if(!soon.length) return `<div class="card" style="margin-bottom:14px"><p class="card-help" style="margin:0">Nothing scheduled to fire in the next 24 hours.</p></div>`;
  return `
    <div class="card" style="margin-bottom:14px">
      <div style="display:flex;align-items:baseline;gap:9px;margin-bottom:10px"><span style="font-weight:600;font-size:12.5px">Next 24 hours</span><span class="secondary" style="font-size:11px">${soon.length} run${soon.length===1?'':'s'} upcoming</span></div>
      <div style="position:relative;height:22px;border-radius:6px;background:var(--surface-2);border:1px solid var(--border);overflow:hidden">
        <div style="position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--urgent)"></div>
        ${soon.map(x=>{ const pct = ((x.at.getTime()-now)/(24*3600*1000)*100).toFixed(1);
          return `<div title="${pad2(x.at.getUTCHours())}:00 UTC — ${esc(x.s.name)}" style="position:absolute;left:${pct}%;top:4px;bottom:4px;width:4px;margin-left:-2px;border-radius:2px;background:var(--rail)"></div>`; }).join('')}
      </div>
      <div style="display:flex;justify-content:space-between;margin-top:5px;font:400 9.5px/1 var(--font-mono);color:var(--text-muted)"><span>now</span><span>+12 h</span><span>+24 h</span></div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:10px">
        ${soon.slice(0, 8).map(x => `<span class="badge neutral" title="${esc(x.s.name)}" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block"><span class="mono">${pad2(x.at.getUTCHours())}:00</span>&nbsp;${esc(x.s.name)}</span>`).join('')}
        ${soon.length > 8 ? `<span class="muted" style="font-size:11.5px;align-self:center">+${soon.length - 8} more below</span>` : ''}
      </div>
    </div>`;
}
async function createScheduleHandler(){
  const name = document.getElementById('new-sched-name').value.trim();
  const team = document.getElementById('new-sched-team').value.trim();
  const day_of_week = parseInt(document.getElementById('new-sched-day').value, 10);
  const hour = parseInt(document.getElementById('new-sched-hour').value, 10);
  const scope = document.getElementById('new-sched-scope').value;
  const severity_filter = scope === 'containers' ? '' : document.getElementById('new-sched-severity').value;
  const ticket_id = document.getElementById('new-sched-ticket').value.trim() || null;
  const rollout = document.getElementById('new-sched-rollout').value;
  const errEl = document.getElementById('schedule-form-error');
  errEl.innerHTML = '';
  if(!name){ errEl.innerHTML = errorBanner('Name is required.'); return; }
  try{
    // Containers are left unspecified on purpose: a schedule fires
    // against whatever hosts are in its team, and each host runs
    // different things. Every updatable container on each host is
    // resolved at fire time.
    await api.createSchedule({ name, team, day_of_week, hour, ticket_id, scope, severity_filter, rollout });
    await loadSchedules();
    toast(`${name} scheduled.`, 'success');
  }catch(e){ errEl.innerHTML = errorBanner(e.message); }
}
async function toggleSchedule(id, newEnabled){
  try{ await api.updateSchedule(id, {enabled: newEnabled}); await loadSchedules(); toast(`Schedule ${newEnabled?'enabled':'disabled'}.`, 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
async function deleteScheduleHandler(id){
  const ok = await confirmDialog({title:'Remove schedule', message:'Remove this schedule? This can\'t be undone.', confirmLabel:'Remove', danger:true});
  if(!ok) return;
  try{ await api.deleteSchedule(id); await loadSchedules(); toast('Schedule removed.', 'success'); }
  catch(e){ state.loadError = e.message; render(); toast(e.message, 'danger'); }
}
