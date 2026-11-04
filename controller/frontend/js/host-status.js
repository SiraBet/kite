/*
 * Host status vocabulary shared by Home and Fleet: badge styles, OS
 * icons, and connectivity tiering.
 *
 * connectivityTier() deliberately mirrors connectivity_tier() in
 * app/monitoring.py — same formula, same thresholds, kept in sync by
 * hand. tests/test_frontend_render.py pins the thresholds on this side
 * so the two copies cannot drift silently.
 */
/* ============================== FLEET ============================== */
// os_family is a free-form string the agent reports at enroll time (e.g.
// "rhel8", "rocky9", "ubuntu22.04", "debian12", "windows"). We only need
// to bucket it into a platform for the icon + label — exact version stays
// in the text, not the icon.
const OS_ICONS = {
  linux: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2c-1.1 0-2 1.3-2 3 0 1 .3 1.8.8 2.4-1.7.9-3.3 2.6-3.3 4.6 0 .5.1 1 .3 1.4-1 .5-1.8 1.5-1.8 2.7 0 1.7 1.5 3 3.4 3 .4 0 .8-.1 1.1-.2.5.7 1.5 1.1 2.5 1.1s2-.4 2.5-1.1c.3.1.7.2 1.1.2 1.9 0 3.4-1.3 3.4-3 0-1.2-.8-2.2-1.8-2.7.2-.4.3-.9.3-1.4 0-2-1.6-3.7-3.3-4.6.5-.6.8-1.4.8-2.4 0-1.7-.9-3-2-3zm-1.3 5.6c.4.2.8.3 1.3.3s.9-.1 1.3-.3c.2.5.3 1 .3 1.5 0 .3-.3.6-.7.6h-1.8c-.4 0-.7-.3-.7-.6 0-.5.1-1 .3-1.5z"/></svg>',
  windows: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 5.6 10.4 4.5V11.4H3zM11.3 4.4 21 3v8.4H11.3zM3 12.4H10.4V19.5L3 18.4zM11.3 12.4H21V21L11.3 19.6z"/></svg>',
  unknown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M8 9h8M8 13h5" stroke-linecap="round"/></svg>',
};
function osPlatform(family){
  const f = (family||'').toLowerCase();
  if(!f) return 'unknown';
  if(f.includes('win')) return 'windows';
  return 'linux'; // rhel/rocky/centos/alma/ubuntu/debian/sles etc. all render as the linux glyph
}
function osLabel(family){
  if(!family) return 'Unknown OS';
  const known = {
    rhel8:'RHEL 8', rhel9:'RHEL 9', rocky8:'Rocky 8', rocky9:'Rocky 9',
    centos8:'CentOS 8', centos9:'CentOS 9', alma8:'AlmaLinux 8', alma9:'AlmaLinux 9',
    ubuntu20:'Ubuntu 20.04', ubuntu22:'Ubuntu 22.04', ubuntu24:'Ubuntu 24.04',
    debian11:'Debian 11', debian12:'Debian 12',
    ubuntu:'Ubuntu', debian:'Debian', windows:'Windows',
    win2016:'Windows Server 2016', win2019:'Windows Server 2019', win2022:'Windows Server 2022',
    win2025:'Windows Server 2025', win10:'Windows 10', win11:'Windows 11',
  };
  return known[family.toLowerCase()] || family;
}
function osBadge(family){
  const plat = osPlatform(family);
  return `<span class="os-badge" title="${esc(family||'OS family not reported yet')}">${OS_ICONS[plat]}${esc(osLabel(family))}</span>`;
}
// Each host reports its own poll_interval_seconds on every poll (see
// controller's /agent/{id}/jobs/next) — offline detection is calibrated
// PER HOST from that, not a single hardcoded constant. This matters now
// that the baseline is long and admin-configurable per agent (default
// 900s / 15 min, can be hours) — a single global threshold would either
// flag every healthy host as offline, or be too loose for a host
// deliberately configured to check in often.
// Three tiers rather than a binary online/offline: a couple of missed
// cycles is ambiguous (network blip, one slow poll) and shouldn't scream
// "offline" — only sustained silence should.
const DEFAULT_POLL_INTERVAL_SECONDS = 900; // fallback for hosts that haven't reported one yet

function connectivityTier(host){
  if(!host.last_seen) return 'offline';
  const baseline = host.poll_interval_seconds || DEFAULT_POLL_INTERVAL_SECONDS;
  const staleThreshold = baseline * 2;   // one missed cycle — could be nothing
  const offlineThreshold = baseline * 4; // sustained silence — likely actually down
  // As of when this record was fetched, not now: an old copy shows what
  // was true then rather than ageing into "unreachable" (loaders.js).
  const asOf = host._fetched_at || Date.now();
  const ageSec = (asOf - parseUTC(host.last_seen).getTime()) / 1000;
  if(ageSec > offlineThreshold) return 'offline';
  if(ageSec > staleThreshold) return 'stale';
  return 'healthy';
}
function fmtLastSeen(iso){
  if(!iso) return 'never';
  // Clamp negatives: an agent whose clock runs a little ahead of the
  // controller's would otherwise report in "from the future" and render
  // as "-39807s ago" instead of a sane recent time.
  const ageSec = Math.max(0, (Date.now() - parseUTC(iso).getTime()) / 1000);
  if(ageSec < 10) return 'just now';
  if(ageSec < 60) return `${Math.floor(ageSec)}s ago`;
  if(ageSec < 3600) return `${Math.floor(ageSec/60)}m ago`;
  if(ageSec < 86400) return `${Math.floor(ageSec/3600)}h ago`;
  return `${Math.floor(ageSec/86400)}d ago`;
}
function daysSince(iso){
  if(!iso) return null;
  return Math.floor((Date.now() - parseUTC(iso).getTime()) / 86400000);
}


// Severity vocabulary, mirroring models.SEVERITY_RANK. 'unknown' is a
// real answer -- apt publishes no per-advisory severity, so a security
// update there has no level, which is NOT the same as 'low' (it renders
// amber "Security", never grey).
const SEVERITY_STYLE = {
  critical:  ['danger',  'Critical',    '&#9650;'],
  important: ['danger',  'Important',   '&#9650;'],
  moderate:  ['warning', 'Moderate',    '&#9679;'],
  low:       ['neutral', 'Low',         ''],
  unknown:   ['warning', 'Security',    '&#9679;'],
  none:      ['neutral', 'Non-security',''],
};
function severityBadge(level){
  const [tone, label, glyph] = SEVERITY_STYLE[level] || SEVERITY_STYLE.none;
  return `<span class="badge ${tone}">${glyph?`<span class="g">${glyph}</span>`:''}${label}</span>`;
}
// Compact coloured severity chip + count, for dense rows (fleet, host
// detail). Short code keeps columns narrow; colour follows severity, and
// "SEC" (unranked security) is amber like the others, never neutral.
const SEV_SHORT = {critical:'CRIT', important:'IMP', moderate:'MOD', low:'LOW', unknown:'SEC', none:'—'};
function sevChip(level, count){
  const cls = SEV_SHORT[level] ? level : 'none';
  return `<span class="sev ${cls}">${SEV_SHORT[cls]||'—'}${count!=null?`&nbsp;${count}`:''}</span>`;
}

// The machine-status vocabulary for the fleet: one badge that fuses
// reachability with patch urgency, following the design's rule — solid
// fill = we have fresh evidence, hatched + dashed = we don't. A host we
// can't reach, or whose package manager wouldn't answer, is NEVER shown
// as healthy; it gets the hatched "unknown" class.
function fleetStatusBadge(host){
  const tier = connectivityTier(host);
  if(host.status === 'locked')
    return `<span class="badge info running"><span class="g"></span>Patching</span>`;
  if(tier === 'offline')
    return `<span class="badge unknown"><span class="g">?</span>Unreachable</span>`;
  if(tier === 'stale')
    return `<span class="badge unknown"><span class="g">?</span>Not confirmed</span>`;
  if(host.updates_assessed_ok === false)
    return `<span class="badge unknown"><span class="g">?</span>Couldn't check</span>`;
  const sev = host.max_severity;
  if((sev === 'critical' || sev === 'important') && host.pending_updates)
    return `<span class="badge danger"><span class="g">&#9650;</span>Urgent</span>`;
  if(host.pending_updates)
    return `<span class="badge warning"><span class="g">&#9679;</span>Due</span>`;
  return `<span class="badge success"><span class="g">&#10003;</span>Current</span>`;
}

/* ---------- removing hosts ---------- */
// Any host can be removed except one with a run in progress (the server
// refuses that too). A host still checking in can go as well -- kite
// then turns its agent away -- but the confirmation says so, with how to
// uninstall the agent, since removing the record doesn't touch the machine.
function hostRemovable(f){ return !f.active_job_id; }
function agentUninstallHint(f){
  const fam = (f.os_family || '').toLowerCase();
  if(fam.startsWith('windows')) return 'kite-agent uninstall (elevated), or Settings → Apps';
  if(fam.startsWith('ubuntu') || fam.startsWith('debian'))
    return 'sudo systemctl disable --now kite-agent && sudo rm -rf /opt/kite-agent /etc/kite /etc/systemd/system/kite-agent.service';
  return 'sudo dnf remove kite-agent';
}
function removeHostsMessage(hosts){
  const live = hosts.filter(f => connectivityTier(f) !== 'offline');
  const lines = [`Remove ${hosts.length === 1 ? hosts[0].hostname : `${hosts.length} hosts`} from the fleet? This can't be undone. The machines themselves aren't touched — only kite's record of them, their inventory and network details. Past runs stay in the history.`];
  if(live.length){
    lines.push(`Still checking in: ${live.map(f => `${f.hostname} (last heard ${fmtLastSeen(f.last_seen)})`).join(', ')}. Their agent keeps running and is turned away from now on. To stop it, uninstall it on the machine:`);
    live.forEach(f => lines.push(`  ${f.hostname}: ${agentUninstallHint(f)}`));
    lines.push('To bring one back later, enrol it again from Add machine.');
  }
  return lines.join('\n\n');
}
