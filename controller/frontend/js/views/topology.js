/*
 * Topology: controller → Proxmox cluster → node → guest, from GET /topology.
 * A node's column is its blast radius — rebooting it takes every guest
 * under it down at once — so each node card carries the counts that
 * matter before patching it: guests, active runs, hosts with no snapshot
 * safety net, critical updates pending.
 *
 * Laid out on a fixed grid and drawn as absolutely-positioned boxes over
 * one SVG of orthogonal edges, inside a pan/zoom canvas. Panning and
 * zooming move the canvas's transform directly instead of re-rendering,
 * so they stay smooth on a large fleet; everything else is an ordinary
 * render() from state.topo.
 *
 * Any card can be dragged, taking everything under it along, and the
 * edges follow. Moves are kept per browser (localStorage) as offsets from
 * the grid, so a refresh that adds a VM still lays the rest out the same.
 */
/* ============================== TOPOLOGY ============================== */
// Rows: root, cluster, node cards (NY), bridge cards (BY), then guest tiles (GY).
// A bridge routed by a gateway sits one level (LV) lower, its gateway card
// in the gap (GW below its parent bridge, GH tall) -- see topoLayout.
const TOPO = {CW: 420, CG: 40, TW: 188, TH: 50, ROW: 60, NY: 208, NH: 140, BY: 404, BH: 112, GY: 560, NODE_W: 320,
  GW: 26, GH: 96, LV: 260, CY: 104, RH: 56};
const TOPO_SEV = {
  critical:  {bar:'#B3261E', bg:'#FDF1EF'},
  important: {bar:'#D2691E', bg:'#FFF6EE'},
  moderate:  {bar:'#8A5200', bg:'#FFFBF2'},
  low:       {bar:'#3B443E', bg:'#FFFFFF'},
  unknown:   {bar:'#8A5200', bg:'#FFFBF2'},
  none:      {bar:'#1E7A4B', bg:'#FFFFFF'},
};
const TOPO_CONN = {healthy:{bar:'#1E7A4B', bg:'#FFFFFF'}, stale:{bar:'#8A5200', bg:'#FFFBF2'}, offline:{bar:'#6E7A84', bg:'#FFFFFF'}};
const TOPO_SAFE = {
  snapshot:        {t:'SNAP', cls:'snap', bar:'#1E7A4B', bg:'#FFFFFF', long:'Snapshot before every patch — full rollback possible'},
  package_history: {t:'PKG',  cls:'pkg',  bar:'#8A5200', bg:'#FFFBF2', long:'Package history only — can downgrade packages, not restore the disk'},
  none:            {t:'NONE', cls:'none', bar:'#B3261E', bg:'#FDF1EF', long:'No safety net — no rollback path if a patch goes wrong'},
};
const UNPLACED_WHY = {
  stale_link: h => `stale link · vmid ${h.proxmox_vmid}`,
  not_linked: () => 'not linked to a VM id',
  proxmox_unavailable: () => 'Proxmox unavailable',
};

function topoNeedsAction(g){
  const h = g.host;
  if(g.coverage==='managed' && h)
    return h.max_severity==='critical' || h.max_severity==='important' || h.connectivity!=='healthy'
      || h.updates_assessed_ok===false || h.safety_net==='none'
      || !!(h.containers && h.containers.update_available);
  return (g.coverage==='unmanaged' && g.status==='running') || g.coverage==='name_match';
}
function topoMatches(g){
  const t = state.topo, q = t.q.trim().toLowerCase();
  const text = `${g.name||''} ${g.host ? g.host.hostname : ''} ${g.vmid ?? ''}`.toLowerCase();
  if(q && !text.includes(q)) return false;
  if(t.filter==='action') return topoNeedsAction(g);
  if(t.filter==='gaps') return g.coverage==='unmanaged' || g.coverage==='name_match';
  return true;
}
// Stable selection keys, so a selection survives a data refresh.
// Nodes are told apart by connection + name: a standalone host and a
// cluster member can both be called "pve". Clusters are one per connection.
function topoNodeKey(n){ return n.key || n.name; }
function topoClusterKey(cid){ return `cluster:${cid == null ? 0 : cid}`; }
function topoClusters(d){
  return d.clusters && d.clusters.length ? d.clusters
    : [{connection_id: null, name: 'Proxmox cluster', host: (d.proxmox || {}).host || '', error: '', stale: false}];
}
function topoKey(g){ return g.host ? `host:${g.host.id}` : g.hostId ? `host:${g.hostId}` : `vm:${g.vmid}`; }

// Columns side by side, each column's items in two staggered rows below
// its card. cols: [{key, list, pinnedCol?}]. Shared by both groupings.
// Columns side by side, each column's items in two staggered rows below
// its card. cols: [{key, list, depth?, pinnedCol?}]. Grid positions only;
// topoPosition applies the person's moves on top.
function topoPlace(cols){
  const W = cols.length * TOPO.CW + (cols.length - 1) * TOPO.CG;
  const cx = i => i * (TOPO.CW + TOPO.CG) + TOPO.CW / 2;
  const items = [];
  cols.forEach((c, i) => {
    const x = cx(i), top = TOPO.GY + (c.depth || 0) * TOPO.LV;
    c.list.forEach((g, j) => {
      const side = j % 2, y = top + Math.floor(j / 2) * TOPO.ROW;
      items.push({g, col: c.key, net: !!c.net, pinned: !!(c.pinnedCol && g.host && g.host.placement === 'pinned'),
        x: side ? x + 22 : x - 22 - TOPO.TW, y});
    });
  });
  // One VM at a time drops its containers out beneath it as a chain:
  // VM -> runtime -> each container. Rows below it in the same column move
  // down to make room; a VM under several bridges expands under its first tile.
  let sub = null;
  const exp = state.topo.expanded;
  const target = exp == null ? null : items.find(it => it.g.host && it.g.host.id === exp
    && it.g.host.containers && it.g.host.containers.total);
  if(target){
    const list = state.topoContainers[exp];
    const all = Array.isArray(list) ? topoCtOrder(list) : [];
    const rt = {key: `rt:${exp}`, x: target.x, y: target.y + TOPO.TH + CT.GAP};
    const cts = all.slice(0, CT.MAX).map((c, j) => ({c, key: `ct:${exp}:${c.id}`, x: target.x + CT.IND,
      y: rt.y + TOPO.TH + CT.GAP + j * CT.ROW}));
    const more = all.length > CT.MAX ? all.length - CT.MAX : 0;
    const gap = CT.GAP + TOPO.TH + (cts.length ? CT.GAP + cts.length * CT.ROW : 0) + (more ? CT.MORE : 0) + CT.GAP;
    items.forEach(it => { if(it.col === target.col && it.y > target.y) it.y += gap; });
    sub = {target, host: target.g.host, list, rt, cts, more};
  }
  return {W, cx, cols, items, rootX: W / 2, sub};
}
// The tree: each node fans out into one column per bridge its guests are
// plugged into, and guests hang off their bridge -- a VM with NICs on
// several bridges appears under each. Collapsing a node folds all of its
// bridges; collapsing a bridge folds just that one.
//
// A gateway (router/firewall) is drawn once instead: its card hangs under
// its uplink bridge (or the node, with none), centred over the bridges it
// routes, which sit one level lower -- node -> uplink -> gateway -> zones.
function topoLayout(data){
  const t = state.topo;
  const cols = [];
  data.nodes.forEach(n => {
    const pinnedCol = n.status !== 'online';
    if(t.collapsed[topoNodeKey(n)]){
      cols.push({key: `node-folded:${topoNodeKey(n)}`, node: n, list: []});
    } else {
      (n.networks || []).forEach(net => cols.push({key: `net:${net.key}`, node: n, net, pinnedCol, depth: net.depth || 0,
        list: t.collapsed[`net:${net.key}`] ? [] : net.members}));
      if(t.showTemplates && (n.template_list || []).length)
        cols.push({key: `tmpl:${topoNodeKey(n)}`, node: n, templates: true,
          list: n.template_list.map(tp => ({...tp, status: 'stopped', coverage: 'template', host: null}))});
      if(!cols.some(c => c.node === n)) cols.push({key: `node-folded:${topoNodeKey(n)}`, node: n, list: []});
    }
  });
  cols.push({key: 'unplaced', node: null, list: data.unplaced.map(h => ({vmid: h.proxmox_vmid, name: h.hostname,
    type: null, status: 'unknown', coverage: 'managed', host: h, unplaced: true}))});
  const P = topoPlace(cols);
  const nodeX = {};
  data.nodes.forEach(n => {
    const xs = P.cols.map((c, i) => c.node === n ? P.cx(i) : null).filter(x => x !== null);
    nodeX[topoNodeKey(n)] = xs.reduce((a, b) => a + b, 0) / xs.length;
  });
  // Each cluster box sits centred over its own nodes.
  const clusterX = {};
  topoClusters(data).forEach(c => {
    const xs = data.nodes.filter(n => (n.connection_id ?? null) === (c.connection_id ?? null)).map(n => nodeX[topoNodeKey(n)]);
    if(xs.length) clusterX[topoClusterKey(c.connection_id)] = (Math.min(...xs) + Math.max(...xs)) / 2;
  });
  // Gateways: centred over the bridges they route, one level-gap below their parent.
  const gateways = [], colGw = {};
  data.nodes.forEach(n => {
    if(t.collapsed[topoNodeKey(n)]) return;
    (n.gateways || []).forEach(gw => {
      const xs = gw.routed.map(k => P.cols.findIndex(c => c.key === `net:${k}`)).filter(i => i >= 0).map(P.cx);
      if(!xs.length) return;
      const G = {gw, node: n, key: `gw:${gw.key}`, parentCol: gw.parent ? `net:${gw.parent}` : null,
        x: (Math.min(...xs) + Math.max(...xs)) / 2, y: TOPO.BY + (gw.depth || 0) * TOPO.LV + TOPO.BH + TOPO.GW};
      gateways.push(G);
      gw.routed.forEach(k => { colGw[`net:${k}`] = G; });
    });
  });
  return topoPosition({...P, nodeX, clusterX, gateways, colGw}, data);
}
// The person's moves, {card key: [dx, dy]}, kept in this browser only.
const TOPO_MOVED_KEY = 'kite.topology.moved';
function topoMoved(){
  if(!state.topo.moved){
    let saved = {};
    try{ saved = JSON.parse(localStorage.getItem(TOPO_MOVED_KEY) || '{}') || {}; }catch(e){ saved = {}; }
    state.topo.moved = saved;
  }
  return state.topo.moved;
}
function topoSaveMoved(){
  try{ localStorage.setItem(TOPO_MOVED_KEY, JSON.stringify(topoMoved())); }catch(e){ /* private window: this session only */ }
}
function topoResetLayout(){
  state.topo.moved = {};
  topoSaveMoved();
  state.topo.fitted = false;
  render();
}
// Final positions: the grid plus each card's own move plus every move
// above it, so dragging a card takes its subtree along. Also the extent
// of the drawing, which can reach left of or above the origin.
function topoPosition(L, data){
  const mv = topoMoved(), own = k => mv[k] || [0, 0];
  const add = (a, b) => [a[0] + b[0], a[1] + b[1]];
  const rootO = own('root');
  L.root = {x: L.rootX + rootO[0], y: rootO[1]};
  const clO = {}, nO = {}, colO = {}, gwO = {};
  L.clusterPos = {};
  Object.keys(L.clusterX).forEach(ck => {
    clO[ck] = add(rootO, own(ck));
    L.clusterPos[ck] = {x: L.clusterX[ck] + clO[ck][0], y: TOPO.CY + clO[ck][1]};
  });
  L.nodePos = {};
  data.nodes.forEach(n => {
    const nk = topoNodeKey(n);
    nO[nk] = add(clO[topoClusterKey(n.connection_id)] || rootO, own(`node:${nk}`));
    L.nodePos[nk] = {x: L.nodeX[nk] + nO[nk][0], y: TOPO.NY + nO[nk][1]};
  });
  const byKey = {};
  L.cols.forEach((c, i) => { byKey[c.key] = c; c.i = i; });
  L.byKey = byKey;
  const gOff = G => gwO[G.key] || (gwO[G.key] = add(
    G.parentCol && byKey[G.parentCol] ? cOff(byKey[G.parentCol]) : nO[topoNodeKey(G.node)], own(G.key)));
  const cOff = c => colO[c.key] || (colO[c.key] = add(
    !c.node ? rootO : L.colGw[c.key] ? gOff(L.colGw[c.key]) : nO[topoNodeKey(c.node)], own(c.key)));
  L.cols.forEach(c => {
    const o = cOff(c), unplaced = c.key === 'unplaced';
    c.x = L.cx(c.i) + o[0];
    c.y = (unplaced ? TOPO.NY : topoBridgeY(c)) + o[1];
    c.spine = c.y + (unplaced ? TOPO.NH : TOPO.BH);
  });
  L.gateways.forEach(G => { const o = gOff(G); G.x += o[0]; G.y += o[1]; });
  L.items.forEach(it => {
    it.key = `t:${it.col}|${topoKey(it.g)}`;
    it.off = add(cOff(byKey[it.col]), own(it.key));
    it.x += it.off[0]; it.y += it.off[1];
    it.bx = byKey[it.col].x;
  });
  if(L.sub){
    const S = L.sub, rtO = add(S.target.off, own(S.rt.key));
    S.rt.x += rtO[0]; S.rt.y += rtO[1];
    S.cts.forEach(ct => { const o = add(rtO, own(ct.key)); ct.x += o[0]; ct.y += o[1]; });
  }
  // Extent: every card's box.
  const boxes = [[L.root.x - 100, L.root.y, 200, TOPO.RH]];
  Object.values(L.clusterPos).forEach(p => boxes.push([p.x - 135, p.y, 270, TOPO.RH]));
  Object.values(L.nodePos).forEach(p => boxes.push([p.x - TOPO.NODE_W / 2, p.y, TOPO.NODE_W, TOPO.NH]));
  L.cols.forEach(c => { if(c.net || c.templates || c.key === 'unplaced') boxes.push([c.x - TOPO.NODE_W / 2, c.y, TOPO.NODE_W, c.spine - c.y]); });
  L.gateways.forEach(G => boxes.push([G.x - TOPO.NODE_W / 2, G.y, TOPO.NODE_W, TOPO.GH]));
  L.items.forEach(it => boxes.push([it.x, it.y, TOPO.TW, TOPO.TH]));
  if(L.sub){
    boxes.push([L.sub.rt.x, L.sub.rt.y, TOPO.TW, TOPO.TH]);
    L.sub.cts.forEach(ct => boxes.push([ct.x, ct.y, CT.W, CT.H + (L.sub.more ? CT.MORE : 0)]));
  }
  L.x0 = Math.min(0, ...boxes.map(b => b[0] - 20));
  L.y0 = Math.min(0, ...boxes.map(b => b[1] - 20));
  L.W = Math.max(...boxes.map(b => b[0] + b[2])) + 20;
  L.H = Math.max(...boxes.map(b => b[1] + b[3])) + 20;
  return L;
}
function topoBridgeY(c){ return TOPO.BY + ((c && c.depth) || 0) * TOPO.LV; }
// The edges above a gateway card, up to the controller.
function topoGwPath(L, G){
  const up = G.parentCol ? topoColPath(L, G.parentCol)
    : [`e:node:${topoNodeKey(G.node)}`, `e:${topoClusterKey(G.node.connection_id)}`];
  return [`e:${G.key}`].concat(up);
}
// The edges above a column, so selecting anything in it lights its path home.
function topoColPath(L, colKey){
  if(colKey === 'unplaced') return ['e:unplaced'];
  const c = L.cols.find(c => c.key === colKey);
  if(c && L.colGw && L.colGw[colKey]) return [`e:${colKey}`].concat(topoGwPath(L, L.colGw[colKey]));
  return c && c.node ? [`e:${colKey}`, `e:node:${topoNodeKey(c.node)}`, `e:${topoClusterKey(c.node.connection_id)}`] : [];
}

function topoTile(it){
  const g = it.g, t = state.topo, h = g.host;
  const key = topoKey(g), sel = t.sel === key, dim = !topoMatches(g);
  const cls = ['topo-tile'];
  let style = '', name = esc(g.name || '—'), sub = '', right = '';
  if(g.coverage==='managed' && h){
    let palette;
    if(t.colorBy==='connectivity') palette = TOPO_CONN[h.connectivity] || TOPO_CONN.offline;
    else if(t.colorBy==='safety') palette = TOPO_SAFE[h.safety_net] || TOPO_SAFE.none;
    else palette = TOPO_SEV[h.max_severity] || TOPO_SEV.none;
    const unknown = h.connectivity !== 'healthy' || h.updates_assessed_ok === false;
    if(unknown && t.colorBy !== 'safety') cls.push('unknown');
    style = `border-left-color:${palette.bar};${unknown && t.colorBy!=='safety' ? '' : `background:${palette.bg}`}`;
    name = `${h.active_job_id ? '<span class="topo-spin"></span>' : `<span class="topo-dot ${h.connectivity}"></span>`}${esc(h.hostname.split('.')[0])}`;
    // Under a bridge the address is the point; the spinner already says "patching".
    sub = it.net ? topoNetSub(g)
      : h.active_job_id ? `run ${h.active_job_id} &middot; patching`
      : it.g.unplaced ? esc((UNPLACED_WHY[h.unplaced_reason] || (() => ''))(h))
      : `${g.vmid ?? '—'} &middot; ${guestTypeLabel(g.type)}`;
    const safe = TOPO_SAFE[h.safety_net] || TOPO_SAFE.none;
    right = `${h.updates_assessed_ok===false ? '<span class="sev none">?</span>' : h.pending_updates ? sevChip(h.max_severity, null) : '<span class="topo-ok">&#10003;</span>'}
      <span class="topo-safe ${safe.cls}">${safe.t}</span>${h.containers && h.containers.total ? `<span class="topo-ct">&#9632;${h.containers.total}</span>` : ''}${g.multi_homed ? '<span class="topo-ct" title="On more than one network">&#8644;</span>' : ''}`;
  } else if(g.coverage==='name_match'){
    cls.push('match');
    name = `&#8776; ${name}`;
    sub = `Suggested: ${esc(g.suggested_host ? g.suggested_host.hostname : '')}`;
  } else if(g.coverage==='ignored'){
    cls.push('ignored');
    name = `&minus; ${name}`;
    sub = `${g.vmid} &middot; ${guestTypeLabel(g.type)} &middot; ignored`;
  } else if(g.coverage==='gateway'){
    cls.push('gateway');
    name = `&#8679; ${name}`;
    sub = `${g.vmid} &middot; gateway &middot; patched outside kite`;
  } else if(g.coverage==='template'){
    cls.push('template');
    sub = `${g.vmid} &middot; template`;
  } else {
    cls.push('unmanaged');
    name = `&#9675; ${name}`;
    sub = `${it.net && g.ips && g.ips.length ? esc(topoBareIp(g.ips[0])) : g.vmid} &middot; ${guestTypeLabel(g.type)} &middot; ${g.status==='running' ? 'not managed' : esc(g.status)}`;
  }
  if(sel) cls.push('sel');
  if(dim) cls.push('dim');
  if(h && state.topo.expanded === h.id) cls.push('expanded');
  // Unenrolled VMs on several bridges (a firewall with a NIC per zone) get the marker too.
  if(!right && g.multi_homed) right = '<span class="topo-ct" title="On more than one network">&#8644;</span>';
  if(g.gateway_suggestion && !g.gateway_dismissed)
    right = `<span class="topo-gw-hint" title="Looks like a gateway: ${esc(g.gateway_suggestion)}">GW?</span>${right}`;
  return `<div class="${cls.join(' ')}" data-drag="${esc(it.key)}" style="left:${it.x}px;top:${it.y}px;${style}" onclick="topoSelect('${jsq(key)}')" title="${esc(g.name||'')}">
    <div class="topo-tile-name">${name}</div>
    <div class="topo-tile-sub">${sub}</div>
    ${right ? `<div class="topo-tile-right">${right}</div>` : ''}
  </div>`;
}

function topoNodeCard(n, p){
  const t = state.topo, b = n.blast_radius, key = `node:${topoNodeKey(n)}`;
  const online = n.status === 'online';
  const chip = (txt, tone) => `<span class="topo-chip ${tone||''}">${txt}</span>`;
  const chips = [
    chip(`${b.guests} guests`),
    online ? chip(`${b.running} running`) : chip('? running', 'unk'),
    chip(`${b.managed} managed`),
    b.unmanaged ? chip(`&#9675; ${b.unmanaged} unmanaged`, 'gap') : chip('0 unmanaged'),
    b.active_runs ? chip(`${b.active_runs} active run${b.active_runs>1?'s':''}`, 'run') : chip('0 runs'),
    b.no_snapshot ? chip(`${b.no_snapshot} no snapshot`, 'warn') : chip('0 no snapshot'),
    b.critical_pending ? chip(`&#9650; ${b.critical_pending} critical`, 'crit') : chip('0 critical'),
  ].join('');
  const collapsed = !!t.collapsed[topoNodeKey(n)];
  const foot = online
    ? `${n.templates} template${n.templates===1?'':'s'} ${t.showTemplates?'shown':'hidden'}${collapsed ? ` &middot; ${b.guests} guests collapsed` : ''}`
    : `<strong>&#8982; Position from pinned node — Proxmox unreachable</strong>`;
  return `<div class="topo-node ${online?'':'unknown'} ${t.sel===key?'sel':''}" data-drag="${esc(key)}" style="left:${p.x - TOPO.NODE_W/2}px;top:${p.y}px" onclick="topoSelect('${jsq(key)}')">
    <div class="topo-node-head">
      <span class="topo-node-icon"></span>
      <span class="mono topo-node-name">${esc(n.name)}</span>
      <span class="topo-status ${online?'ok':'unk'}">${online ? '&#10003; Online' : n.status==='offline' ? '? Offline' : '? Unreachable'}</span>
      <span class="grow"></span>
      <button class="topo-mini" onclick="event.stopPropagation();topoToggleNode('${jsq(topoNodeKey(n))}')">${collapsed ? `Expand ${b.guests}` : 'Collapse'}</button>
    </div>
    <div class="topo-chips">${chips}</div>
    <div class="topo-node-foot">${foot}</div>
  </div>`;
}

function renderTopology(){
  const d = state.topology, t = state.topo;
  const bar = proxmoxStatusBar(d && d.proxmox, state.topologyLoading, 'loadTopology(true)');
  const header = `
    <div class="topo-top">
      <h1 class="view-title" style="margin:0">Topology</h1>
      <div class="topo-pm">${bar.includes('pm-empty') ? '' : bar}</div>
      <div class="grow"></div>
      <label class="fleet-search" style="width:230px"><span style="width:11px;height:11px;border:1.5px solid var(--text-faint);border-radius:50%;flex:none"></span>
        <input id="topo-search" placeholder="Find machine or VM" value="${esc(t.q)}" oninput="liveTopoSearch(this)"></label>
      <div class="seg">${[['all','All'],['action','Needs action'],['gaps','Coverage gaps']].map(([id,l]) =>
        `<button class="${t.filter===id?'on':''}" onclick="state.topo.filter='${id}';render()">${l}</button>`).join('')}</div>
    </div>
    <div class="topo-top" style="margin-top:8px">
      <span class="topo-lbl">Colour by</span>
      <div class="seg">${[['severity','Severity'],['connectivity','Connectivity'],['safety','Safety net']].map(([id,l]) =>
        `<button class="${t.colorBy===id?'on':''}" onclick="state.topo.colorBy='${id}';render()">${l}</button>`).join('')}</div>
      <label class="tok-toggle" style="border:none;padding:0"><input type="checkbox" ${t.showTemplates?'checked':''} onchange="state.topo.showTemplates=this.checked;render()"> Templates</label>
    </div>`;
  if(!d){
    return `${header}${state.loadError ? errorBanner(state.loadError) : ''}<div class="loading-rows"><div class="skeleton" style="height:420px"></div></div>`;
  }
  const L = topoLayout(d);
  const vlanUnknown = d.nodes.some(n => (n.networks || []).some(x => /VLAN unknown$/.test(x.label)));
  const movedAny = Object.keys(topoMoved()).length > 0;
  return `
    ${header}
    ${state.loadError ? errorBanner(state.loadError) : ''}
    ${bar.includes('pm-empty') ? `<div style="margin-top:12px">${bar}</div>` : ''}
    ${vlanUnknown ? `<div class="banner warning" style="margin-top:12px"><strong>VLAN IDs unknown.</strong> kite couldn't see the Proxmox node's bridges, so each one is shown without its VLAN. The API token needs <span class="mono">Sys.Audit</span> and <span class="mono">SDN.Audit</span> (since Proxmox 8, bridges are hidden without it) — Settings &rarr; Connections &rarr; <em>Test connection</em> shows what's missing.</div>` : ''}
    <div class="topo ${t.full ? 'full' : ''}">
      <div id="topo-vp" class="topo-vp" onwheel="topoWheel(event)" onmousedown="topoDown(event)">
        <div id="topo-canvas" class="topo-canvas" data-w="${L.W}" data-h="${L.H}" data-x0="${L.x0}" data-y0="${L.y0}" style="width:${L.W}px;height:${L.H}px;transform:translate(${t.tx}px,${t.ty}px) scale(${t.k})">${topoCanvas(d, L)}</div>
        <div class="topo-hint">drag the background to pan &middot; drag a card to move it and everything under it &middot; scroll or +/&minus; to zoom &middot; esc to clear</div>
        <div class="topo-zoom" onmousedown="event.stopPropagation()">
          <button onclick="topoZoomCenter(1/1.2)">&minus;</button><span id="topo-pct" class="mono">${Math.round(t.k*100)}%</span><button onclick="topoZoomCenter(1.2)">+</button><button onclick="topoFit()">Fit</button>${movedAny ? '<button onclick="topoResetLayout()" title="Put every card back where kite lays it out">Reset layout</button>' : ''}
        </div>
        <button class="topo-full-btn" onmousedown="event.stopPropagation()" onclick="topoToggleFull()" title="${t.full ? 'Exit full screen (esc)' : 'Use the whole screen'}">${t.full ? '&times; Exit full screen' : 'Full screen'}</button>
      </div>
      <aside class="topo-side">${topoSidePanel(d, L)}${topoLegend()}</aside>
    </div>
    ${state.coverageIgnoring ? renderIgnoreDialog() : ''}`;
}
// Everything inside the pan/zoom canvas: edges, then cards. Redrawn on
// its own while a card is dragged, so the rest of the page stays put.
function topoCanvas(d, L){
  const t = state.topo;
  const hl = topoHighlights(L);
  const runEdges = new Set();
  const edges = [], R = topoRect;
  // parent -> child: a line between the facing sides of the two cards, with a dot where it leaves the parent
  const link = (id, a, b, extra) => { const k = topoLink(a, b); edges.push({id, d: k.d, dot: k.from, ...extra}); };
  const clusters = topoClusters(d);
  const rootR = R.root(L.root);
  clusters.forEach(c => { const p = L.clusterPos[topoClusterKey(c.connection_id)];
    if(p) link(`e:${topoClusterKey(c.connection_id)}`, rootR, R.cluster(p), {nodot: true}); });
  const un = L.byKey.unplaced;
  link('e:unplaced', rootR, R.card(un, TOPO.NH), {dash: '2 4', muted: true, nodot: true});
  d.nodes.forEach(n => {
    const p = L.nodePos[topoNodeKey(n)], cp = L.clusterPos[topoClusterKey(n.connection_id)];
    if(p && cp) link(`e:node:${topoNodeKey(n)}`, R.cluster(cp), R.card(p, TOPO.NH),
      {dash: n.status === 'online' ? null : '6 5', muted: n.status !== 'online', nodot: true});
  });
  L.gateways.forEach(G => {
    const pc = G.parentCol ? L.byKey[G.parentCol] : null;
    link(`e:${G.key}`, pc ? R.card(pc, TOPO.BH) : R.card(L.nodePos[topoNodeKey(G.node)], TOPO.NH), R.card(G, TOPO.GH));
  });
  L.cols.forEach(c => {
    const G = L.colGw[c.key];
    if(G) link(`e:${c.key}`, R.card(G, TOPO.GH), R.card(c, TOPO.BH), {gw: true});
    else if(c.net || c.templates)
      link(`e:${c.key}`, R.card(L.nodePos[topoNodeKey(c.node)], TOPO.NH), R.card(c, TOPO.BH),
        {dash: c.templates || (c.net && c.net.kind === 'unknown') ? '2 4' : null, muted: !!c.templates});
  });
  // Tiles share their bridge's spine while they sit where the grid put
  // them; one moved on its own gets its own line to the nearest sides.
  const moved = topoMoved();
  L.items.forEach(it => {
    const g = it.g, col = L.byKey[it.col];
    let dash = it.pinned ? '6 5' : null;
    if(g.coverage==='unmanaged' || g.coverage==='name_match') dash = '4 4';
    if(g.coverage==='ignored' || g.coverage==='template') dash = '2 4';
    const id = `e:${it.col}:${topoKey(g)}`;
    const own = moved[it.key], parent = R.card(col, col.spine - col.y);
    const k = own ? topoLink(parent, R.tile(it)) : {d: topoSpine(it.bx, col.spine, it.x, it.y, TOPO.TW, TOPO.TH), from: [col.x, col.spine]};
    edges.push({id, d: k.d, dot: k.from, dash, muted: g.coverage !== 'managed' || it.pinned || it.col === 'unplaced', dim: !topoMatches(g)});
    if(g.host && g.host.active_job_id){ runEdges.add(id); topoColPath(L, it.col).forEach(e => runEdges.add(e)); }
  });
  const S = L.sub;
  if(S){
    const rtR = R.tile(S.rt);
    link(`e:${S.rt.key}`, R.tile(S.target), rtR);
    S.cts.forEach(ct => {
      const k = moved[ct.key] ? topoLink(rtR, R.ct(ct))
        : {d: topoSpine(S.rt.x + CT.IND / 2, S.rt.y + TOPO.TH, ct.x, ct.y, CT.W, CT.H), from: null};
      edges.push({id: `e:${ct.key}`, d: k.d, dot: k.from, muted: ct.c.state !== 'running'});
    });
  }
  const order = e => hl.has(e.id) ? 2 : (e.muted ? 0 : 1);
  const paths = edges.slice().sort((a, b) => order(a) - order(b)).map(e =>
    `<path d="${e.d}" fill="none" stroke="${hl.has(e.id) ? '#1E6852' : e.muted ? '#B3BAB3' : '#7E8A84'}" stroke-width="${hl.has(e.id) ? 2.5 : 1.5}"${e.dash ? ` stroke-dasharray="${e.dash}"` : ''}${e.dim && !hl.has(e.id) ? ' opacity=".3"' : ''}/>`).join('')
    + edges.filter(e => runEdges.has(e.id)).map(e => `<path class="topo-flow" d="${e.d}" fill="none" stroke="#2D64B8" stroke-width="2.5" stroke-dasharray="6 8"/>`).join('')
    + topoDots(edges);

  const unplacedSel = t.sel === 'unplaced';
  return `
    <svg width="${L.W}" height="${L.H}" class="topo-svg">${paths}</svg>
    <div class="topo-root ${t.sel==='root'?'sel':''}" data-drag="root" style="left:${L.root.x - 100}px;top:${L.root.y}px" onclick="topoSelect('root')">
      <span class="topo-root-mark"></span><div><div class="topo-root-name">kite controller</div><div class="topo-root-sub">${esc(location.host)}</div></div>
    </div>
    ${clusters.map(c => {
      const ck = topoClusterKey(c.connection_id), p = L.clusterPos[ck];
      if(!p) return '';
      const count = d.nodes.filter(n => (n.connection_id ?? null) === (c.connection_id ?? null)).length;
      return `<div class="topo-cluster ${t.sel===ck?'sel':''} ${c.error ? 'err' : ''}" data-drag="${esc(ck)}" style="left:${p.x - 135}px;top:${p.y}px" onclick="topoSelect('${jsq(ck)}')">
        <span class="topo-node-icon"></span><div style="min-width:0"><div style="font-weight:600;font-size:11.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(c.name)}</div><div class="mono muted" style="font-size:10px">${esc(c.host || '—')} &middot; ${count} node${count===1?'':'s'}${c.error ? ' &middot; <span style="color:var(--urgent)">&#9650; error</span>' : ''}</div></div>
      </div>`;
    }).join('')}
    ${d.nodes.map(n => topoNodeCard(n, L.nodePos[topoNodeKey(n)])).join('')}
    ${L.cols.map(c => c.net ? topoBridgeCard(c.net, c.x, c.y) : c.templates ? topoTemplatesCard(c) : '').join('')}
    ${L.gateways.map(topoGatewayCard).join('')}
    <div class="topo-node unplaced ${unplacedSel?'sel':''}" data-drag="unplaced" style="left:${un.x - TOPO.NODE_W/2}px;top:${un.y}px" onclick="topoSelect('unplaced')">
      <div class="topo-node-head"><span class="topo-node-name" style="font-family:var(--font-ui)">Unplaced</span><span class="topo-chip">${d.unplaced.length} host${d.unplaced.length===1?'':'s'}</span></div>
      <div class="topo-node-foot" style="margin-top:6px">Managed by kite but not on Proxmox, or not linked to a VM id — topology can't say where they run.</div>
      <a href="#" style="font-size:11px;font-weight:600;margin-top:6px;display:inline-block" onclick="event.stopPropagation();setFleetSection('coverage');navigate('fleet');return false">Review in Coverage &rarr;</a>
    </div>
    ${L.items.map(topoTile).join('')}
    ${topoContainerChain(L)}`;
}
// Card boxes {x, y, w, h} (top-left), from the centre-top positions the layout keeps.
const topoRect = {
  root: p => ({x: p.x - 100, y: p.y, w: 200, h: TOPO.RH}),
  cluster: p => ({x: p.x - 135, y: p.y, w: 270, h: TOPO.RH}),
  card: (p, h) => ({x: p.x - TOPO.NODE_W / 2, y: p.y, w: TOPO.NODE_W, h}),
  tile: p => ({x: p.x, y: p.y, w: TOPO.TW, h: TOPO.TH}),
  ct: p => ({x: p.x, y: p.y, w: CT.W, h: CT.H}),
};
// A line from box a to box b between the middles of their facing sides:
// bottom to top when b is below a, top to bottom when above, side to side
// when they sit next to each other -- so a moved card never has a line
// ending underneath it. Orthogonal, bending halfway. `from` is where it
// leaves a.
const TOPO_LINK_GAP = 12;
function topoLink(a, b){
  const acx = a.x + a.w / 2, acy = a.y + a.h / 2, bcx = b.x + b.w / 2, bcy = b.y + b.h / 2;
  const vert = (x1, y1, x2, y2) => { const m = (y1 + y2) / 2; return {d: `M${x1} ${y1}V${m}H${x2}V${y2}`, from: [x1, y1]}; };
  const horz = (x1, y1, x2, y2) => { const m = (x1 + x2) / 2; return {d: `M${x1} ${y1}H${m}V${y2}H${x2}`, from: [x1, y1]}; };
  if(b.y >= a.y + a.h + TOPO_LINK_GAP) return vert(acx, a.y + a.h, bcx, b.y);       // below
  if(b.y + b.h + TOPO_LINK_GAP <= a.y) return vert(acx, a.y, bcx, b.y + b.h);       // above
  if(b.x >= a.x + a.w) return horz(a.x + a.w, acy, b.x, bcy);                        // to the right
  if(b.x + b.w <= a.x) return horz(a.x, acy, b.x + b.w, bcy);                        // to the left
  return vert(acx, bcy > acy ? a.y + a.h : a.y, bcx, bcy > acy ? b.y : b.y + b.h);   // overlapping: nearest ends
}
// One dot per point a line leaves a card from (several share a spine).
function topoDots(edges){
  const seen = new Set();
  return edges.filter(e => e.dot && !e.nodot).map(e => {
    const k = `${e.dot[0]},${e.dot[1]}`;
    if(seen.has(k)) return '';
    seen.add(k);
    return `<circle cx="${e.dot[0]}" cy="${e.dot[1]}" r="3.5" fill="#fff" stroke="${e.gw ? '#1E6852' : '#7E8A84'}" stroke-width="1.5"/>`;
  }).join('');
}
// A tile hangs off a vertical spine at bx: across to its nearer side, or
// straight into its top when the spine runs through it.
function topoSpine(bx, top, x, y, w, h){
  if(bx <= x) return `M${bx} ${top}V${y + h / 2}H${x}`;
  if(bx >= x + w) return `M${bx} ${top}V${y + h / 2}H${x + w}`;
  return `M${bx} ${top}V${y < top ? y + h : y}`;
}
function topoHighlights(L){
  const sel = state.topo.sel, hl = new Set();
  if(!sel) return hl;
  const lightItem = (it, key) => { hl.add(`e:${it.col}:${key}`); topoColPath(L, it.col).forEach(e => hl.add(e)); };
  const S = L.sub;
  if(S && (sel === `host:${S.host.id}` || sel === S.rt.key || sel.startsWith(`ct:${S.host.id}:`))){
    hl.add(`e:${S.rt.key}`);
    const vm = `host:${S.host.id}`;
    L.items.filter(it => topoKey(it.g) === vm).forEach(it => lightItem(it, vm));
    if(sel.startsWith('ct:')){ hl.add(`e:${sel}`); return hl; }
    if(sel === S.rt.key){ S.cts.forEach(ct => hl.add(`e:${ct.key}`)); return hl; }
  }
  const items = L.items.filter(it => topoKey(it.g) === sel);
  if(items.length){
    items.forEach(it => lightItem(it, sel));
  } else if(sel.startsWith('net:') || sel.startsWith('tmpl:')){
    topoColPath(L, sel).forEach(e => hl.add(e));
    L.items.forEach(it => { if(it.col === sel) hl.add(`e:${it.col}:${topoKey(it.g)}`); });
  } else if(sel.startsWith('node:')){
    const nk = sel.slice(5);
    hl.add(`e:${sel}`);
    L.cols.forEach(c => { if(c.node && topoNodeKey(c.node) === nk){ hl.add(`e:${c.key}`); hl.add(`e:${topoClusterKey(c.node.connection_id)}`); } });
    L.gateways.forEach(G => { if(topoNodeKey(G.node) === nk) hl.add(`e:${G.key}`); });
    L.items.forEach(it => { const c = L.cols.find(c => c.key === it.col); if(c && c.node && topoNodeKey(c.node) === nk) hl.add(`e:${it.col}:${topoKey(it.g)}`); });
  } else if(sel.startsWith('gw:')){
    const G = L.gateways.find(G => G.key === sel);
    if(G){
      topoGwPath(L, G).forEach(e => hl.add(e));
      G.gw.routed.forEach(k => hl.add(`e:net:${k}`));
    }
  } else if(sel === 'unplaced'){
    hl.add('e:unplaced');
    L.items.forEach(it => { if(it.col === 'unplaced') hl.add(`e:${it.col}:${topoKey(it.g)}`); });
  } else if(sel.startsWith('cluster:')){
    hl.add(`e:${sel}`);
    L.cols.forEach(c => { if(c.node && topoClusterKey(c.node.connection_id) === sel) hl.add(`e:node:${topoNodeKey(c.node)}`); });
  }
  return hl;
}

/* ---------- side panel ---------- */
function topoHostBadge(h){
  if(h.status === 'locked' || h.active_job_id) return `<span class="badge info running"><span class="g"></span>Patching</span>`;
  if(h.connectivity === 'offline') return `<span class="badge unknown"><span class="g">?</span>Unreachable</span>`;
  if(h.connectivity === 'stale') return `<span class="badge unknown"><span class="g">?</span>Not confirmed</span>`;
  if(h.updates_assessed_ok === false) return `<span class="badge unknown"><span class="g">?</span>Couldn't check</span>`;
  if((h.max_severity === 'critical' || h.max_severity === 'important') && h.pending_updates)
    return `<span class="badge danger"><span class="g">&#9650;</span>Urgent</span>`;
  if(h.pending_updates) return `<span class="badge warning"><span class="g">&#9679;</span>Due</span>`;
  return `<span class="badge success"><span class="g">&#10003;</span>Current</span>`;
}
function topoPendingCell(h){
  if(h.updates_assessed_ok === false) return '<span class="muted">unknown — the package manager couldn’t be queried</span>';
  const by = h.pending_by_severity || {};
  const parts = SEVERITY_ORDER.filter(s => by[s]).map(s => sevChip(s, by[s]));
  return parts.length ? parts.join(' ') : '<span class="muted">none</span>';
}
const SEVERITY_ORDER = ['critical', 'important', 'moderate', 'low', 'unknown', 'none'];
function topoKv(rows){
  return `<div class="topo-kv">${rows.filter(Boolean).map(([k, v]) => `<div class="k">${k}</div><div class="v">${v}</div>`).join('')}</div>`;
}
function topoSidePanel(d, L){
  const sel = state.topo.sel;
  if(sel && sel.startsWith('ct:')) return topoContainerPanel(L);
  if(sel && sel.startsWith('rt:')) return topoRuntimePanel(L);
  const role = state.user.role, isAdmin = atLeast(role, 'admin'), canIgnore = atLeast(role, 'lead');
  const crumbs = parts => `<div class="topo-crumbs mono">${parts.map(esc).join(' &rsaquo; ')}</div>`;
  if(!sel) return `<div class="topo-panel-empty">Select a node, bridge or machine to see its details.<br><br>Each node fans out into the bridges its VMs are plugged into; a VM with NICs on several bridges appears under each, marked &#8644;. A gateway — a router or firewall — is drawn once, above the bridges it routes. A dashed line is something kite doesn't manage, or a position it couldn't confirm.<br><br><em>Listening</em> means a process accepts connections there — a firewall may still block it.</div>`;

  if(sel.startsWith('gw:')) return topoGatewayPanel(L);
  const item = L.items.find(it => topoKey(it.g) === sel);
  if((item && item.net) || sel.startsWith('net:')) return topoBridgeSidePanel(L);
  if(item){
    const g = item.g, h = g.host;
    const colNode = (L.cols.find(c => c.key === item.col) || {}).node;
    const path = ['kite'].concat(colNode ? [colNode.connection || 'cluster', colNode.name] : ['unplaced']);
    if(h && g.coverage === 'managed'){
      const safe = TOPO_SAFE[h.safety_net] || TOPO_SAFE.none;
      return `${crumbs(path)}
        <div class="topo-panel-title mono">${esc(h.hostname)}</div>
        <div style="margin-bottom:12px">${topoHostBadge(h)}</div>
        ${topoKv([
          ['Host', `<span class="mono">${esc(h.hostname)}</span>`],
          colNode ? ['Node', `<span class="mono">${esc(colNode.name)}</span>${h.placement==='pinned' ? ' <span class="muted">(pinned)</span>' : ''}`] : ['Why unplaced', esc((UNPLACED_WHY[h.unplaced_reason] || (() => '—'))(h))],
          g.vmid != null ? ['VM id', `<span class="mono">${g.vmid}${g.type ? ` &middot; ${guestTypeLabel(g.type)}` : ''}</span>`] : null,
          ['Pending', topoPendingCell(h)],
          ['Last heard', `<span class="mono">${fmtLastSeen(h.last_seen)}</span>`],
          ['Safety net', esc(safe.long)],
          h.containers && h.containers.total ? ['Containers', `<span class="mono">${h.containers.total}</span>${h.containers.update_available ? ` &middot; ${h.containers.update_available} outdated` : ''}`] : null,
          h.active_job_id ? ['Active run', `<a href="#" class="mono" onclick="openJobProgress(${h.active_job_id});return false">run ${h.active_job_id} &rarr;</a>`] : null,
        ])}
        <button class="primary" style="margin-top:14px" onclick="openHostDetail(${h.id})">Open machine &rarr;</button>`;
    }
    const kv = topoKv([
      ['VM id', `<span class="mono">${g.vmid} &middot; ${guestTypeLabel(g.type)}</span>`],
      ['Node', `<span class="mono">${esc(colNode ? colNode.name : '—')}</span>`],
      ['Power', esc(g.status)],
      g.coverage==='ignored' ? ['Reason', `&ldquo;${esc(g.ignore_reason)}&rdquo;${g.ignored_by ? ` &middot; ${esc(g.ignored_by)}` : ''}`] : null,
      g.coverage==='name_match' && g.suggested_host ? ['Suggested', `<span class="mono">${esc(g.suggested_host.hostname)}</span>`] : null,
    ]);
    const actions = [];
    if(g.coverage==='unmanaged'){
      if(isAdmin) actions.push(`<button class="primary" onclick="enrollGuest('${jsq(g.name)}')">Enroll</button>`);
      if(canIgnore) actions.push(`<button onclick="openIgnoreDialog(${g.vmid},'${jsq(g.name)}',${g.connection_id ?? 'null'})">Ignore&hellip;</button>`);
    }
    if(g.coverage==='name_match' && isAdmin && g.suggested_host)
      actions.push(`<button class="info-outline" onclick="linkGuest(${g.suggested_host.id},${g.vmid},'${jsq(g.suggested_host.hostname)}',${g.connection_id ?? 'null'})">Link to ${esc(g.suggested_host.hostname)}</button>`);
    if(g.coverage==='ignored' && canIgnore) actions.push(`<button onclick="unignoreGuest(${g.vmid},${g.connection_id ?? 'null'})">Un-ignore</button>`);
    const blurb = {
      unmanaged: 'Proxmox runs this guest, but no kite agent reports from it — nobody is patching it.',
      name_match: 'A host with this name is enrolled but not linked to this VM id, so snapshots can’t target it.',
      ignored: 'Deliberately left out of kite.',
      template: 'A template never runs, so it never needs patching.',
    }[g.coverage] || '';
    return `${crumbs(path)}
      <div class="topo-panel-title mono">${esc(g.name || '—')}</div>
      <div style="margin-bottom:10px">${coverageBadge(g.coverage)}</div>
      <p class="card-help">${blurb}</p>
      ${kv}
      ${actions.length ? `<div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">${actions.join('')}</div>` : ''}`;
  }
  if(sel.startsWith('node:')){
    const n = d.nodes.find(x => `node:${topoNodeKey(x)}` === sel);
    if(!n) return '';
    const b = n.blast_radius;
    return `${crumbs(['kite', n.connection || 'cluster', n.name])}
      <div class="topo-panel-title mono">${esc(n.name)}</div>
      <p class="card-help">Rebooting this node takes every guest below down with it.</p>
      ${topoKv([
        ['Status', esc(n.status)],
        ['Guests', `${b.guests} (${b.running} running)`],
        ['Managed', `${b.managed}${b.unmanaged ? ` &middot; <span style="color:var(--urgent)">${b.unmanaged} not managed</span>` : ''}`],
        ['Active runs', String(b.active_runs)],
        ['No snapshot', b.no_snapshot ? `<span style="color:var(--urgent)">${b.no_snapshot} host${b.no_snapshot===1?'':'s'}</span>` : '0'],
        ['Critical pending', b.critical_pending ? `<span style="color:var(--urgent)">${b.critical_pending} host${b.critical_pending===1?'':'s'}</span>` : '0'],
        ['Templates', String(n.templates)],
      ])}`;
  }
  if(sel === 'unplaced'){
    return `${crumbs(['kite', 'unplaced'])}
      <div class="topo-panel-title">Unplaced</div>
      <p class="card-help">${d.unplaced.length} host${d.unplaced.length===1?'':'s'} kite manages but can't place on a node: bare metal, another hypervisor, or a VM id that was never linked or no longer exists.</p>
      <button onclick="setFleetSection('coverage');navigate('fleet')">Review in Coverage &rarr;</button>`;
  }
  if(sel.startsWith('cluster:')){
    const c = topoClusters(d).find(c => topoClusterKey(c.connection_id) === sel);
    if(!c) return '';
    const nodes = d.nodes.filter(n => (n.connection_id ?? null) === (c.connection_id ?? null));
    return `${crumbs(['kite', c.name])}
      <div class="topo-panel-title">${esc(c.name)}</div>
      <p class="card-help">A Proxmox connection — a cluster, or a standalone host. Managed in Settings &rarr; Connections.</p>
      ${topoKv([['Endpoint', `<span class="mono">${esc(c.host || '—')}</span>`], ['Nodes', String(nodes.length)],
        ['Status', c.error ? `<span style="color:var(--urgent)">${esc(c.error)}</span>${c.stale ? ' — showing the last good fetch' : ''}` : 'reachable']])}`;
  }
  return `${crumbs(['kite'])}<div class="topo-panel-title">kite controller</div>
    <p class="card-help">Agents poll this controller; it never connects into a host. The only outbound connection is the read-only Proxmox API this map is drawn from.</p>`;
}
function topoLegend(){
  return `<div class="topo-legend">
    <div class="topo-lbl" style="margin-bottom:6px">Legend</div>
    <div class="row">${sevChip('critical',null)}${sevChip('important',null)}${sevChip('moderate',null)}${sevChip('low',null)} pending <span class="topo-dot healthy"></span> reachable</div>
    <div class="row"><span class="topo-dot offline"></span> no answer <span class="topo-spin"></span> patching</div>
    <div class="row"><span class="topo-safe snap">SNAP</span><span class="topo-safe pkg">PKG</span><span class="topo-safe none">NONE</span> safety net <span class="topo-ct">&#9632;</span> containers</div>
    <div class="row"><span class="sw solid"></span> managed <span class="sw gap"></span> unmanaged <span class="sw match"></span> name match <span class="sw ign"></span> ignored</div>
    <div class="row"><span class="topo-ct">&#8644;</span> on several bridges <span class="topo-port">tcp/22</span> listening</div>
    <div class="row"><span class="sw gw"></span> gateway <span class="topo-gw-hint">GW?</span> looks like one</div>
  </div>`;
}

/* ---------- interaction ---------- */
let topoDrag = null;      // {x, y, tx, ty, moved} panning, or {card, x, y, start, moved} moving a card
let topoRaf = 0;
let topoListening = false;
function topoSelect(key){
  if(topoDrag && topoDrag.moved) return;  // the end of a pan, not a click
  const t = state.topo;
  t.sel = t.sel === key ? null : key;
  if(key.startsWith('host:')){
    const id = +key.slice(5);
    t.expanded = t.sel ? id : null;
    if(t.sel && state.topoContainers[id] === undefined) loadTopoContainers(id);
  }
  render();
}
function topoToggleNode(name){ state.topo.collapsed[name] = !state.topo.collapsed[name]; render(); }
function liveTopoSearch(input){
  const pos = input.selectionStart;
  state.topo.q = input.value;
  render();
  const el = document.getElementById('topo-search');
  if(el){ el.focus(); el.setSelectionRange(pos, pos); }
}
function topoApplyTransform(){
  const t = state.topo, c = document.getElementById('topo-canvas'), pct = document.getElementById('topo-pct');
  if(c) c.style.transform = `translate(${t.tx}px,${t.ty}px) scale(${t.k})`;
  if(pct) pct.textContent = `${Math.round(t.k * 100)}%`;
}
function topoZoomAt(mx, my, f){
  const t = state.topo, k = Math.min(1.8, Math.max(0.25, t.k * f));
  t.tx = mx - (mx - t.tx) * k / t.k;
  t.ty = my - (my - t.ty) * k / t.k;
  t.k = k;
  t.fitted = true;  // the user has taken over; stop auto-fitting
  topoApplyTransform();
}
function topoZoomCenter(f){
  const vp = document.getElementById('topo-vp');
  if(vp && vp.clientWidth) topoZoomAt(vp.clientWidth / 2, vp.clientHeight / 2, f);
}
function topoWheel(e){
  e.preventDefault();
  const r = e.currentTarget.getBoundingClientRect();
  topoZoomAt(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 1 / 1.12);
}
function topoDown(e){
  if(e.button !== 0) return;
  const card = e.target && e.target.closest ? e.target.closest('[data-drag]') : null;
  if(card && !e.target.closest('button, a, input')){
    const key = card.getAttribute('data-drag');
    topoDrag = {card: key, x: e.clientX, y: e.clientY, start: (topoMoved()[key] || [0, 0]).slice(), moved: false};
    return;
  }
  topoDrag = {x: e.clientX, y: e.clientY, tx: state.topo.tx, ty: state.topo.ty, moved: false};
}
function topoMove(e){
  if(!topoDrag) return;
  const dx = e.clientX - topoDrag.x, dy = e.clientY - topoDrag.y;
  if(!topoDrag.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
  topoDrag.moved = true;
  if(topoDrag.card){
    const k = state.topo.k;
    topoMoved()[topoDrag.card] = [Math.round(topoDrag.start[0] + dx / k), Math.round(topoDrag.start[1] + dy / k)];
    if(!topoRaf) topoRaf = requestAnimationFrame(topoRedrawCanvas);
    return;
  }
  state.topo.tx = topoDrag.tx + dx;
  state.topo.ty = topoDrag.ty + dy;
  state.topo.fitted = true;
  topoApplyTransform();
}
// Mid-drag: only the canvas, not the page around it.
function topoRedrawCanvas(){
  topoRaf = 0;
  const c = document.getElementById('topo-canvas');
  if(!c || !state.topology) return;
  const L = topoLayout(state.topology);
  c.innerHTML = topoCanvas(state.topology, L);
  Object.assign(c.dataset, {w: L.W, h: L.H, x0: L.x0, y0: L.y0});
  c.style.width = `${L.W}px`;
  c.style.height = `${L.H}px`;
}
function topoUp(){
  // Cleared after the click that follows mouseup has been dispatched, so
  // topoSelect can still tell a drag from a click.
  if(!topoDrag) return;
  if(topoDrag.card && topoDrag.moved){
    topoSaveMoved();
    render();          // the Reset layout button, the side panel
  }
  setTimeout(() => { topoDrag = null; }, 0);
}
function topoToggleFull(){
  state.topo.full = !state.topo.full;
  state.topo.fitted = false;
  render();
}
function topoFit(){
  const vp = document.getElementById('topo-vp'), c = document.getElementById('topo-canvas');
  if(!vp || !c || !vp.clientWidth) return;
  const x0 = +c.dataset.x0 || 0, y0 = +c.dataset.y0 || 0;
  const W = +c.dataset.w - x0, H = +c.dataset.h - y0;
  const k = Math.min((vp.clientWidth - 40) / W, (vp.clientHeight - 70) / H, 1.2);
  Object.assign(state.topo, {k, tx: (vp.clientWidth - W * k) / 2 - x0 * k,
    ty: Math.max(20, (vp.clientHeight - 50 - H * k) / 2) - y0 * k, fitted: true});
  topoApplyTransform();
}
// Called by render() after the view's HTML is in place.
function topoAfterRender(){
  if(!topoListening){
    topoListening = true;
    document.addEventListener('mousemove', topoMove);
    document.addEventListener('mouseup', topoUp);
    document.addEventListener('keydown', e => {
      if(state.nav !== 'topology' || (e.target && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName))) return;
      if(e.key === 'Escape' && (state.topo.sel || state.topo.expanded != null)){ state.topo.sel = null; state.topo.expanded = null; render(); }
      else if(e.key === 'Escape' && state.topo.full) topoToggleFull();
      if(e.key === '+' || e.key === '=') topoZoomCenter(1.2);
      if(e.key === '-') topoZoomCenter(1 / 1.2);
    });
  }
  if(!state.topo.fitted && document.getElementById('topo-canvas')) topoFit();
}

/* ============================== BRIDGES ============================== */
function topoBareIp(cidr){ return String(cidr || '').split('/')[0]; }
function topoNetSub(g){
  const ip = g.ips && g.ips.length ? topoBareIp(g.ips[0])
    : g.host ? (g.host.network_ok == null ? 'network not reported' : 'no IP matched') : `${g.vmid} · ${guestTypeLabel(g.type)}`;
  const n = (g.ports || []).length;
  return `${esc(ip)}${n ? ` &middot; ${n} listening` : ''}`;
}
function topoBridgeCard(n, x, y){
  const t = state.topo, s = n.summary, key = `net:${n.key}`;
  const chip = (txt, tone) => `<span class="topo-chip ${tone||''}">${txt}</span>`;
  const chips = [
    chip(`${s.machines} machine${s.machines===1?'':'s'}`),
    s.unmanaged ? chip(`&#9675; ${s.unmanaged} unmanaged`, 'gap') : '',
    s.listening ? chip(`${s.listening} listening`, 'run') : '',
    s.critical ? chip(`&#9650; ${s.critical} critical`, 'crit') : '',
  ].join('');
  const collapsed = !!t.collapsed[key];
  return `<div class="topo-node topo-bridge ${n.kind} ${t.sel===key?'sel':''}" data-drag="${esc(key)}" style="left:${x - TOPO.NODE_W/2}px;top:${y ?? TOPO.BY}px" onclick="topoSelect('${jsq(key)}')">
    <div class="topo-node-head">
      <span class="topo-net-icon ${n.kind}"></span>
      <span class="topo-node-name">${esc(n.label)}</span>
      <span class="grow"></span>
      <button class="topo-mini" onclick="event.stopPropagation();topoToggleNode('${jsq(key)}')">${collapsed ? `Expand ${s.machines}` : 'Collapse'}</button>
    </div>
    ${n.note ? `<div class="topo-net-note">${esc(n.note)}</div>` : ''}
    <div class="topo-chips">${chips}</div>
    ${n.subnets.length ? `<div class="topo-node-foot mono">${n.subnets.map(esc).join(', ')}</div>` : ''}
  </div>`;
}
/* ---------- gateways ---------- */
function topoGatewayCard(G){
  const t = state.topo, gw = G.gw, h = gw.host, sel = t.sel === G.key;
  const chip = (txt, tone) => `<span class="topo-chip ${tone||''}">${txt}</span>`;
  const uplink = gw.interfaces.find(i => i.role === 'uplink');
  const status = h && gw.coverage === 'managed'
    ? (h.pending_updates ? sevChip(h.max_severity, null) : '<span class="topo-ok">&#10003;</span>')
    : '<span class="muted" style="font-size:10.5px">no agent</span>';
  const chips = [
    chip(`routes ${gw.routed.length} bridge${gw.routed.length===1?'':'s'}`),
    chip(uplink ? `uplink ${esc(uplink.label)}` : 'no uplink bridge'),
    chip(gw.source === 'tag' ? 'Proxmox tag' : 'marked in kite'),
  ].join('');
  const addrs = gw.interfaces.filter(i => i.role === 'routes')
    .map(i => `${esc(i.iface)}${i.ips.length ? ` ${esc(i.ips[0])}` : ''}`).join(' &middot; ');
  return `<div class="topo-node topo-gw ${gw.coverage==='managed' ? '' : 'unmanaged'} ${sel?'sel':''} ${topoMatches(gw) ? '' : 'dim'}" data-drag="${esc(G.key)}" style="left:${G.x - TOPO.NODE_W/2}px;top:${G.y}px" onclick="topoSelect('${jsq(G.key)}')" title="${esc(gw.name || '')}">
    <div class="topo-node-head">
      <span class="topo-gw-icon"></span>
      <span class="mono topo-node-name">${esc(h ? h.hostname.split('.')[0] : gw.name || '—')}</span>
      <span class="topo-gw-badge">Gateway</span>
      <span class="grow"></span>${status}
    </div>
    <div class="topo-chips">${chips}</div>
    ${addrs ? `<div class="topo-node-foot">${addrs}</div>` : ''}
  </div>`;
}
function topoGatewayPanel(L){
  const G = L.gateways.find(G => G.key === state.topo.sel);
  if(!G) return '';
  const gw = G.gw, h = gw.host, canLead = atLeast(state.user.role, 'lead');
  const crumbs = `<div class="topo-crumbs mono">${['kite', G.node.connection || 'cluster', G.node.name].map(esc).join(' &rsaquo; ')}</div>`;
  const role = {uplink: 'uplink', routes: 'routes', 'also on': 'also on — routed by another gateway'};
  const blocks = gw.interfaces.map(i => `
    <div class="topo-netblock" style="cursor:pointer" onclick="topoSelect('${jsq(`net:${i.network}`)}')">
      <div style="display:flex;align-items:baseline;gap:6px"><strong>${esc(i.label)}</strong><span class="muted" style="font-size:11px">${role[i.role] || esc(i.role)}</span><span class="grow"></span><span class="mono muted" style="font-size:10.5px">${esc(i.iface)}</span></div>
      <div class="mono" style="font-size:12px;margin-top:3px">${i.ips.length ? i.ips.map(esc).join(', ') : '<span class="muted">address unknown</span>'}</div>
    </div>`).join('');
  const actions = [];
  if(h && gw.coverage === 'managed') actions.push(`<button class="primary" onclick="openHostDetail(${h.id})">Open machine &rarr;</button>`);
  if(gw.source === 'marked' && canLead)
    actions.push(`<button onclick="setGateway(${gw.vmid},${gw.connection_id ?? 'null'},false)">Not a gateway</button>`);
  return `${crumbs}
    <div class="topo-panel-title mono">${esc(gw.name || '—')}</div>
    <div style="margin-bottom:10px"><span class="badge cov-gateway"><span class="g">&#8679;</span>Gateway</span> ${coverageBadge(gw.coverage)}</div>
    <p class="card-help">Routes the bridges below it. Drawn once here instead of under every bridge it has a NIC on.${gw.coverage === 'gateway' ? ' No kite agent: routers and firewalls are patched from their own UI, and kite never touches this one.' : ''}</p>
    ${blocks}
    ${topoKv([
      ['VM id', `<span class="mono">${gw.vmid} &middot; ${guestTypeLabel(gw.type)}</span>`],
      ['Power', esc(gw.status || '—')],
      ['Identified by', gw.source === 'tag' ? `Proxmox tag <span class="mono">kite-gateway</span>` : 'marked in kite'],
    ])}
    ${gw.source === 'tag' ? '<p class="card-help" style="margin-top:10px">To stop drawing it as a gateway, remove the tag in Proxmox.</p>' : ''}
    ${actions.length ? `<div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">${actions.join('')}</div>` : ''}`;
}
// On a VM's panel: the gateway suggestion, or the way to promote it by hand.
function topoGatewayHint(g, nets){
  if(!atLeast(state.user.role, 'lead') && !g.gateway_suggestion) return '';
  const canLead = atLeast(state.user.role, 'lead'), cid = g.connection_id ?? 'null';
  if(g.gateway_secondary) return '';
  if(g.gateway_dismissed)
    return `<p class="card-help" style="margin-top:10px">Marked as not a gateway${typeof g.gateway_dismissed === 'string' ? ` by ${esc(g.gateway_dismissed)}` : ''}.${canLead ? ` <a href="#" onclick="clearGateway(${g.vmid},${cid});return false">Undo</a>` : ''}</p>`;
  const promote = canLead ? `<button class="info-outline" onclick="setGateway(${g.vmid},${cid},true)">Show as gateway</button>` : '';
  if(g.gateway_suggestion)
    return `<div class="topo-netblock" style="margin-top:12px"><strong>Looks like a gateway</strong>
      <div class="muted" style="font-size:12px;margin:3px 0 8px">${esc(g.gateway_suggestion)}. A gateway is drawn once, above the bridges it routes. Tagging the VM <span class="mono">kite-gateway</span> in Proxmox does the same.</div>
      ${canLead ? `<div style="display:flex;gap:8px;flex-wrap:wrap">${promote}<button onclick="setGateway(${g.vmid},${cid},false)">Not a gateway</button></div>` : ''}</div>`;
  return nets > 1 && canLead ? `<div style="margin-top:12px">${promote}</div>` : '';
}
function topoTemplatesCard(c){
  return `<div class="topo-node topo-bridge unknown" data-drag="${esc(c.key)}" style="left:${c.x - TOPO.NODE_W/2}px;top:${c.y}px">
    <div class="topo-node-head"><span class="topo-node-name">Templates</span><span class="topo-chip">${c.list.length}</span></div>
    <div class="topo-net-note">never run, so never need patching</div>
  </div>`;
}
function topoPortChips(ports){
  if(!ports.length) return '<span class="muted">nothing listening on this address</span>';
  return ports.map(p => `<span class="topo-port" title="bound to ${esc(p.address)}${p.first_seen ? ` · first seen ${fmtTs(p.first_seen)} UTC` : ''}">${esc(p.proto)}/${p.port}${p.process ? ` <span class="muted">${esc(p.process)}</span>` : ''}</span>`).join('');
}
// What listens across a bridge: its attack surface in one place. Folded
// to a one-line count by default -- each machine's own panel has the
// full list -- and capped per machine when open, so a busy bridge stays
// readable as more agents report.
const TOPO_PORTS_PER_MACHINE = 6;
function topoBridgePorts(exposed){
  const total = exposed.reduce((n, m) => n + m.ports.length, 0);
  if(!exposed.length) return '<p class="card-title" style="margin:14px 0 6px;font-size:12px">Listening on this bridge</p><div class="muted" style="font-size:12px">Nothing reported listening.</div>';
  const open = !!state.topo.portsOpen;
  const head = `<button class="topo-fold" onclick="state.topo.portsOpen=${open ? 'false' : 'true'};render()">
      <span>${open ? '&#9662;' : '&#9656;'}</span> Listening on this bridge
      <span class="grow"></span><span class="mono muted">${exposed.length} machine${exposed.length===1?'':'s'} &middot; ${total} port${total===1?'':'s'}</span></button>`;
  if(!open) return head;
  return head + exposed.map(m => {
    const shown = m.ports.slice(0, TOPO_PORTS_PER_MACHINE), rest = m.ports.length - shown.length;
    return `<div class="topo-netblock" style="cursor:pointer" onclick="topoSelect('${jsq(topoKey(m))}')"><span class="mono" style="font-size:12px;font-weight:600">${esc(m.host ? m.host.hostname : m.name)}</span> <span class="mono muted" style="font-size:11px">${esc(topoBareIp(m.ips[0] || ''))}</span><div class="topo-ports" style="margin-top:5px">${topoPortChips(shown)}${rest > 0 ? `<span class="muted" style="font-size:11px">+${rest} more</span>` : ''}</div></div>`;
  }).join('');
}
function topoBridgeSidePanel(L){
  const sel = state.topo.sel;
  if(sel && sel.startsWith('ct:')) return topoContainerPanel(L);
  const role = state.user.role, isAdmin = atLeast(role, 'admin'), canIgnore = atLeast(role, 'lead');
  const crumbs = parts => `<div class="topo-crumbs mono">${parts.map(esc).join(' &rsaquo; ')}</div>`;
  const items = L.items.filter(it => topoKey(it.g) === sel);
  if(items.length){
    const g = items[0].g, h = g.host;
    const nets = items.filter(it => it.net).map(it => ({net: L.cols.find(c => c.key === it.col).net, g: it.g}));
    const node = (L.cols.find(c => c.key === items[0].col) || {}).node;
    const blocks = nets.map(({net, g}) => net ? `
      <div class="topo-netblock">
        <div style="display:flex;align-items:baseline;gap:6px"><strong>${esc(net.label)}</strong><span class="grow"></span>${g.nic ? `<span class="mono muted" style="font-size:10.5px">${esc(g.nic.iface)}</span>` : ''}</div>
        <div class="mono" style="font-size:12px;margin:3px 0 6px">${g.ips.length ? g.ips.map(esc).join(', ') : `<span class="muted">${g.host ? (g.host.network_ok === null ? 'agent doesn’t report addresses yet' : 'no interface with this NIC’s MAC') : 'unknown — no agent'}</span>`}</div>
        ${g.host ? `<div class="topo-ports">${topoPortChips(g.ports)}</div>` : ''}
        ${g.nic && g.nic.mac ? `<div class="mono muted" style="font-size:10.5px;margin-top:5px">MAC ${esc(g.nic.mac)}${g.nic.firewall ? ' &middot; Proxmox firewall on' : ''}</div>` : ''}
      </div>` : `<div class="topo-netblock"><strong>Network unknown</strong><div class="muted" style="font-size:12px;margin-top:3px">${esc(g.why || '')}</div></div>`).join('');
    if(h){
      const safe = TOPO_SAFE[h.safety_net] || TOPO_SAFE.none;
      return `${crumbs(['kite', node ? node.name : '—'])}
        <div class="topo-panel-title mono">${esc(h.hostname)}</div>
        <div style="margin-bottom:12px">${topoHostBadge(h)}${g.multi_homed ? ` <span class="badge info">&#8644; ${nets.length} bridges</span>` : ''}</div>
        ${blocks}
        ${topoKv([
          ['Pending', topoPendingCell(h)],
          ['Last heard', `<span class="mono">${fmtLastSeen(h.last_seen)}</span>`],
          ['Gateway', h.default_gateway ? `<span class="mono">${esc(h.default_gateway)}</span>` : '<span class="muted">—</span>'],
          ['Safety net', esc(safe.long)],
        ])}
        ${topoGatewayHint(g, nets.length)}
        <button class="primary" style="margin-top:14px" onclick="openHostDetail(${h.id})">Open machine &rarr;</button>`;
    }
    const actions = [];
    if(g.coverage==='unmanaged'){
      if(isAdmin) actions.push(`<button class="primary" onclick="enrollGuest('${jsq(g.name)}')">Enroll</button>`);
      if(canIgnore) actions.push(`<button onclick="openIgnoreDialog(${g.vmid},'${jsq(g.name)}',${g.connection_id ?? 'null'})">Ignore&hellip;</button>`);
    }
    if(g.coverage==='name_match' && isAdmin && g.suggested_host)
      actions.push(`<button class="info-outline" onclick="linkGuest(${g.suggested_host.id},${g.vmid},'${jsq(g.suggested_host.hostname)}',${g.connection_id ?? 'null'})">Link to ${esc(g.suggested_host.hostname)}</button>`);
    if(g.coverage==='ignored' && canIgnore) actions.push(`<button onclick="unignoreGuest(${g.vmid},${g.connection_id ?? 'null'})">Un-ignore</button>`);
    return `${crumbs(['kite', node ? node.name : '—'])}
      <div class="topo-panel-title mono">${esc(g.name || '—')}</div>
      <div style="margin-bottom:10px">${coverageBadge(g.coverage)}</div>
      ${blocks}
      ${g.vmid != null ? topoKv([['VM id', `<span class="mono">${g.vmid} &middot; ${guestTypeLabel(g.type)}</span>`], ['Node', `<span class="mono">${esc(g.node || '—')}</span>`], ['Power', esc(g.status || '—')]]) : ''}
      ${g.coverage==='unmanaged' ? '<p class="card-help" style="margin-top:10px">Proxmox runs this guest, but no kite agent reports from it — nobody is patching it. Its address and ports are unknown; only the bridges it’s plugged into.</p>' : ''}
      ${g.gateway_secondary ? '<p class="card-help" style="margin-top:10px">A gateway, drawn as a tile here because another gateway routes this bridge.</p>' : ''}
      ${topoGatewayHint(g, nets.length)}
      ${actions.length ? `<div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">${actions.join('')}</div>` : ''}`;
  }
  if(sel.startsWith('net:')){
    const c = L.cols.find(c => c.key === sel);
    if(!c || !c.net) return '';
    const n = c.net, s = n.summary;
    const exposed = n.members.filter(m => m.ports.length);
    return `${crumbs(['kite', c.node ? c.node.name : '—', n.label])}
      <div class="topo-panel-title">${esc(n.label)}</div>
      ${n.note ? `<p class="card-help" style="margin-top:-2px">${esc(n.note)}</p>` : ''}
      ${topoKv([
        ['Subnets', n.subnets.length ? `<span class="mono">${n.subnets.map(esc).join('<br>')}</span>` : '<span class="muted">none seen yet</span>'],
        n.parent_gateway ? ['Routed by', (G => G ? `<a href="#" class="mono" onclick="topoSelect('${jsq(G.key)}');return false">${esc(G.gw.name || G.gw.vmid)}</a>` : '—')(L.gateways.find(G => G.gw.key === n.parent_gateway))] : null,
        ['Bridges', n.bridges.length ? `<span class="mono">${n.bridges.map(esc).join('<br>')}</span>` : '<span class="muted">not on Proxmox</span>'],
        ['Machines', `${s.machines} (${s.managed} managed${s.unmanaged ? `, <span style="color:var(--urgent)">${s.unmanaged} not</span>` : ''})`],
        ['Critical', s.critical ? `<span style="color:var(--urgent)">${s.critical} host${s.critical===1?'':'s'}</span>` : '0'],
      ])}
      ${topoBridgePorts(exposed)}`;
  }
  return '';
}


/* ============================== CONTAINERS UNDER A VM ============================== */
// Selecting a VM drops its containers out beneath it as part of the tree --
// VM -> runtime (docker, podman) -> each container -- from the same
// GET /hosts/{id}/containers the machine page uses, fetched on click so
// the map itself stays light. Compose projects come first, then the rest.
const CT = {GAP: 18, ROW: 52, IND: 28, W: 160, H: 44, MORE: 26, MAX: 40};

async function loadTopoContainers(id){
  state.topoContainers[id] = null;
  try{ state.topoContainers[id] = await api.hostContainers(id); }
  catch(e){ state.topoContainers[id] = {error: e.message}; }
  if(state.nav === 'topology') render();
}
function topoCtGroups(list){
  const groups = {};
  list.forEach(c => {
    const k = c.managed_by === 'compose' && c.compose_project ? `compose:${c.compose_project}` : `other:${c.managed_by || 'standalone'}`;
    (groups[k] = groups[k] || []).push(c);
  });
  return Object.keys(groups)
    .sort((a, b) => (a.startsWith('compose:') ? 0 : 1) - (b.startsWith('compose:') ? 0 : 1) || a.localeCompare(b))
    .map(k => ({key: k, compose: k.startsWith('compose:'), label: k.split(':').slice(1).join(':'),
                list: groups[k].sort((a, b) => a.name.localeCompare(b.name))}));
}
function topoCtOrder(list){ return [].concat(...topoCtGroups(list).map(g => g.list)); }
function topoCtGroupLabel(c){
  return c.managed_by === 'compose' && c.compose_project ? c.compose_project : (c.managed_by || 'standalone');
}
function topoCtStatus(c){
  if(c.pinned) return '<span class="sev none" title="Pinned to a digest — never drifts">PIN</span>';
  if(c.update_available === true) return '<span class="sev moderate" title="A newer image exists upstream">NEW</span>';
  if(c.update_available === false) return '<span class="topo-ok" title="Up to date">&#10003;</span>';
  return '<span class="sev none" title="Couldn’t check the registry">?</span>';
}
function topoShortImage(image){
  const s = String(image || '');
  const last = s.split('/').pop();
  return last.length > 34 ? last.slice(0, 33) + '…' : last;
}
function topoContainerChain(L){
  const S = L.sub;
  if(!S) return '';
  const h = S.host, list = S.list, t = state.topo;
  const runtime = h.container_runtime || 'containers';
  const status = list === null || list === undefined ? '<span class="pm-spin"></span> loading…'
    : !Array.isArray(list) ? `<span style="color:var(--urgent-ink)">couldn't load: ${esc(list.error)}</span>`
    : `${h.containers.total} container${h.containers.total===1?'':'s'}${h.containers.update_available ? ` &middot; <span style="color:var(--due)">${h.containers.update_available} outdated</span>` : ''}`;
  const rt = `<div class="topo-tile topo-rt ${t.sel === S.rt.key ? 'sel' : ''}" data-drag="${esc(S.rt.key)}" style="left:${S.rt.x}px;top:${S.rt.y}px" onclick="topoSelect('${jsq(S.rt.key)}')" title="${esc(runtime)} on ${esc(h.hostname)}">
      <div class="topo-tile-name"><span class="ctray-rt">${esc(runtime)}</span></div>
      <div class="topo-tile-sub">${status}</div>
      <div class="topo-tile-right"><button class="topo-mini" title="Fold" onclick="event.stopPropagation();state.topo.expanded=null;if(String(state.topo.sel||'').match(/^(rt|ct):/))state.topo.sel=null;render()">&times;</button></div>
    </div>`;
  const cts = S.cts.map(({c, key, x, y}) => `<div class="ctile ${t.sel === key ? 'sel' : ''} ${c.update_available === true ? 'outdated' : ''} ${c.update_available == null && !c.pinned ? 'unknown' : ''}" data-drag="${esc(key)}" style="position:absolute;left:${x}px;top:${y}px;width:${CT.W}px" onclick="topoSelect('${jsq(key)}')" title="${esc(c.image)}">
      <div class="ctile-name"><span class="topo-dot ${c.state === 'running' ? 'healthy' : 'offline'}"></span>${esc(c.name)}</div>
      <div class="ctile-sub">${esc(topoCtGroupLabel(c))} &middot; ${esc(topoShortImage(c.image))}${c.state !== 'running' ? ` &middot; ${esc(c.state || '?')}` : ''}</div>
      <div class="topo-tile-right">${topoCtStatus(c)}</div>
    </div>`).join('');
  const last = S.cts[S.cts.length - 1];
  const more = S.more && last ? `<div class="topo-ct-more" style="left:${last.x}px;top:${last.y + CT.H + 6}px"><a href="#" onclick="openHostDetail(${h.id});return false">+${S.more} more on the machine page &rarr;</a></div>` : '';
  return rt + cts + more;
}
function topoRuntimePanel(L){
  const S = L.sub;
  if(!S || state.topo.sel !== S.rt.key) return '<div class="topo-panel-empty">Select a machine to see its containers.</div>';
  const h = S.host, list = Array.isArray(S.list) ? S.list : [];
  const runtime = h.container_runtime || 'containers';
  const groups = topoCtGroups(list);
  return `<div class="topo-crumbs mono">kite &rsaquo; ${esc(h.hostname)} &rsaquo; ${esc(runtime)}</div>
    <div class="topo-panel-title mono">${esc(runtime)}</div>
    <p class="card-help">${h.containers.total} container${h.containers.total===1?'':'s'} on <span class="mono">${esc(h.hostname)}</span>${h.containers.update_available ? `, ${h.containers.update_available} with a newer image upstream` : ''}.</p>
    ${groups.map(g => `<div class="topo-netblock">
      <div style="display:flex;align-items:baseline;gap:6px">${g.compose ? `<span class="ctray-proj">compose</span> <strong class="mono">${esc(g.label)}</strong>` : `<span class="ctray-proj other">${esc(g.label)}</span>`}<span class="grow"></span><span class="mono muted" style="font-size:11px">${g.list.length}</span></div>
      <div class="muted" style="font-size:11.5px;margin-top:4px">${g.compose ? 'a containers-only run pulls and recreates these' : g.label === 'standalone' ? 'kite can’t update these safely' : 'managed by the orchestrator, not kite'}</div>
    </div>`).join('')}
    <button class="primary" style="margin-top:10px" onclick="openHostDetail(${h.id})">Open machine &rarr;</button>`;
}
function topoContainerPanel(L){
  const [, hid, cid] = state.topo.sel.split(':');
  const list = state.topoContainers[+hid];
  const c = Array.isArray(list) ? list.find(x => String(x.id) === cid) : null;
  const it = L.items.find(i => i.g.host && i.g.host.id === +hid);
  const h = it ? it.g.host : null;
  if(!c || !h) return '<div class="topo-panel-empty">That container is no longer reported.</div>';
  const managed = c.managed_by === 'compose'
    ? `compose &middot; <span class="mono">${esc(c.compose_project)}</span>${c.compose_service ? ` / <span class="mono">${esc(c.compose_service)}</span>` : ''}`
    : esc(c.managed_by || 'standalone');
  const canUpdate = c.updatable && atLeast(state.user.role, 'operator');
  return `<div class="topo-crumbs mono">kite &rsaquo; ${esc(h.hostname)} &rsaquo; ${esc(h.container_runtime || 'containers')}</div>
    <div class="topo-panel-title mono">${esc(c.name)}</div>
    <div style="margin-bottom:12px;display:flex;gap:6px;flex-wrap:wrap">${c.state === 'running' ? '<span class="badge success">running</span>' : `<span class="badge neutral">${esc(c.state || 'unknown')}</span>`}${containerStatusBadge(c)}</div>
    ${topoKv([
      ['Image', `<span class="mono" style="word-break:break-all">${esc(c.image)}</span>`],
      ['Managed by', managed],
      ['Updatable', c.updatable ? 'yes — a containers-only run pulls and recreates it' : `<span class="muted">no — ${c.managed_by === 'standalone' ? 'its creation flags aren’t recorded anywhere' : 'it belongs to its orchestrator'}</span>`],
      ['Rollback', c.rollback_available ? `capture held${c.rollback_captured_at ? ` (${relTime(c.rollback_captured_at)})` : ''}` : '<span class="muted">no capture</span>'],
      ['Reported', c.reported_at ? relTime(c.reported_at) : '—'],
    ])}
    <div class="topo-netblock" style="margin-top:14px;cursor:pointer" onclick="topoSelect('host:${h.id}')">
      <span class="muted" style="font-size:11px">Runs on</span><br><span class="mono" style="font-weight:600">${esc(h.hostname)}</span> ${topoHostBadge(h)}
    </div>
    ${canUpdate ? '<p class="card-help" style="margin-top:8px">To update it, start a run from the machine page and choose <em>Containers</em> as the scope.</p>' : ''}
    <button class="primary" style="margin-top:8px" onclick="openHostDetail(${h.id})">Open machine &rarr;</button>`;
}
