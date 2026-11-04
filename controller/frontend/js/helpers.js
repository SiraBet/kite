/*
 * Formatting and escaping. `esc()` in particular is load-bearing:
 * hostnames come from enrolling agents, so they are attacker-influenced.
 */
/* ============================== HELPERS ============================== */
function parseUTC(iso){
  // The backend sends naive ISO strings (e.g. "2026-08-09T05:08:39") that are
  // always UTC wall-clock time, by convention (everything server-side uses
  // datetime.utcnow()). Without an explicit 'Z'/offset suffix, JS's Date
  // parser silently treats the SAME string as LOCAL time instead — which
  // corrupts every "time ago" calculation by exactly the browser's UTC
  // offset. Force it.
  if(!iso) return null;
  const hasTz = /Z$|[+-]\d{2}:\d{2}$/.test(iso);
  return new Date(hasTz ? iso : iso + 'Z');
}
function fmtTs(iso){
  if(!iso) return '—';
  const d = parseUTC(iso);
  const p = n => String(n).padStart(2,'0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtDate(iso){ return iso ? iso.slice(0,10) : '—'; }
function within(hour, start, end){ return start<=end ? (hour>=start && hour<=end) : (hour>=start || hour<=end); }
// HTML escaping — safe for text content and for double-quoted attribute
// VALUES. The single quote and backtick are escaped too: without them a
// value dropped into a single-quoted JS string inside an on*="…" handler
// can break out of it. jsq() below covers the one context esc() can't.
function esc(s){ return String(s).replace(/[&<>"'`]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c])); }
// A value going inside a SINGLE-QUOTED JS string that itself sits inside a
// DOUBLE-QUOTED HTML attribute — e.g. onclick="fn('HERE')". esc() alone is
// wrong here: the browser HTML-decodes the attribute before the JS parser
// runs, so an entity like &#39; turns back into a string-breaking quote.
// The value must be JS-escaped (so quote/backslash survive as an escape
// once decoded), with only the chars that would end the HTML attribute
// entity-escaped on top.
function jsq(s){
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\r/g, '\\r').replace(/\n/g, '\\n')
    .replace(/</g, '\\x3C').replace(/>/g, '\\x3E')
    .replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}
function errorBanner(msg){ return `<div class="banner danger">${esc(msg)}</div>`; }
// This app re-renders a view by replacing its innerHTML wholesale on any
// state change (see render()) — fine for clicks, but a live-filter text
// input loses focus and cursor position on every keystroke unless we
// explicitly restore both after the re-render.
function liveFilter(inputEl, stateKey){
  const id = inputEl.id, pos = inputEl.selectionStart;
  state[stateKey] = inputEl.value;
  render();
  const el = document.getElementById(id);
  if(el){ el.focus(); el.setSelectionRange(pos, pos); }
}
