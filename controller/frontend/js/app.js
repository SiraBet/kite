/*
 * Render root and boot. Loaded last: it calls into every view above.
 */
/* ============================== RENDER ROOT ============================== */
function render(){
  const choosing = !!(state.user && state.user.must_change_password);
  document.querySelector('.app').classList.toggle('pre-auth', !state.user || choosing);
  renderNav();
  renderUserBox();
  const main = document.querySelector('.main');
  if(main) main.classList.toggle('wide', state.nav === 'topology');   // the map uses the whole width
  const view = document.getElementById('view');
  if(!state.authChecked){ view.innerHTML = ''; return; }
  if(!state.user){ view.innerHTML = renderLogin(); return; }
  // Signed in with a password someone else chose: nothing else until they pick their own.
  if(choosing){ view.innerHTML = renderChoosePassword(); return; }

  if(state.nav==='home') view.innerHTML = renderHome();
  else if(state.nav==='fleet') view.innerHTML = state.fleetSection==='coverage' ? renderCoverage()
    : state.fleetSection==='vulns' ? renderFleetVulns() : renderFleet();
  else if(state.nav==='topology'){ view.innerHTML = renderTopology(); topoAfterRender(); }
  else if(state.nav==='host') view.innerHTML = renderHostDetail();
  else if(state.nav==='run') view.innerHTML = renderRun();
  else if(state.nav==='defs') view.innerHTML = renderDefs();
  else if(state.nav==='scripts') view.innerHTML = renderScripts();
  else if(state.nav==='schedules') view.innerHTML = renderSchedules();
  else if(state.nav==='audit') view.innerHTML = renderAudit();
  else if(state.nav==='settings') view.innerHTML = renderSettings();
}
render();
(async () => {
  await preloadSettingsQuietly();
  await checkAuth();
})();
// Skip the periodic fleet refresh while the Add-machine drawer is open —
// a full re-render there would flicker the panel and drop input focus.
setInterval(() => { if(state.user && state.nav==='fleet' && !state.addMachine) loadFleet(); }, 30000);
// A background tab's timers are throttled, so its list can be minutes old
// when you come back to it: fetch again as soon as it's visible.
document.addEventListener('visibilitychange', () => {
  if(document.visibilityState === 'visible' && state.user && (state.nav === 'fleet' || state.nav === 'host')) loadFleet();
});
