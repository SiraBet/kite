/*
 * Session bootstrap, the login view, and hash-based route restoration.
 */
/* ============================== AUTH / LOGIN ============================== */
async function checkAuth(){
  try{
    state.user = await api.me();
  }catch(e){
    state.user = null;
  }
  state.authChecked = true;
  render();
  if(state.user){
    loadDashboard();
    loadChecklistItems();
    await restoreFromHash();
  }
}
// The browser's Back/Forward change the hash; follow them. The app's own
// navigation writes the hash too (setHash), and is already where it points.
function setHash(h){
  state.__routedHash = h ? '#' + h : '';
  location.hash = h;
}
window.addEventListener('hashchange', () => {
  if(!state.user || location.hash === state.__routedHash) return;
  restoreFromHash();
});
async function restoreFromHash(){
  state.__routedHash = location.hash;
  const runMatch = location.hash.match(/^#run\/(job|host|batch)\/(\d+)$/);
  const hostDetailMatch = location.hash.match(/^#h\/(\d+)$/);
  const tabMatch = location.hash.match(/^#(home|fleet|topology|defs|scripts|schedules|audit|settings)$/);

  if(tabMatch){
    navigate(tabMatch[1]);
    return;
  }
  if(hostDetailMatch){
    await openHostDetail(parseInt(hostDetailMatch[1], 10));
    return;
  }
  if(!runMatch) return;

  const [, kind, idStr] = runMatch;
  const id = parseInt(idStr, 10);
  state.nav = 'run';
  if(state.defs===null) loadDefs();

  if(kind === 'job'){
    try{
      const job = await api.getRun(id);
      let host = null;
      try{ host = await api.getHost(job.host_id); }catch(e){ /* still show progress even if host details fail */ }
      state.run = { step: stepIndex('progress'), host, ticketId: job.ticket_id||'', ticketInfo:null,
        ticketError:'', windowOverrideReason:'', checklist:(state.checklistItems||[]).map(()=>true),
        jobId: job.id, job, pollHandle:null, familyScripts:null };
      render();
      if(job.status==='running' || job.status==='queued') pollRun();
    }catch(e){
      setHash('');
      state.loadError = `Couldn't restore run: ${e.message}`;
    }
  } else if(kind === 'batch'){
    try{
      const batch = await api.getBatch(id);
      if(state.run && state.run.pollHandle) clearInterval(state.run.pollHandle);
      state.run = { step: 0, host: null, hosts: null, batchId: batch.id, batch, jobId: null, job: null, pollHandle: null,
        checklist: [], ticketId: '', ticketInfo: null };
      render();
      if(batch.status === 'running' || batch.status === 'paused' || (batch.status === 'stopped' && !batch.finished_at)) pollBatch();
    }catch(e){
      setHash('');
      state.loadError = `Couldn't open batch: ${e.message}`;
    }
  } else if(kind === 'host'){
    try{
      const host = await api.getHost(id);
      startRun(host.id, host);
    }catch(e){
      setHash('');
    }
  }
  render();
}
async function doLogin(){
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  state.loginError = '';
  try{
    state.user = await api.login(username, password);
    render();
    loadDashboard();
    loadChecklistItems();
  }catch(e){
    state.loginError = e.message;
    render();
  }
}
// Every interval polling the API. Signed out, they'd only collect 401s.
function stopPolls(){
  if(state.run && state.run.pollHandle){ clearInterval(state.run.pollHandle); state.run.pollHandle = null; }
  if(state.addMachine && state.addMachine.pollHandle){ clearInterval(state.addMachine.pollHandle); state.addMachine.pollHandle = null; }
}
async function doLogout(){
  stopPolls();
  try{ await api.logout(); }catch(e){}
  // A fresh page: nothing loaded for the last user (tokens, lists, a run
  // in progress) survives into the next one's session.
  setHash('');
  location.reload();
  state.user = null;
  state.nav = 'home';
  render();
}
function renderLogin(){
  return `
    <div class="login-page">
      <div class="login-card">
        <div class="login-brand">
          <div class="brand-mark" style="background-color:#101619;border-radius:7px;background-size:22px"></div>
          <span class="login-brand-name">kite</span>
          <span class="login-env">${esc(window.location.host)}</span>
        </div>
        <div class="login-title">Sign in to the console</div>
        <div class="login-sub">You'll land on a read-only overview. Nothing runs until you confirm it.</div>
        ${state.loginError ? errorBanner(state.loginError) : ''}
        <div style="display:flex;flex-direction:column;gap:13px">
          <div>
            <label class="login-label" for="login-username">Username</label>
            <input id="login-username" style="width:100%" placeholder="your username" onkeydown="if(event.key==='Enter')doLogin()" autofocus>
          </div>
          <div>
            <label class="login-label" for="login-password">Password</label>
            <div style="position:relative">
              <input id="login-password" type="password" style="width:100%;padding-right:54px" placeholder="password" onkeydown="if(event.key==='Enter')doLogin()">
              <span onclick="toggleLoginPassword(this)" style="position:absolute;right:11px;top:50%;transform:translateY(-50%);font-size:11px;font-weight:600;color:var(--accent);cursor:pointer">Show</span>
            </div>
          </div>
          <button class="primary" style="height:40px;margin-top:2px" onclick="doLogin()">Continue</button>
        </div>
        <div class="login-foot">
          <span class="dot"></span>
          <span class="msg">Controller reachable — services operational</span>
        </div>
        <p class="login-form-hint">First run? The controller prints a one-time admin password to its startup log (<code>journalctl -u kite-controller</code>).</p>
      </div>
    </div>`;
}
// After signing in with a password an admin set (a reset, a new account,
// the first-run admin): choose your own before anything else. The server
// refuses every other request until this is done.
function renderChoosePassword(){
  return `
    <div class="login-page">
      <div class="login-card">
        <div class="login-brand">
          <div class="brand-mark" style="background-color:#101619;border-radius:7px;background-size:22px"></div>
          <span class="login-brand-name">kite</span>
          <span class="login-env">${esc(window.location.host)}</span>
        </div>
        <div class="login-title">Choose your password</div>
        <div class="login-sub">Signed in as <strong>${esc(state.user.username)}</strong> with a password someone else set. Pick your own to continue — at least 12 characters.</div>
        ${state.choosePasswordError ? errorBanner(state.choosePasswordError) : ''}
        <div style="display:flex;flex-direction:column;gap:13px">
          <div>
            <label class="login-label" for="cp-current">Password you signed in with</label>
            <input id="cp-current" type="password" style="width:100%" autocomplete="current-password" autofocus>
          </div>
          <div>
            <label class="login-label" for="cp-new">New password</label>
            <input id="cp-new" type="password" style="width:100%" autocomplete="new-password" onkeydown="if(event.key==='Enter')doChoosePassword()">
          </div>
          <div>
            <label class="login-label" for="cp-confirm">New password again</label>
            <input id="cp-confirm" type="password" style="width:100%" autocomplete="new-password" onkeydown="if(event.key==='Enter')doChoosePassword()">
          </div>
          <button class="primary" style="height:40px;margin-top:2px" onclick="doChoosePassword()">Set password and continue</button>
          <a href="#" style="font-size:12px;text-align:center" onclick="doLogout();return false">Sign out instead</a>
        </div>
      </div>
    </div>`;
}
async function doChoosePassword(){
  const val = id => (document.getElementById(id) || {}).value || '';
  const current = val('cp-current'), next = val('cp-new'), again = val('cp-confirm');
  state.choosePasswordError = '';
  if(next.length < 12) state.choosePasswordError = 'The new password needs at least 12 characters.';
  else if(next !== again) state.choosePasswordError = 'The two new passwords don’t match.';
  else if(next === current) state.choosePasswordError = 'Choose a password different from the one you signed in with.';
  if(state.choosePasswordError){ render(); return; }
  try{
    await api.changePassword(current, next);
    state.user.must_change_password = false;
    render();
    loadDashboard();
    loadChecklistItems();
    toast('Password set.', 'success');
  }catch(e){ state.choosePasswordError = e.message; render(); }
}
function toggleLoginPassword(el){
  const inp = document.getElementById('login-password');
  if(inp.type==='password'){ inp.type='text'; el.textContent='Hide'; }
  else { inp.type='password'; el.textContent='Show'; }
}
