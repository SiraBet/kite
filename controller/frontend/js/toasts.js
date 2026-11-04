/*
 * Transient notifications and the confirm modal.
 */
/* ============================== TOASTS & CONFIRM MODAL ============================== */
function toast(message, tone='neutral', ms=3200){
  const stack = document.getElementById('toast-stack');
  const el = document.createElement('div');
  el.className = `toast ${tone}`;
  el.textContent = message;
  stack.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 200);
  }, ms);
}
// Promise-based replacement for window.confirm() — same call shape (await
// it, get a boolean back) but styled to match the rest of the app instead
// of popping the browser's native dialog.
// typeToConfirm: for what can't be undone -- the confirm button stays off
// until that exact text (a machine's name) is typed.
// `inputs`: optional fields asked for in the dialog, [{id, label,
// placeholder, required}]. With them, confirming resolves to {id: value}
// rather than true; cancelling is still false.
function confirmDialog({title, message, confirmLabel='Confirm', danger=false, typeToConfirm='', inputs=[]}){
  return new Promise(resolve => {
    const root = document.getElementById('modal-root');
    function close(result){
      if(result && inputs.length){
        result = {};
        for(const f of inputs) result[f.id] = root.querySelector(`#confirm-in-${f.id}`).value.trim();
      }
      root.innerHTML=''; document.removeEventListener('keydown', onKey); resolve(result);
    }
    function onKey(e){ if(e.key==='Escape') close(false); }
    // The confirm button waits for the typed confirmation and every required field.
    window.__checkConfirm = () => {
      const typed = root.querySelector('#confirm-typed');
      const ready = (!typed || typed.value === typeToConfirm)
        && inputs.every(f => !f.required || root.querySelector(`#confirm-in-${f.id}`).value.trim());
      root.querySelector('#confirm-go').disabled = !ready;
    };
    document.addEventListener('keydown', onKey);
    const waits = typeToConfirm || inputs.some(f => f.required);
    root.innerHTML = `
      <div class="modal-backdrop" onclick="if(event.target===this) window.__closeConfirm(false)">
        <div class="modal">
          <p class="modal-title">${esc(title)}</p>
          <p class="modal-message">${esc(message)}</p>
          ${inputs.map(f => `<label class="modal-message" style="display:block;margin-top:8px">${esc(f.label)}
            <input id="confirm-in-${esc(f.id)}" autocomplete="off" placeholder="${esc(f.placeholder||'')}" style="width:100%;margin-top:4px" oninput="window.__checkConfirm()"></label>`).join('')}
          ${typeToConfirm ? `<p class="modal-message" style="margin-top:8px">Type <strong class="mono">${esc(typeToConfirm)}</strong> to confirm.</p>
            <input id="confirm-typed" autocomplete="off" style="width:100%;margin-bottom:12px" oninput="window.__checkConfirm()">` : ''}
          <div class="modal-actions">
            <button onclick="window.__closeConfirm(false)">Cancel</button>
            <button id="confirm-go" ${waits ? 'disabled' : ''} class="${danger?'':'primary'}" style="${danger?'background:var(--danger-bg);border-color:var(--danger);color:var(--danger)':''}" onclick="window.__closeConfirm(true)">${esc(confirmLabel)}</button>
          </div>
        </div>
      </div>`;
    window.__closeConfirm = close;
    (inputs.length ? root.querySelector(`#confirm-in-${inputs[0].id}`)
      : typeToConfirm ? root.querySelector('#confirm-typed')
      : root.querySelector('.modal-actions button.primary, .modal-actions button:last-child')).focus();
  });
}
// Off by default (matches app/settings_store.py's DEFAULTS) -- only 'true'
// (settings loaded and explicitly turned on) shows the Ticket step.
function requireTicket(){ return !!state.settings && state.settings.require_ticket === 'true'; }
