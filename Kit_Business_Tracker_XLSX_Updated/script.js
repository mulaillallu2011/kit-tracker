/* =========================================================
   APPEARANCE
========================================================= */
(function(){
  const savedTheme = localStorage.getItem('kit-tracker-theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initialTheme = savedTheme || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', initialTheme);

  window.toggleAppearance = function(){
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('kit-tracker-theme', next);
    window.updateAppearanceButton?.();
  };

  window.updateAppearanceButton = function(){
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const text = document.getElementById('appearanceText');
    const state = document.getElementById('appearanceState');
    if(text) text.textContent = dark ? 'Light mode' : 'Dark mode';
    if(state) state.textContent = dark ? 'ON' : 'OFF';
  };
})();


/* =========================================================
   AUTHENTICATION
========================================================= */
const ACCOUNT_KEY='kit-tracker-accounts-v3';
const SECURITY_KEY='kit-tracker-security-v3';
const AUDIT_KEY='kit-tracker-audit-v3';

// Login protection: after 3 failed attempts, temporarily lock sign-in.
// The lockout increases on repeated failed cycles.
const MAX_FAILED=3;
const LOCKOUT_STEPS=[15,30,60,300];
let loginLockTimer=null;

const DEFAULT_ACCOUNTS={
  admin:{id:'admin',username:'admin',name:'Administrator',role:'administrator',passwordHash:'',active:true},
  operators:[],
  requests:[]
};

let ACCOUNTS=loadAccounts();
let currentRole=sessionStorage.getItem('kit-tracker-role')||null;
let currentUserId=sessionStorage.getItem('kit-tracker-user-id')||null;
let idleTimer=null;

function loadAccounts(){
  try{
    const saved=JSON.parse(localStorage.getItem(ACCOUNT_KEY)||'null');
    if(saved && saved.admin){
      if(!Array.isArray(saved.operators)) saved.operators=[];
      if(!Array.isArray(saved.requests)) saved.requests=[];
      saved.operators.forEach(o=>{
        if(!o.accessRole)o.accessRole='viewer';
        if(!o.role)o.role='operator';
      });
      return saved;
    }
  }catch(e){}
  return JSON.parse(JSON.stringify(DEFAULT_ACCOUNTS));
}
function saveAccounts(){localStorage.setItem(ACCOUNT_KEY,JSON.stringify(ACCOUNTS));}
function isAdmin(){return currentRole==='administrator';}

function currentAccount(){
  return allAccounts().find(a=>a.id===currentUserId) || null;
}

function accessLevel(){
  if(isAdmin())return 'admin';
  const account=currentAccount();
  return account?.accessRole || 'viewer';
}

function canEdit(){
  return isAdmin() || accessLevel()==='editor';
}

function canDelete(){
  return isAdmin();
}

function accessLabel(level){
  if(level==='admin')return 'Administrator';
  if(level==='editor')return 'Editor';
  return 'Viewer';
}

function allAccounts(){return [ACCOUNTS.admin,...(ACCOUNTS.operators||[])];}
function getSecurity(){
  try{
    const saved=JSON.parse(localStorage.getItem(SECURITY_KEY)||'null');
    if(saved)return saved;
  }catch(e){}
  return {failed:0,lockedUntil:0,lastLogin:null};
}
function saveSecurity(v){localStorage.setItem(SECURITY_KEY,JSON.stringify(v));}
function getAudit(){
  try{
    const v=JSON.parse(localStorage.getItem(AUDIT_KEY)||'[]');
    return Array.isArray(v)?v:[];
  }catch(e){return [];}
}
function audit(action,details=''){
  try{
    const logs=getAudit();
    logs.unshift({
      time:new Date().toISOString(),
      user:currentUserId||'unknown',
      action,
      details:String(details).slice(0,160)
    });
    localStorage.setItem(AUDIT_KEY,JSON.stringify(logs.slice(0,200)));
  }catch(e){}
}
async function hashPassword(password){
  const bytes=new TextEncoder().encode(password);
  const hash=await crypto.subtle.digest('SHA-256',bytes);
  return Array.from(new Uint8Array(hash)).map(x=>x.toString(16).padStart(2,'0')).join('');
}
function validPassword(p){return typeof p==='string' && p.length>=8;}
function adminNeedsSetup(){return !ACCOUNTS.admin.passwordHash;}
function lockedNow(){return Number(getSecurity().lockedUntil||0)>Date.now();}

function clearLoginLockTimer(){
  if(loginLockTimer){
    clearInterval(loginLockTimer);
    loginLockTimer=null;
  }
}

function formatLockTime(seconds){
  const s=Math.max(0,Math.ceil(seconds));
  if(s<60)return `${s} second${s===1?'':'s'}`;
  const mins=Math.ceil(s/60);
  return `${mins} minute${mins===1?'':'s'}`;
}

function startLoginLockCountdown(error){
  clearLoginLockTimer();
  const tick=()=>{
    const lockedUntil=Number(getSecurity().lockedUntil||0);
    const remaining=Math.ceil((lockedUntil-Date.now())/1000);
    if(remaining<=0){
      clearLoginLockTimer();
      const sec=getSecurity();
      sec.lockedUntil=0;
      saveSecurity(sec);
      error.textContent='Login unlocked. You can try again.';
      return;
    }
    error.textContent=`Login locked. Try again in ${formatLockTime(remaining)}.`;
    error.style.display='block';
  };
  tick();
  loginLockTimer=setInterval(tick,250);
}

function startIdleTimer(){
  if(!currentRole)return;
  if(idleTimer)clearTimeout(idleTimer);
  idleTimer=setTimeout(()=>{
    if(currentRole){
      audit('Auto logout','20 minute inactivity timeout');
      logoutUser(true);
    }
  },20*60*1000);
}


function loginMarkup(){
  const setup=adminNeedsSetup();
  return `
    <div class="auth-screen">
      <div class="auth-card">
        <section class="auth-brand">
          <div class="brand-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">
              <rect x="4" y="4" width="16" height="16" rx="3"/>
              <circle cx="8" cy="8" r="1" fill="currentColor"/>
              <circle cx="16" cy="8" r="1" fill="currentColor"/>
              <circle cx="8" cy="16" r="1" fill="currentColor"/>
              <circle cx="16" cy="16" r="1" fill="currentColor"/>
            </svg>
          </div>
          <h1>Kit Business Tracker</h1>
          <p>${setup?'Create your administrator password to begin.':'Sign in to your secure kit business workspace.'}</p>
          <div class="auth-features">
            <div class="auth-feature">✓ Administrator & operator access</div>
            <div class="auth-feature">✓ Login protection</div>
            <div class="auth-feature">✓ Activity tracking</div>
          </div>
        </section>

        <section class="auth-form-wrap">
          <div class="auth-theme-row">
            <button class="auth-theme" type="button" id="authThemeBtn">🌙 Dark mode</button>
          </div>
          <h2>${setup?'Administrator setup':'Welcome back'}</h2>
          <div class="auth-subtitle">${setup?'The old default password has been removed. Choose a new password.':'Choose your account type and sign in.'}</div>

          <div class="role-switch">
            <button type="button" class="role-btn active" data-role="administrator">Administrator</button>
            <button type="button" class="role-btn" data-role="user" ${setup?'disabled':''}>Operator</button>
          </div>

          <form id="loginForm">
            <div class="auth-field">
              <label>Username</label>
              <input id="loginUsername" name="username" type="text" required value="${setup?'admin':''}" ${setup?'readonly':''} placeholder="Enter username">
            </div>
            <div class="auth-field">
              <label>${setup?'Create password':'Password'}</label>
              <div class="password-wrap">
                <input id="loginPassword" name="password" type="password" required placeholder="Minimum 8 characters">
                <button class="password-toggle" type="button" id="passwordToggle">Show</button>
              </div>
            </div>
            <div class="auth-error" id="loginError"></div>
            <button type="submit" class="btn btn-primary auth-submit">${setup?'Create administrator':'Sign in'}</button>
            ${setup ? '' : '<button type="button" class="auth-register-link" id="registerAccountBtn">Register a new account</button><button type="button" class="auth-register-link" id="forgotPasswordBtn">Forgot password?</button>'}
          </form>

          <div class="auth-demo">
            ${setup?'<b>First-time setup</b><br>Username: <span class="mono">admin</span><br>Create your own password now.':
              '<b>Account management</b><br>Operators are created by the Administrator.'}
          </div>
        </section>
      </div>
    </div>`;
}


function registrationMarkup(){
  return `
    <div class="auth-screen">
      <div class="auth-card">
        <section class="auth-brand">
          <div class="brand-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">
              <circle cx="9" cy="8" r="4"/>
              <path d="M3 21c0-4.4 2.7-7 6-7s6 2.6 6 7"/>
              <path d="M18 8v6M15 11h6"/>
            </svg>
          </div>
          <h1>Register Account</h1>
          <p>Create a User account request. An Administrator must approve it before login access is enabled.</p>
          <div class="auth-features">
            <div class="auth-feature">✓ Admin approval required</div>
            <div class="auth-feature">✓ Password is protected</div>
            <div class="auth-feature">✓ Account can be disabled later</div>
          </div>
        </section>

        <section class="auth-form-wrap">
          <div class="auth-theme-row">
            <button class="auth-theme" type="button" id="registerThemeBtn">🌙 Dark mode</button>
          </div>

          <h2>Request an account</h2>
          <div class="auth-subtitle">Enter your details and submit the request.</div>

          <form id="registerForm">
            <div class="auth-field">
              <label>Full name</label>
              <input name="name" type="text" required autocomplete="name" placeholder="Your full name">
            </div>

            <div class="auth-field">
              <label>Username</label>
              <input name="username" type="text" required autocomplete="username" placeholder="Choose a username">
            </div>

            <div class="auth-field">
              <label>Contact</label>
              <input name="contact" type="text" required placeholder="Phone or email">
            </div>

            <div class="auth-field">
              <label>Password</label>
              <div class="password-wrap">
                <input id="registerPassword" name="password" type="password" required minlength="8" autocomplete="new-password" placeholder="Minimum 8 characters">
                <button class="password-toggle" type="button" id="registerPasswordToggle">Show</button>
              </div>
            </div>

            <div class="auth-error" id="registerError"></div>

            <div class="register-info">
              Your account will remain <b>Pending</b> until the Administrator approves the request.
            </div>

            <button class="btn btn-primary auth-submit" type="submit">Submit registration</button>
            <button class="auth-register-link" type="button" id="backToLoginBtn">← Back to login</button>
          </form>
        </section>
      </div>
    </div>`;
}

function showRegistration(){
  document.body.classList.add('auth-locked');

  let overlay=document.getElementById('authOverlay');
  if(!overlay){
    overlay=document.createElement('div');
    overlay.id='authOverlay';
    overlay.className='auth-overlay';
    document.body.appendChild(overlay);
  }

  overlay.innerHTML=registrationMarkup();

  const themeBtn=overlay.querySelector('#registerThemeBtn');
  const updateTheme=()=>{
    const dark=document.documentElement.getAttribute('data-theme')==='dark';
    themeBtn.textContent=dark?'☀️ Light mode':'🌙 Dark mode';
  };
  updateTheme();

  themeBtn.addEventListener('click',()=>{
    window.toggleAppearance();
    updateTheme();
  });

  overlay.querySelector('#registerPasswordToggle').addEventListener('click',()=>{
    const input=overlay.querySelector('#registerPassword');
    const show=input.type==='password';
    input.type=show?'text':'password';
    overlay.querySelector('#registerPasswordToggle').textContent=show?'Hide':'Show';
  });

  overlay.querySelector('#backToLoginBtn').addEventListener('click',showLogin);

  overlay.querySelector('#registerForm').addEventListener('submit',async e=>{
    e.preventDefault();

    const fd=new FormData(e.currentTarget);
    const name=String(fd.get('name')||'').trim();
    const username=String(fd.get('username')||'').trim();
    const contact=String(fd.get('contact')||'').trim();
    const password=String(fd.get('password')||'');

    const error=overlay.querySelector('#registerError');

    error.style.display='none';

    if(!name || !username || !contact){
      error.textContent='Please complete all required fields.';
      error.style.display='block';
      return;
    }

    if(!validPassword(password)){
      error.textContent='Password must contain at least 8 characters.';
      error.style.display='block';
      return;
    }

    const lower=username.toLowerCase();

    if(allAccounts().some(a=>String(a.username||'').toLowerCase()===lower)){
      error.textContent='That username is already registered.';
      error.style.display='block';
      return;
    }

    if((ACCOUNTS.requests||[]).some(r=>r.status==='pending' && String(r.username||'').toLowerCase()===lower)){
      error.textContent='A registration request with that username is already pending.';
      error.style.display='block';
      return;
    }

    ACCOUNTS.requests.push({
      id:'req-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,6),
      name,
      username,
      contact,
      role:'operator',
      passwordHash:await hashPassword(password),
      requestedAt:new Date().toISOString(),
      status:'pending'
    });

    saveAccounts();

    overlay.innerHTML=`
      <div class="auth-screen">
        <div class="auth-card">
          <section class="auth-brand">
            <div class="brand-icon">✓</div>
            <h1>Request Submitted</h1>
            <p>Your registration has been sent to the Administrator for approval.</p>
          </section>
          <section class="auth-form-wrap">
            <h2>Waiting for approval</h2>
            <div class="auth-subtitle">You cannot sign in until the Administrator approves this account.</div>
            <div class="operator-success" style="display:flex;">
              <span>✓</span>
              <span>Your request for <b>@${escapeHtml(username)}</b> is pending.</span>
            </div>
            <button class="auth-register-link" type="button" id="submittedBack">← Back to login</button>
          </section>
        </div>
      </div>`;
    overlay.querySelector('#submittedBack').addEventListener('click',showLogin);
  });
}


function showForgotPassword(){
  document.body.classList.add('auth-locked');
  let overlay=document.getElementById('authOverlay');
  if(!overlay){
    overlay=document.createElement('div'); overlay.id='authOverlay'; overlay.className='auth-overlay'; document.body.appendChild(overlay);
  }
  overlay.innerHTML=`<div class="auth-screen"><div class="auth-card"><section class="auth-brand"><div class="brand-icon">?</div><h1>Reset your password</h1><p>Use your registered username and contact detail to create a new password.</p><div class="auth-features"><div class="auth-feature">✓ Username verification</div><div class="auth-feature">✓ Contact verification</div><div class="auth-feature">✓ Password is re-hashed</div></div></section><section class="auth-form-wrap"><div class="auth-theme-row"><button class="auth-theme" type="button" id="forgotThemeBtn">🌙 Dark mode</button></div><h2>Password recovery</h2><div class="auth-subtitle">This browser-based recovery only works with information already stored in this tracker.</div><form id="forgotForm"><div class="auth-field"><label>Username</label><input name="username" required autocomplete="username"></div><div class="auth-field"><label>Registered contact</label><input name="contact" required placeholder="Phone or email"></div><div class="auth-field"><label>New password</label><div class="password-wrap"><input name="password" id="forgotPassword" type="password" required minlength="8"><button class="password-toggle" type="button" id="forgotToggle">Show</button></div></div><div class="auth-field"><label>Confirm new password</label><input name="confirm" type="password" required minlength="8"></div><div class="auth-error" id="forgotError"></div><button class="btn btn-primary auth-submit" type="submit">Reset password</button><button class="auth-register-link" type="button" id="forgotBack">← Back to login</button></form></section></div></div>`;
  const themeBtn=overlay.querySelector('#forgotThemeBtn');
  const update=()=>{const d=document.documentElement.getAttribute('data-theme')==='dark'; themeBtn.textContent=d?'☀️ Light mode':'🌙 Dark mode';}; update();
  themeBtn.addEventListener('click',()=>{window.toggleAppearance();update();});
  overlay.querySelector('#forgotToggle').addEventListener('click',()=>{const i=overlay.querySelector('#forgotPassword');i.type=i.type==='password'?'text':'password';overlay.querySelector('#forgotToggle').textContent=i.type==='password'?'Show':'Hide';});
  overlay.querySelector('#forgotBack').addEventListener('click',showLogin);
  overlay.querySelector('#forgotForm').addEventListener('submit',async e=>{
    e.preventDefault();
    const fd=new FormData(e.currentTarget), username=String(fd.get('username')||'').trim(), contact=String(fd.get('contact')||'').trim(), next=String(fd.get('password')||''), confirm=String(fd.get('confirm')||'');
    const error=overlay.querySelector('#forgotError'); error.style.display='none';
    const account=allAccounts().find(a=>String(a.username||'').toLowerCase()===username.toLowerCase() && String(a.contact||'').trim().toLowerCase()===contact.toLowerCase() && a.active!==false);
    if(!account){error.textContent='Username and registered contact did not match an active account.';error.style.display='block';return;}
    if(!validPassword(next)){error.textContent='New password must contain at least 8 characters.';error.style.display='block';return;}
    if(next!==confirm){error.textContent='Passwords do not match.';error.style.display='block';return;}
    account.passwordHash=await hashPassword(next); saveAccounts(); audit('Password recovery',username); overlay.remove(); document.body.classList.remove('auth-locked'); alert('Password reset successfully. You can now sign in.'); showLogin();
  });
}

function showLogin(){
  clearLoginLockTimer();
  document.body.classList.add('auth-locked');

  let overlay=document.getElementById('authOverlay');
  if(!overlay){
    overlay=document.createElement('div');
    overlay.id='authOverlay';
    overlay.className='auth-overlay';
    document.body.appendChild(overlay);
  }
  overlay.innerHTML=loginMarkup();

  let selectedRole='administrator';
  const themeBtn=overlay.querySelector('#authThemeBtn');
  const error=overlay.querySelector('#loginError');

  const updateTheme=()=>{
    const dark=document.documentElement.getAttribute('data-theme')==='dark';
    themeBtn.textContent=dark?'☀️ Light mode':'🌙 Dark mode';
  };
  updateTheme();

  themeBtn.addEventListener('click',()=>{
    window.toggleAppearance();
    updateTheme();
  });

  overlay.querySelectorAll('[data-role]').forEach(btn=>{
    btn.addEventListener('click',()=>{
      if(btn.disabled)return;
      selectedRole=btn.dataset.role;
      overlay.querySelectorAll('[data-role]').forEach(b=>b.classList.toggle('active',b.dataset.role===selectedRole));
      overlay.querySelector('#loginUsername').value='';
      overlay.querySelector('#loginPassword').value='';
      error.style.display='none';
    });
  });

  overlay.querySelector('#passwordToggle').addEventListener('click',()=>{
    const input=overlay.querySelector('#loginPassword');
    input.type=input.type==='password'?'text':'password';
    overlay.querySelector('#passwordToggle').textContent=input.type==='password'?'Show':'Hide';
  });
  const registerAccountBtn=overlay.querySelector('#registerAccountBtn');
  if(registerAccountBtn) registerAccountBtn.addEventListener('click',showRegistration);
  const forgotPasswordBtn=overlay.querySelector('#forgotPasswordBtn');
  if(forgotPasswordBtn) forgotPasswordBtn.addEventListener('click',showForgotPassword);

  overlay.querySelector('#loginForm').addEventListener('submit',async e=>{
    e.preventDefault();
    const username=overlay.querySelector('#loginUsername').value.trim();
    const password=overlay.querySelector('#loginPassword').value;

    if(lockedNow()){
      startLoginLockCountdown(error);
      return;
    }

    if(adminNeedsSetup()){
      if(selectedRole!=='administrator' || username!=='admin'){
        error.textContent='Complete administrator setup first.';
        error.style.display='block';
        return;
      }
      if(!validPassword(password)){
        error.textContent='Password must contain at least 8 characters.';
        error.style.display='block';
        return;
      }

      ACCOUNTS.admin.passwordHash=await hashPassword(password);
      saveAccounts();
      currentRole='administrator';
      currentUserId='admin';
      sessionStorage.setItem('kit-tracker-role',currentRole);
      sessionStorage.setItem('kit-tracker-user-id',currentUserId);
      saveSecurity({failed:0,lockedUntil:0,lockoutLevel:0,lastLogin:new Date().toISOString()});
      audit('Initial setup','Administrator password created');

      overlay.remove();
      document.body.classList.remove('auth-locked');
      await loadAll();
      render();
      window.updateAppearanceButton();
      startIdleTimer();
      return;
    }

    const account=allAccounts().find(a=>
      a.active!==false &&
      a.username===username &&
      ((selectedRole==='administrator' && a.role==='administrator') ||
       (selectedRole==='user' && a.role==='operator'))
    );

    const suppliedHash=await hashPassword(password);

    if(account && account.passwordHash===suppliedHash){
      currentRole=selectedRole;
      currentUserId=account.id;
      sessionStorage.setItem('kit-tracker-role',currentRole);
      sessionStorage.setItem('kit-tracker-user-id',currentUserId);
      saveSecurity({failed:0,lockedUntil:0,lockoutLevel:0,lastLogin:new Date().toISOString()});
      audit('Login','Successful sign in');

      overlay.remove();
      document.body.classList.remove('auth-locked');
      await loadAll();
      render();
      window.updateAppearanceButton();
      startIdleTimer();
      return;
    }

    const sec=getSecurity();
    sec.failed=Number(sec.failed||0)+1;

    if(sec.failed>=MAX_FAILED){
      // lockoutLevel increases each time a complete failed-attempt cycle is reached.
      sec.lockoutLevel=Number(sec.lockoutLevel||0)+1;
      const stepIndex=Math.min(sec.lockoutLevel-1,LOCKOUT_STEPS.length-1);
      const lockSeconds=LOCKOUT_STEPS[stepIndex];
      sec.failed=0;
      sec.lockedUntil=Date.now()+lockSeconds*1000;

      error.textContent=`Too many failed attempts. Login locked for ${formatLockTime(lockSeconds)}.`;
      startLoginLockCountdown(error);
    }else{
      const remaining=MAX_FAILED-sec.failed;
      error.textContent=`Incorrect username or password. ${remaining} attempt${remaining===1?'':'s'} remaining.`;
    }

    saveSecurity(sec);
    audit('Failed login',username);
    error.style.display='block';
  });
}

function logoutUser(auto=false){
  if(currentRole) audit(auto?'Auto logout':'Logout','Session ended');
  if(idleTimer)clearTimeout(idleTimer);
  sessionStorage.removeItem('kit-tracker-role');
  sessionStorage.removeItem('kit-tracker-user-id');
  currentRole=null;
  currentUserId=null;
  showLogin();
}


/* =========================================================
   CONFIG
========================================================= */
const NAV = [
  {id:'dashboard', label:'Dashboard', icon:'grid'},
  {id:'purchases', label:'Purchases', icon:'box'},
  {id:'kits', label:'Kits', icon:'layers'},
  {id:'lp', label:'LP Students', icon:'user'},
  {id:'up', label:'UP Students', icon:'user'},
  {id:'sold', label:'Kits Sold', icon:'tag'},
  {id:'stock', label:'Available Stock', icon:'layers'},
];

const ICONS = {
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.2"/><rect x="14" y="3" width="7" height="7" rx="1.2"/><rect x="3" y="14" width="7" height="7" rx="1.2"/><rect x="14" y="14" width="7" height="7" rx="1.2"/>',
  box:'<path d="M3 8l9-5 9 5-9 5-9-5z"/><path d="M3 8v9l9 5 9-5V8"/><path d="M12 13v9"/>',
  user:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
  tag:'<path d="M20 12l-8 8-9-9V4h7l10 8z"/><circle cx="7.5" cy="7.5" r="1.3" fill="currentColor" stroke="none"/>',
  layers:'<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
};

const INR = new Intl.NumberFormat('en-IN', {style:'currency', currency:'INR', maximumFractionDigits:0});
const fmt = (n)=> INR.format(Number(n)||0);
const uid = ()=> (crypto.randomUUID ? crypto.randomUUID() : 'id-'+Date.now()+Math.random());
const todayStr = ()=> new Date().toISOString().slice(0,10);

/* =========================================================
   STATE
========================================================= */
let state = {
  purchases: [],
  lpStudents: [],
  upStudents: [],
  kitsSold: [],
  kits: [],
};
let currentSection = 'dashboard';
let editingId = {purchases:null, lpStudents:null, upStudents:null, kitsSold:null, kits:null};
let showGuide = true;

const KEYS = {
  purchases:'purchases',
  lpStudents:'lp_students',
  upStudents:'up_students',
  kitsSold:'kits_sold',
  kits:'kits'
};

/* =========================================================
   STORAGE
========================================================= */
async function loadAll(){
  for(const [stateKey, storeKey] of Object.entries(KEYS)){
    try{
      const res = await window.storage.get(storeKey, false);
      state[stateKey] = res ? JSON.parse(res.value) : [];
      if(stateKey==='kits') state.kits = state.kits.map(k=>({...k, items:Array.isArray(k.items)?k.items:[]}));
    }catch(e){
      state[stateKey] = [];
    }
  }
  // first-run seed
  const totalRows = state.purchases.length + state.lpStudents.length + state.upStudents.length + state.kitsSold.length;
  if(totalRows === 0){
    seedSampleData();
    await saveAll();
  }
}

async function save(stateKey){
  try{
    await window.storage.set(KEYS[stateKey], JSON.stringify(state[stateKey]), false);
  }catch(e){
    console.error('Storage error saving', stateKey, e);
  }
}
async function saveAll(){
  for(const k of Object.keys(KEYS)) await save(k);
}

function seedSampleData(){
  state.kits = [
    {id:uid(), name:'Robotics Starter Kit', level:'LP', price:1500, description:'Starter electronics and robotics learning kit', active:true, items:[{name:'Arduino Uno',qty:1},{name:'LED',qty:5},{name:'Resistor Pack',qty:1},{name:'Jumper Wires',qty:1}]},
    {id:uid(), name:'Robotics Starter Kit - UP', level:'UP', price:1800, description:'Upper Primary starter learning kit', active:true, items:[{name:'ESP32 Board',qty:1},{name:'Breadboard',qty:1},{name:'LED',qty:5},{name:'Jumper Wires',qty:1}]},
  ];

  state.purchases = [
    {id:uid(), date:'2026-06-01', item:'Arduino Uno Board', type:'Material', supplier:'Robu.in', qty:20, unitPrice:450, productLink:'https://robu.in/', productDetails:'Arduino Uno board — sample product record.', orderStatus:'Received', orderId:'ROB-001', expectedDate:'2026-06-03', paymentMode:'UPI', refundStatus:'Not applicable'},
    {id:uid(), date:'2026-06-02', item:'Robotics Starter Kit', type:'Finished Kit', supplier:'In-house assembly', qty:15, unitPrice:900, productLink:'', productDetails:'Finished kit assembled in-house.', orderStatus:'Received', orderId:'KIT-001', expectedDate:'2026-06-04', paymentMode:'Cash', refundStatus:'Not applicable'},
  ];
  state.lpStudents = [
    {id:uid(), name:'Aisha Rahman', grade:'Grade 3', contact:'9876543210', admissionDate:'2026-06-05', kit:'Robotics Starter Kit', fee:1500, paid:1000},
  ];
  state.upStudents = [
    {id:uid(), name:'Nihal Thomas', grade:'Grade 6', contact:'9876501234', admissionDate:'2026-06-06', kit:'Robotics Starter Kit', fee:1800, paid:1800},
  ];
  state.kitsSold = [
    {id:uid(), date:'2026-06-10', studentName:'Aisha Rahman', level:'LP', kitName:'Robotics Starter Kit', qty:1, price:1500, paymentMode:'Cash'},
  ];
}

/* =========================================================
   COMPUTATIONS
========================================================= */
function purchaseTotal(p){ return (Number(p.qty)||0) * (Number(p.unitPrice)||0); }
function soldTotal(s){ return (Number(s.qty)||0) * (Number(s.price)||0); }
function balance(s){ return (Number(s.fee)||0) - (Number(s.paid)||0); }
function payStatus(s){
  const fee = Number(s.fee)||0, paid = Number(s.paid)||0;
  if(fee===0 && paid===0) return null;
  if(paid >= fee) return 'Paid';
  if(paid === 0) return 'Unpaid';
  return 'Partial';
}
function statusBadge(status){
  if(status==='Paid') return '<span class="badge badge-green">Paid</span>';
  if(status==='Partial') return '<span class="badge badge-yellow">Partial</span>';
  if(status==='Unpaid') return '<span class="badge badge-red">Unpaid</span>';
  return '<span class="badge badge-grey">—</span>';
}

function kitOptions(){
  return state.kits.filter(k=>k.active!==false).map(k=>k.name).sort();
}

function getKitByName(name){
  return state.kits.find(k=>k.name===name);
}

function findStudentByName(name){
  return [...state.lpStudents, ...state.upStudents].find(s=>s.name===name);
}

function syncStudentIntoSaleForm(studentName){
  const student=findStudentByName(studentName);
  const soldForm=document.getElementById('soldForm');
  if(!soldForm || !student) return;

  const levelField=soldForm.querySelector('[name="level"]');
  const kitField=soldForm.querySelector('[name="kitName"]');

  if(levelField && student.levelCode) levelField.value=student.levelCode;
  else if(levelField){
    levelField.value=state.lpStudents.includes(student)?'LP':'UP';
  }

  if(kitField && student.kit) kitField.value=student.kit;

  const kit=getKitByName(student.kit);
  const priceField=soldForm.querySelector('[name="price"]');
  if(kit && priceField && (!priceField.value || Number(priceField.value)===0)){
    priceField.value=kit.price;
  }

}

function distinctItems(){
  const names = new Set();
  state.purchases.forEach(p=> p.item && names.add(p.item));
  return Array.from(names).sort();
}

function stockRows(){
  return distinctItems().map(name=>{
    const purchRows = state.purchases.filter(p=>p.item===name);
    const type = purchRows[0] ? purchRows[0].type : '';
    const purchasedQty = purchRows.reduce((s,p)=> s+(Number(p.qty)||0),0);
    const purchasedCost = purchRows.reduce((s,p)=> s+purchaseTotal(p),0);
    const soldQty = state.kitsSold.filter(k=>k.kitName===name).reduce((s,k)=> s+(Number(k.qty)||0),0);
    const available = purchasedQty - soldQty;
    const avgCost = purchasedQty>0 ? purchasedCost/purchasedQty : 0;
    return {name, type, purchasedQty, soldQty, available, avgCost, stockValue: available*avgCost};
  });
}

function summaryData(){
  const totalPurchaseCost = state.purchases.reduce((s,p)=> s+purchaseTotal(p),0);
  const lpFeeBilled = state.lpStudents.reduce((s,x)=> s+(Number(x.fee)||0),0);
  const lpFeePaid = state.lpStudents.reduce((s,x)=> s+(Number(x.paid)||0),0);
  const upFeeBilled = state.upStudents.reduce((s,x)=> s+(Number(x.fee)||0),0);
  const upFeePaid = state.upStudents.reduce((s,x)=> s+(Number(x.paid)||0),0);
  const totalFeeBilled = lpFeeBilled + upFeeBilled;
  const totalFeePaid = lpFeePaid + upFeePaid;
  const balanceDue = totalFeeBilled - totalFeePaid;
  const kitsSoldQty = state.kitsSold.reduce((s,k)=> s+(Number(k.qty)||0),0);
  const salesRevenue = state.kitsSold.reduce((s,k)=> s+soldTotal(k),0);
  const stockValue = stockRows().reduce((s,r)=> s+r.stockValue,0);
  const totalIncome = totalFeePaid + salesRevenue;
  const netProfit = totalIncome - totalPurchaseCost;
  return {
    totalPurchaseCost, lpFeeBilled, lpFeePaid, upFeeBilled, upFeePaid,
    totalFeeBilled, totalFeePaid, balanceDue, kitsSoldQty, salesRevenue,
    stockValue, totalIncome, netProfit,
    lpCount: state.lpStudents.length, upCount: state.upStudents.length,
  };
}

/* =========================================================
   NAV RENDER
========================================================= */
function renderNav(){
  const nav = document.getElementById('nav');
  nav.innerHTML = NAV.map(n=>`
    <button class="nav-item ${n.id===currentSection?'active':''}" data-nav="${n.id}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICONS[n.icon]}</svg>
      ${n.label}
    </button>
  `).join('');
  nav.querySelectorAll('[data-nav]').forEach(btn=>{
    btn.addEventListener('click', ()=>{ currentSection = btn.dataset.nav; render(); });
  });
}

/* =========================================================
   MAIN RENDER DISPATCH
========================================================= */
function render(){
  renderNav();
  const main = document.getElementById('main');
  if(currentSection==='dashboard') main.innerHTML = pageDashboard();
  else if(currentSection==='purchases') main.innerHTML = pagePurchases();
  else if(currentSection==='lp') main.innerHTML = pageStudents('lpStudents','LP','Lower Primary');
  else if(currentSection==='up') main.innerHTML = pageStudents('upStudents','UP','Upper Primary');
  else if(currentSection==='sold') main.innerHTML = pageSold();
  else if(currentSection==='stock') main.innerHTML = pageStock();
  else if(currentSection==='kits') main.innerHTML = pageKits();
  attachHandlers();
  attachResetHandler();
}

/* =========================================================
   GUIDE BANNER
========================================================= */
function guideHtml(){
  if(!showGuide) return '';
  return `<div class="guide">
    <b>How this works:</b> log what you buy in <b>Purchases</b>, enroll students in <b>LP</b> or <b>UP Students</b>,
    record every sale in <b>Kits Sold</b> — <b>Available Stock</b> and the <b>Dashboard</b> update on their own.
    <div><button id="hideGuide">Hide this</button></div>
  </div>`;
}

/* =========================================================
   DASHBOARD
========================================================= */

function adminControlHtml(){
  const operators=ACCOUNTS.operators||[];
  const s=summaryData();
  return `
    <div class="admin-panel">
      <div class="admin-panel-head">
        <div>
          <h2>Administrator Control Centre</h2>
          <div style="font-size:11.5px;color:var(--ink-soft);margin-top:3px;">Security, operators, exports and business controls</div>
        </div>
      </div>

      <div class="admin-grid">
        <button class="admin-action" type="button" data-admin-action="add">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="9" cy="8" r="4"/><path d="M3 21c0-4 2.7-6.5 6-6.5s6 2.5 6 6.5"/><path d="M19 8v6M16 11h6"/></svg></span>
          <span class="admin-action-text"><b>Add operator</b><small>Create a new User login</small></span>
        </button>

        <button class="admin-action" type="button" data-admin-action="manage">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="9" cy="8" r="3"/><path d="M3 20c0-4 2.5-6 6-6s6 2 6 6"/><path d="M17 11h4M19 9v4"/></svg></span>
          <span class="admin-action-text"><b>Manage operators</b><small>${operators.length} operator${operators.length===1?'':'s'}</small></span>
        </button>
        <button class="admin-action" type="button" data-admin-action="requests">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 5h16v12H4z"/><path d="M8 9h8M8 13h5"/><path d="m16 20-2.5-3H20"/></svg></span>
          <span class="admin-action-text"><b>Registration requests</b><small>${(ACCOUNTS.requests||[]).filter(r=>r.status==='pending').length} pending approval</small></span>
        </button>

        <button class="admin-action" type="button" data-admin-action="password">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></span>
          <span class="admin-action-text"><b>Change password</b><small>Update administrator password</small></span>
        </button>

        <button class="admin-action" type="button" data-admin-action="calculations">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M5 20V10M12 20V4M19 20v-7"/><path d="M3 20h18"/></svg></span>
          <span class="admin-action-text"><b>Export calculations</b><small>Separate calculation sheet</small></span>
        </button>

        <button class="admin-action" type="button" data-admin-action="report">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M6 3h9l3 3v15H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/></svg></span>
          <span class="admin-action-text"><b>Export full report</b><small>One complete Excel workbook</small></span>
        </button>

        <button class="admin-action" type="button" data-admin-action="backup">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/></svg></span>
          <span class="admin-action-text"><b>Backup data</b><small>Download a readable Excel backup</small></span>
        </button>

        <button class="admin-action" type="button" data-admin-action="security">
          <span class="admin-action-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 3l8 4v5c0 4.8-3.4 7.9-8 9-4.6-1.1-8-4.2-8-9V7l8-4z"/><path d="M9 12l2 2 4-4"/></svg></span>
          <span class="admin-action-text"><b>Security dashboard</b><small>Login protection & audit log</small></span>
        </button>
      </div>

      <div class="admin-kpis" style="margin-top:14px;">
        <div class="admin-kpi"><div class="kpi-label">Income</div><div class="kpi-value">${fmt(s.totalIncome)}</div></div>
        <div class="admin-kpi"><div class="kpi-label">Profit / Loss</div><div class="kpi-value">${fmt(s.netProfit)}</div></div>
        <div class="admin-kpi"><div class="kpi-label">Fees Due</div><div class="kpi-value">${fmt(s.balanceDue)}</div></div>
      </div>
    </div>`;
}

/* =========================================================
   XLSX EXPORT — VALID TEMPLATE + LOCAL JSZip
   The workbook template is generated with a valid Excel structure.
   Current tracker values are injected into the template before download.
========================================================= */
const BACKUP_TEMPLATE_B64 = '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';

const CALCULATIONS_TEMPLATE_B64 = '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';

function xmlEscapeText(value){
  return String(value ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&apos;');
}

function xlsxCellReplace(xml, ref, value, kind='str'){
  const escaped=xmlEscapeText(value);
  // Handle self-closing template cells first; otherwise a broad closing-tag
  // regex could accidentally consume the next cell.
  const selfPattern=new RegExp(`<x:c\\s+([^>]*r="${ref}"[^>]*)\\s*\/\\s*>`, 'm');
  let match=xml.match(selfPattern);
  if(match){
    const attrs=match[1]
      .replace(/\s+t="[^"]*"/g,'')
      .replace(/\s*\/\s*$/,'')
      .trim();
    const tag=`<x:c ${attrs} t="${kind}"><x:v>${escaped}</x:v></x:c>`;
    return xml.replace(match[0],tag);
  }

  const pattern=new RegExp(`<x:c\\s+([^>]*r="${ref}"[^>]*)>([\\s\\S]*?)<\/x:c>`, 'm');
  match=xml.match(pattern);
  if(!match) return xml;
  const attrs=match[1].replace(/\s+t="[^"]*"/g,'').trim();
  const body=kind==='str'
    ? `<x:v>${escaped}</x:v>`
    : `<x:v>${Number.isFinite(Number(value)) ? Number(value) : 0}</x:v>`;
  return xml.replace(match[0], `<x:c ${attrs} t="${kind}">${body}</x:c>`);
}

function xlsxCellBlank(xml, ref){
  const pattern=new RegExp(`<x:c\\s+([^>]*\\br="${ref}"[^>]*)>([\\s\\S]*?)<\\/x:c>`, 'm');
  const selfPattern=new RegExp(`<x:c\\s+([^>]*\\br="${ref}"[^>]*)\\s*\\/\\s*>`, 'm');
  let match=xml.match(pattern);
  if(match){
    const attrs=match[1].replace(/\s+t="[^"]*"/g,'');
    return xml.replace(match[0], `<x:c ${attrs}/>`);
  }
  match=xml.match(selfPattern);
  return xml;
}

function xlsxSetHiddenRow(xml, rowNumber, hidden){
  const pattern=new RegExp(`<x:row\\s+([^>]*\\br="${rowNumber}"[^>]*)>`, 'm');
  return xml.replace(pattern,(full,attrs)=>{
    let cleaned=attrs.replace(/\s+hidden="[^"]*"/g,'');
    return hidden ? `<x:row ${cleaned} hidden="1">` : `<x:row ${cleaned}>`;
  });
}

function xlsxStatusStyle(xml, ref, styleId){
  const pattern=new RegExp(`<x:c\\s+([^>]*\\br="${ref}"[^>]*)>`, 'm');
  return xml.replace(pattern,(full,attrs)=>{
    const updated=attrs.replace(/\s+s="\d+"/g,'') + ` s="${styleId}"`;
    return `<x:c ${updated}>`;
  });
}

function setNumber(xml, ref, value){ return xlsxCellReplace(xml,ref,Number(value)||0,'n'); }
function setString(xml, ref, value){ return xlsxCellReplace(xml,ref,String(value ?? ''),'str'); }

async function buildCalculationsXlsx(){
  if(typeof JSZip==='undefined'){
    throw new Error('The local JSZip library was not loaded. Keep jszip.min.js in the same folder as index.html.');
  }

  const s=summaryData();
  const stock=stockRows();
  const zip=await JSZip.loadAsync(CALCULATIONS_TEMPLATE_B64,{base64:true});
  let xml=await zip.file('xl/worksheets/sheet1.xml').async('string');

  // Meta + KPI values
  xml=setString(xml,'B3',new Date().toLocaleString('en-IN'));
  xml=setNumber(xml,'A6',s.totalIncome);
  xml=setNumber(xml,'C6',s.totalPurchaseCost);
  xml=setNumber(xml,'E6',s.netProfit);

  // Financial table
  const financial={
    B11:s.totalPurchaseCost,
    B12:s.lpFeeBilled,
    B13:s.lpFeePaid,
    B14:s.upFeeBilled,
    B15:s.upFeePaid,
    B16:s.totalFeeBilled,
    B17:s.totalFeePaid,
    B18:s.balanceDue,
    B19:s.kitsSoldQty,
    B20:s.salesRevenue,
    B21:s.stockValue,
    B22:s.totalIncome,
    B23:s.netProfit,
  };
  Object.entries(financial).forEach(([ref,val])=>{ xml=setNumber(xml,ref,val); });

  // Financial statuses
  xml=setString(xml,'D18',s.balanceDue>0?'DUE':'PAID');
  xml=setString(xml,'D23',s.netProfit<0?'LOSS':'PROFIT');
  xml=xlsxStatusStyle(xml,'D18',s.balanceDue>0?109:102);
  xml=xlsxStatusStyle(xml,'D23',s.netProfit<0?90:102);

  // Stock section rows 28-127. Hide unused template rows.
  const maxStockRows=100;
  for(let i=0;i<maxStockRows;i++){
    const row=28+i;
    const item=stock[i];
    if(!item){
      xml=xlsxSetHiddenRow(xml,row,true);
      xml=setString(xml,`A${row}`,'');
      xml=setNumber(xml,`B${row}`,0);
      xml=setNumber(xml,`C${row}`,0);
      xml=setNumber(xml,`D${row}`,0);
      xml=setNumber(xml,`E${row}`,0);
      xml=setNumber(xml,`F${row}`,0);
      xml=setString(xml,`G${row}`,'');
      continue;
    }
    xml=xlsxSetHiddenRow(xml,row,false);
    const status=item.available<=0?'OUT OF STOCK':(item.available<5?'LOW STOCK':'IN STOCK');
    xml=setString(xml,`A${row}`,item.name);
    xml=setNumber(xml,`B${row}`,item.purchasedQty);
    xml=setNumber(xml,`C${row}`,item.soldQty);
    xml=setNumber(xml,`D${row}`,item.available);
    xml=setNumber(xml,`E${row}`,item.avgCost);
    xml=setNumber(xml,`F${row}`,item.stockValue);
    xml=setString(xml,`G${row}`,status);
    const style=status==='IN STOCK'?102:(status==='LOW STOCK'?109:114);
    xml=xlsxStatusStyle(xml,`G${row}`,style);
  }

  // Student fee summary (fixed rows in the template)
  xml=setString(xml,'A132','LP');
  xml=setNumber(xml,'B132',s.lpCount);
  xml=setNumber(xml,'C132',s.lpFeeBilled);
  xml=setNumber(xml,'D132',s.lpFeePaid);
  xml=setNumber(xml,'E132',s.lpFeeBilled-s.lpFeePaid);
  xml=setString(xml,'F132',(s.lpFeeBilled-s.lpFeePaid)>0?'DUE':'PAID');
  xml=xlsxStatusStyle(xml,'F132',(s.lpFeeBilled-s.lpFeePaid)>0?109:102);

  xml=setString(xml,'A133','UP');
  xml=setNumber(xml,'B133',s.upCount);
  xml=setNumber(xml,'C133',s.upFeeBilled);
  xml=setNumber(xml,'D133',s.upFeePaid);
  xml=setNumber(xml,'E133',s.upFeeBilled-s.upFeePaid);
  xml=setString(xml,'F133',(s.upFeeBilled-s.upFeePaid)>0?'DUE':'PAID');
  xml=xlsxStatusStyle(xml,'F133',(s.upFeeBilled-s.upFeePaid)>0?109:102);

  xml=setString(xml,'A134','TOTAL');
  xml=setNumber(xml,'B134',s.lpCount+s.upCount);
  xml=setNumber(xml,'C134',s.totalFeeBilled);
  xml=setNumber(xml,'D134',s.totalFeePaid);
  xml=setNumber(xml,'E134',s.balanceDue);
  xml=setString(xml,'F134',s.balanceDue>0?'DUE':'PAID');
  xml=xlsxStatusStyle(xml,'F134',s.balanceDue>0?109:119);

  // Re-cache key formulas as values are already correct; Excel can recalculate if edited later.
  zip.file('xl/worksheets/sheet1.xml',xml);
  const blob=await zip.generateAsync({type:'blob',compression:'DEFLATE',compressionOptions:{level:6}});
  return blob;
}

async function exportCalculations(){
  try{
    const blob=await buildCalculationsXlsx();
    if(!blob || blob.size<1000) throw new Error('The generated Excel workbook is empty.');
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download='Kit_Business_Calculations.xlsx';
    link.style.display='none';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),10000);
    audit('Export calculations','Formatted Excel XLSX exported');
  }catch(error){
    console.error('XLSX export failed:',error);
    alert('Excel export failed.\n\n'+(error?.message||error));
  }
}

const FULL_REPORT_TEMPLATE_B64='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';

function xlsxColLetter(n){
  let s='';
  while(n>0){
    const r=(n-1)%26;
    s=String.fromCharCode(65+r)+s;
    n=Math.floor((n-1)/26);
  }
  return s;
}

function setRowValues(xml,rowNumber,values){
  values.forEach((value,i)=>{
    const ref=`${xlsxColLetter(i+1)}${rowNumber}`;
    if(typeof value==='number' && Number.isFinite(value)) xml=setNumber(xml,ref,value);
    else xml=setString(xml,ref,value==null?'':value);
  });
  return xml;
}

async function buildFullReportXlsx(){
  if(typeof JSZip==='undefined') throw new Error('The local JSZip library was not loaded. Keep jszip.min.js in the same folder as index.html.');
  const s=summaryData();
  const zip=await JSZip.loadAsync(FULL_REPORT_TEMPLATE_B64,{base64:true});
  let xml=await zip.file('xl/worksheets/sheet1.xml').async('string');

  xml=setString(xml,'B3',new Date().toLocaleString('en-IN'));
  xml=setNumber(xml,'A6',s.totalIncome);
  xml=setNumber(xml,'C6',s.totalPurchaseCost);
  xml=setNumber(xml,'E6',s.netProfit);
  xml=setNumber(xml,'H6',s.stockValue);

  [s.totalIncome,s.totalPurchaseCost,s.netProfit,s.balanceDue,s.stockValue,s.kitsSoldQty,s.lpCount,s.upCount]
    .forEach((v,i)=>{ xml=setNumber(xml,`B${11+i}`,v); });

  function fillSection(startHeaderRow,maxRows,records,width,mapper){
    for(let i=0;i<maxRows;i++){
      const row=startHeaderRow+2+i;
      const rec=records[i];
      if(!rec){
        xml=xlsxSetHiddenRow(xml,row,true);
        for(let c=1;c<=width;c++) xml=setString(xml,`${xlsxColLetter(c)}${row}`,'');
      }else{
        xml=xlsxSetHiddenRow(xml,row,false);
        xml=setRowValues(xml,row,mapper(rec));
      }
    }
  }

  fillSection(21,100,state.purchases,7,p=>[
    p.date||'',p.item||'',p.type||'',p.supplier||'',Number(p.qty||0),Number(p.unitPrice||0),Number(purchaseTotal(p)||0)
  ]);

  fillSection(124,80,state.kits||[],6,k=>[
    k.name||'',k.level||'General',Number(k.price||0),k.active!==false?'ACTIVE':'DISABLED',k.description||'',
    (k.items||[]).length?k.items.map(item=>`${item.name} × ${item.qty}`).join(' | '):'No components added'
  ]);

  fillSection(207,100,state.lpStudents,9,x=>[
    x.name||'',x.grade||'',x.contact||'',x.admissionDate||'',x.kit||'',Number(x.fee||0),Number(x.paid||0),Number(balance(x)||0),payStatus(x)||'—'
  ]);

  fillSection(320,100,state.upStudents,9,x=>[
    x.name||'',x.grade||'',x.contact||'',x.admissionDate||'',x.kit||'',Number(x.fee||0),Number(x.paid||0),Number(balance(x)||0),payStatus(x)||'—'
  ]);

  fillSection(433,100,state.kitsSold,8,x=>[
    x.date||'',x.studentName||'',x.level||'',x.kitName||'',Number(x.qty||0),Number(x.price||0),Number(soldTotal(x)||0),x.paymentMode||''
  ]);

  fillSection(546,100,stockRows(),8,x=>[
    x.name||'',x.type||'',Number(x.purchasedQty||0),Number(x.soldQty||0),Number(x.available||0),Number(x.avgCost||0),Number(x.stockValue||0),
    x.available<=0?'OUT OF STOCK':(x.available<5?'LOW STOCK':'IN STOCK')
  ]);

  zip.file('xl/worksheets/sheet1.xml',xml);
  return await zip.generateAsync({type:'blob',compression:'DEFLATE',compressionOptions:{level:6}});
}

async function exportReport(){
  try{
    const blob=await buildFullReportXlsx();
    if(!blob || blob.size<1000) throw new Error('The generated full report is empty.');
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download='Kit_Business_Full_Report.xlsx';
    link.style.display='none';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),10000);
    audit('Export report','Formatted full business XLSX exported');
  }catch(error){
    console.error('Full report XLSX export failed:',error);
    alert('Full report export failed.\n\n'+(error?.message||error));
  }
}

async function buildBackupXlsx(){
  if(typeof JSZip==='undefined') throw new Error('The local JSZip library was not loaded. Keep jszip.min.js in the same folder as index.html.');
  const zip=await JSZip.loadAsync(BACKUP_TEMPLATE_B64,{base64:true});
  let xml=await zip.file('xl/worksheets/sheet1.xml').async('string');

  xml=setString(xml,'B3',new Date().toLocaleString('en-IN'));

  function fillSection(startHeaderRow,maxRows,records,width,mapper){
    records=Array.isArray(records)?records:[];
    for(let i=0;i<maxRows;i++){
      const row=startHeaderRow+2+i;
      const rec=records[i];
      if(!rec){
        xml=xlsxSetHiddenRow(xml,row,true);
        for(let c=1;c<=width;c++) xml=setString(xml,`${xlsxColLetter(c)}${row}`,'');
      }else{
        xml=xlsxSetHiddenRow(xml,row,false);
        xml=setRowValues(xml,row,mapper(rec));
      }
    }
  }

  fillSection(6,100,state.purchases,7,p=>[
    p.date||'',p.item||'',p.type||'',p.supplier||'',Number(p.qty||0),Number(p.unitPrice||0),Number(purchaseTotal(p)||0)
  ]);

  fillSection(110,80,state.kits||[],6,k=>[
    k.name||'',k.level||'General',Number(k.price||0),k.active!==false?'ACTIVE':'DISABLED',k.description||'',
    (k.items||[]).length?k.items.map(item=>`${item.name} × ${item.qty}`).join(' | '):'No components added'
  ]);

  fillSection(200,100,state.lpStudents,9,x=>[
    x.name||'',x.grade||'',x.contact||'',x.admissionDate||'',x.kit||'',Number(x.fee||0),Number(x.paid||0),Number(balance(x)||0),payStatus(x)||'—'
  ]);

  fillSection(313,100,state.upStudents,9,x=>[
    x.name||'',x.grade||'',x.contact||'',x.admissionDate||'',x.kit||'',Number(x.fee||0),Number(x.paid||0),Number(balance(x)||0),payStatus(x)||'—'
  ]);

  fillSection(426,100,state.kitsSold,8,x=>[
    x.date||'',x.studentName||'',x.level||'',x.kitName||'',Number(x.qty||0),Number(x.price||0),Number(soldTotal(x)||0),x.paymentMode||''
  ]);

  fillSection(539,120,stockRows(),8,x=>[
    x.name||'',x.type||'',Number(x.purchasedQty||0),Number(x.soldQty||0),Number(x.available||0),Number(x.avgCost||0),Number(x.stockValue||0),
    x.available<=0?'OUT OF STOCK':(x.available<5?'LOW STOCK':'IN STOCK')
  ]);

  const operators=(ACCOUNTS.operators||[]).map(o=>({
    id:o.id||'',name:o.name||'',username:o.username||'',contact:o.contact||'',
    role:o.accessRole||o.role||'viewer',active:o.active!==false,
    createdAt:o.createdAt||'',approvedAt:o.approvedAt||''
  }));
  fillSection(665,60,operators,7,o=>[
    o.id,o.name,o.username,o.contact,o.role,o.active?'ACTIVE':'DISABLED',`${o.createdAt}${o.approvedAt?' / '+o.approvedAt:''}`
  ]);

  const requests=(ACCOUNTS.requests||[]).filter(r=>r.status==='pending');
  fillSection(733,60,requests,6,r=>[
    r.id||'',r.name||'',r.username||'',r.contact||'',r.requestedAt||'',r.status||'pending'
  ]);

  const logs=getAudit().slice(0,150);
  fillSection(801,150,logs,6,l=>[
    l.timestamp||'',l.user||'',l.action||'',l.details||'',l.type||'',typeof l.metadata==='string'?l.metadata:(l.metadata?JSON.stringify(l.metadata):'')
  ]);

  zip.file('xl/worksheets/sheet1.xml',xml);
  return await zip.generateAsync({type:'blob',compression:'DEFLATE',compressionOptions:{level:6}});
}

async function exportBackup(){
  try{
    const blob=await buildBackupXlsx();
    if(!blob || blob.size<1000) throw new Error('The generated backup is empty.');
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download='Kit_Business_Backup.xlsx';
    link.style.display='none';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),10000);
    audit('Export backup','Readable Excel backup exported without password data');
  }catch(error){
    console.error('Backup XLSX export failed:',error);
    alert('Backup export failed.\n\n'+(error?.message||error));
  }
}

function securityDashboardHtml(){
  const sec=getSecurity();
  const logs=getAudit();
  const locked=Number(sec.lockedUntil||0)>Date.now();
  return `
    <div class="security-box">
      <div class="security-grid">
        <div class="security-stat"><span>Password storage</span><b>HASHED</b></div>
        <div class="security-stat"><span>Login status</span><b>${locked?'LOCKED':'ACTIVE'}</b></div>
        <div class="security-stat"><span>Failed attempts</span><b>${sec.failed||0} / 5</b></div>
        <div class="security-stat"><span>Auto logout</span><b>20 MIN</b></div>
        <div class="security-stat"><span>Operators</span><b>${(ACCOUNTS.operators||[]).length}</b></div>
        <div class="security-stat"><span>Audit events</span><b>${logs.length}</b></div>
      </div>
      <div class="audit-box">
        <table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>
          ${logs.length?logs.slice(0,50).map(x=>`<tr><td>${escapeHtml(new Date(x.time).toLocaleString('en-IN'))}</td><td>${escapeHtml(x.user)}</td><td>${escapeHtml(x.action)}</td><td>${escapeHtml(x.details)}</td></tr>`).join(''):
          '<tr><td colspan="4" style="text-align:center;color:var(--ink-faint);padding:18px;">No activity yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>`;
}


function showOperatorDetails(id){
  const op=(ACCOUNTS.operators||[]).find(o=>o.id===id);
  if(!op)return;

  const back=document.createElement('div');
  back.className='admin-modal-backdrop';

  back.innerHTML=`<div class="admin-modal" role="dialog" aria-modal="true">
    <div class="admin-modal-header">
      <div class="admin-modal-icon">👤</div>
      <div class="admin-modal-heading">
        <h3>User details & permissions</h3>
        <p>Administrator can change this user's access level.</p>
      </div>
      <button type="button" class="admin-modal-close" data-close>×</button>
    </div>

    <form id="operatorDetailsForm">
      <div class="admin-modal-body">
        <div class="user-detail-grid">
          <div class="user-detail"><div class="label">Full name</div><div class="value">${escapeHtml(op.name||'—')}</div></div>
          <div class="user-detail"><div class="label">Username</div><div class="value">${escapeHtml(op.username||'—')}</div></div>
          <div class="user-detail"><div class="label">Contact</div><div class="value">${escapeHtml(op.contact||'Not provided')}</div></div>
          <div class="user-detail"><div class="label">Status</div><div class="value">${op.active?'Active':'Disabled'}</div></div>
        </div>

        <div class="modal-field" style="margin-top:14px;">
          <label>Access level</label>
          <select name="accessRole">
            <option value="viewer" ${op.accessRole!=='editor'?'selected':''}>Viewer — view only</option>
            <option value="editor" ${op.accessRole==='editor'?'selected':''}>Editor — add & edit</option>
          </select>
          <div class="modal-help">Viewer cannot modify records. Editor can add and edit records. Administrator retains delete and user-management rights.</div>
        </div>

        <div class="password-security-note">
          <b>Password:</b> ••••••••••<br>
          Passwords are never shown to administrators. Use Reset password to create a new temporary password.
        </div>
      </div>

      <div class="admin-modal-footer">
        <button type="button" class="btn btn-ghost" id="operatorResetPassword">Reset password</button>
        <button type="button" class="btn btn-ghost" id="operatorToggle">${op.active?'Disable user':'Enable user'}</button>
        <button type="button" class="user-action-btn" id="operatorDelete">Delete user</button>
        <button type="button" class="btn btn-ghost" data-close>Cancel</button>
        <button type="submit" class="btn btn-primary">Save permissions</button>
      </div>
    </form>
  </div>`;

  document.body.appendChild(back);

  const close=()=>back.remove();
  back.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',close));
  back.addEventListener('click',e=>{if(e.target===back)close();});

  back.querySelector('#operatorDetailsForm').addEventListener('submit',e=>{
    e.preventDefault();
    op.accessRole=back.querySelector('[name="accessRole"]').value==='editor'?'editor':'viewer';
    saveAccounts();
    audit('Change user role',`${op.username} → ${op.accessRole}`);
    close();
    render();
  });

  back.querySelector('#operatorToggle').addEventListener('click',()=>{
    op.active=!op.active;
    saveAccounts();
    audit(op.active?'Enable user':'Disable user',op.username);
    close();
    render();
  });

  back.querySelector('#operatorDelete').addEventListener('click',async()=>{
    if(!(await confirmDeleteWithReminder(op.username,'user account')))return;
    ACCOUNTS.operators=ACCOUNTS.operators.filter(x=>x.id!==op.id);
    saveAccounts();
    audit('Delete user',op.username);
    close();
    render();
  });

  back.querySelector('#operatorResetPassword').addEventListener('click',async()=>{
    const temp='Temp-'+Math.random().toString(36).slice(2,8)+'A1!';
    op.passwordHash=await hashPassword(temp);
    saveAccounts();
    audit('Reset user password',op.username);
    alert('Temporary password:\\n\\n'+temp+'\\n\\nGive it to the user securely. It will not be shown again.');
  });
}

function openAdminTool(kind){

  // Export actions do not need a popup. Handle them directly.
  if(!isAdmin()) return;

  if(kind==='calculations'){
    exportCalculations();
    return;
  }

  if(kind==='report'){
    exportReport();
    return;
  }

  if(kind==='backup'){
    exportBackup();
    return;
  }

  const back=document.createElement('div');
  back.className='admin-modal-backdrop';

  if(kind==='add'){
    back.innerHTML=`<div class="admin-modal" role="dialog" aria-modal="true" aria-labelledby="addOperatorTitle">
      <div class="admin-modal-header">
        <div class="admin-modal-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
            <circle cx="9" cy="8" r="4"/>
            <path d="M3 21c0-4.4 2.7-7 6-7s6 2.6 6 7"/>
            <path d="M18 8v6M15 11h6"/>
          </svg>
        </div>
        <div class="admin-modal-heading">
          <h3 id="addOperatorTitle">Add operator</h3>
          <p>Create a secure read-only account for a team member.</p>
        </div>
        <button type="button" class="admin-modal-close" data-close aria-label="Close">×</button>
      </div>

      <form id="operatorForm">
        <div class="admin-modal-body">
          <div class="modal-field">
            <label>Operator name</label>
            <input name="name" required autocomplete="name" placeholder="e.g. Rahul">
          </div>

          <div class="modal-field">
            <label>Username</label>
            <input name="username" required autocomplete="username" placeholder="e.g. rahul">
            <div class="modal-help">This username is used to sign in.</div>
          </div>

          <div class="modal-field">
            <label>Access level</label>
            <select name="accessRole">
              <option value="viewer">Viewer — view only</option>
              <option value="editor">Editor — add & edit</option>
            </select>
            <div class="modal-help">Only the Administrator can manage users or delete records.</div>
          </div>

          <div class="modal-field">
            <label>Password</label>
            <div class="modal-password-wrap">
              <input id="opPassword" name="password" type="password" required minlength="8" autocomplete="new-password" placeholder="Minimum 8 characters">
              <button type="button" class="modal-show-btn" id="opShow">Show</button>
            </div>
            <div class="modal-help">Use at least 8 characters. Avoid easy-to-guess passwords.</div>
          </div>

          <div class="modal-error" id="modalError"></div>
        </div>

        <div class="admin-modal-footer">
          <button type="button" class="btn btn-ghost" data-close>Cancel</button>
          <button type="submit" class="btn btn-primary">Create operator</button>
        </div>
      </form>
    </div>`;
    document.body.appendChild(back);
    back.querySelector('#opShow').addEventListener('click',()=>{
      const input=back.querySelector('#opPassword');
      const show=input.type==='password';
      input.type=show?'text':'password';
      back.querySelector('#opShow').textContent=show?'Hide':'Show';
    });
    back.querySelector('#operatorForm').addEventListener('submit',async e=>{
      e.preventDefault();
      const fd=new FormData(e.currentTarget),err=back.querySelector('#modalError');
      const name=fd.get('name').trim(),username=fd.get('username').trim(),password=fd.get('password');
      if(!name){err.textContent='Enter the operator name.';err.style.display='block';return;}
      if(!username){err.textContent='Enter a username.';err.style.display='block';return;}
      if(!validPassword(password)){err.textContent='Password must be at least 8 characters.';err.style.display='block';return;}
      if(allAccounts().some(a=>a.username.toLowerCase()===username.toLowerCase())){err.textContent='Username already exists.';err.style.display='block';return;}
      ACCOUNTS.operators.push({
        id:'op-'+Date.now().toString(36),
        name,
        username,
        role:'operator',
        accessRole:fd.get('accessRole')==='editor'?'editor':'viewer',
        active:true,
        passwordHash:await hashPassword(password),
        createdAt:new Date().toISOString()
      });
      saveAccounts();audit('Add operator',username);
      back.remove();
      render();
    });
  }

  if(kind==='manage'){
    const ops=ACCOUNTS.operators||[];
    back.innerHTML=`<div class="admin-modal">
      <h3>Manage users</h3>
      <p>Click a user to view their details and change Viewer / Editor access.</p>
      <div class="table-wrap">
        <table class="admin-table">
          <thead><tr><th>Name</th><th>Username</th><th>Access</th><th>Status</th><th></th></tr></thead>
          <tbody>
          ${ops.length?ops.map(o=>`<tr>
            <td>${escapeHtml(o.name||'—')}</td>
            <td>${escapeHtml(o.username)}</td>
            <td><span class="badge badge-blue">${escapeHtml(accessLabel(o.accessRole||'viewer'))}</span></td>
            <td><span class="badge ${o.active?'badge-green':'badge-red'}">${o.active?'Active':'Disabled'}</span></td>
            <td><button class="user-action-btn" data-user-details="${o.id}">View</button></td>
          </tr>`).join(''):`<tr><td colspan="5" style="text-align:center;color:var(--ink-faint);padding:20px;">No operators yet.</td></tr>`}
          </tbody>
        </table>
      </div>
      <div class="modal-actions"><button class="btn btn-ghost" data-close>Close</button></div>
    </div>`;
    document.body.appendChild(back);

    back.querySelectorAll('[data-user-details]').forEach(btn=>{
      btn.addEventListener('click',()=>{
        const op=ACCOUNTS.operators.find(x=>x.id===btn.dataset.userDetails);
        if(op)showOperatorDetails(op.id);
      });
    });
  }

  if(kind==='requests'){
    const pending=(ACCOUNTS.requests||[]).filter(r=>r.status==='pending');

    back.innerHTML=`<div class="admin-modal" role="dialog" aria-modal="true">
      <div class="admin-modal-header">
        <div class="admin-modal-icon">✓</div>
        <div class="admin-modal-heading">
          <h3>Registration requests</h3>
          <p>Approve or reject people who requested a User account.</p>
        </div>
        <button type="button" class="admin-modal-close" data-close>×</button>
      </div>

      <div class="admin-modal-body">
        ${pending.length ? pending.map(r=>`
          <div class="request-card">
            <div class="request-top">
              <div>
                <div class="request-name">${escapeHtml(r.name)}</div>
                <div class="request-meta">@${escapeHtml(r.username)}</div>
                <div class="request-meta">${escapeHtml(r.contact)}</div>
                <div class="request-meta">Requested ${escapeHtml(new Date(r.requestedAt).toLocaleString('en-IN'))}</div>
              </div>
              <span class="pending-count">Pending</span>
            </div>
            <div class="request-actions">
              <button class="btn btn-primary" data-approve-request="${r.id}">Approve</button>
              <button class="btn btn-ghost" data-reject-request="${r.id}">Reject</button>
              <button class="user-action-btn" data-delete-request="${r.id}">Delete request</button>
            </div>
          </div>
        `).join('') :
          '<div style="text-align:center;color:var(--ink-faint);padding:24px;">No pending registration requests.</div>'}
      </div>

      <div class="admin-modal-footer">
        <button type="button" class="btn btn-ghost" data-close>Close</button>
      </div>
    </div>`;

    document.body.appendChild(back);

    back.querySelectorAll('[data-approve-request]').forEach(btn=>{
      btn.addEventListener('click',()=>{
        const req=(ACCOUNTS.requests||[]).find(r=>r.id===btn.dataset.approveRequest);
        if(!req)return;

        if(allAccounts().some(a=>String(a.username||'').toLowerCase()===req.username.toLowerCase())){
          alert('That username is already in use.');
          return;
        }

        ACCOUNTS.operators.push({
          id:'op-'+Date.now().toString(36),
          name:req.name,
          username:req.username,
          contact:req.contact,
          role:'operator',
          accessRole:'viewer',
          active:true,
          passwordHash:req.passwordHash,
          createdAt:new Date().toISOString(),
          approvedAt:new Date().toISOString()
        });

        req.status='approved';
        req.approvedAt=new Date().toISOString();

        saveAccounts();
        audit('Approve registration',req.username);

        back.remove();
        render();
        openAdminTool('requests');
      });
    });

    back.querySelectorAll('[data-reject-request]').forEach(btn=>{
      btn.addEventListener('click',()=>{
        const req=(ACCOUNTS.requests||[]).find(r=>r.id===btn.dataset.rejectRequest);
        if(!req)return;

        req.status='rejected';
        req.rejectedAt=new Date().toISOString();
        saveAccounts();
        audit('Reject registration',req.username);

        back.remove();
        render();
        openAdminTool('requests');
      });
    });

    back.querySelectorAll('[data-delete-request]').forEach(btn=>{
      btn.addEventListener('click',()=>{
        const req=(ACCOUNTS.requests||[]).find(r=>r.id===btn.dataset.deleteRequest);
        if(!req)return;

        if(!confirm('Delete this registration request permanently?'))return;

        ACCOUNTS.requests=ACCOUNTS.requests.filter(r=>r.id!==req.id);
        saveAccounts();
        audit('Delete registration request',req.username);

        back.remove();
        render();
        openAdminTool('requests');
      });
    });
  }

  if(kind==='password'){
    back.innerHTML=`<div class="admin-modal">
      <h3>Change administrator password</h3><p>Set a new password for the administrator account.</p>
      <form id="changePassForm">
        <div class="field"><label>Current password</label><input name="current" type="password" required></div>
        <div class="field" style="margin-top:10px;"><label>New password</label><input name="next" type="password" required></div>
        <div class="field" style="margin-top:10px;"><label>Confirm new password</label><input name="confirm" type="password" required></div>
        <div class="auth-error" id="modalError"></div>
        <div class="modal-actions"><button type="button" class="btn btn-ghost" data-close>Cancel</button><button type="submit" class="btn btn-primary">Update password</button></div>
      </form>
    </div>`;
    document.body.appendChild(back);
    back.querySelector('#changePassForm').addEventListener('submit',async e=>{
      e.preventDefault();
      const fd=new FormData(e.currentTarget),err=back.querySelector('#modalError');
      if(await hashPassword(fd.get('current'))!==ACCOUNTS.admin.passwordHash){err.textContent='Current password is incorrect.';err.style.display='block';return;}
      if(!validPassword(fd.get('next'))){err.textContent='New password must be at least 8 characters.';err.style.display='block';return;}
      if(fd.get('next')!==fd.get('confirm')){err.textContent='Passwords do not match.';err.style.display='block';return;}
      ACCOUNTS.admin.passwordHash=await hashPassword(fd.get('next'));saveAccounts();audit('Change admin password','Password changed');back.remove();alert('Administrator password updated.');
    });
  }

  if(kind==='security'){
    back.innerHTML=`<div class="admin-modal"><h3>Security dashboard</h3><p>Browser-side security status and recent activity.</p>${securityDashboardHtml()}<div class="modal-actions"><button class="btn btn-ghost" data-close>Close</button></div></div>`;
    document.body.appendChild(back);
  }

  // Export actions: these must be handled here because the Admin Control Centre
  // dispatches every action through openAdminTool().
  if(kind==='calculations'){
    exportCalculations();
    return;
  }

  if(kind==='report'){
    exportReport();
    return;
  }

  if(kind==='backup'){
    exportBackup();
    return;
  }

  back.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>back.remove()));
  back.addEventListener('click',e=>{if(e.target===back)back.remove();});
  document.addEventListener('keydown',function closeOnEscape(ev){
    if(ev.key==='Escape' && document.body.contains(back)){
      back.remove();
      document.removeEventListener('keydown',closeOnEscape);
    }
  });
}

function pageDashboard(){
  const s = summaryData();
  const profitClass = s.netProfit>=0 ? 'profit-pos' : 'profit-neg';
  return `
  ${guideHtml()}
  <div class="page-head">
    <h1>Dashboard</h1>
    <p>A live snapshot of your kit business — pulled straight from Purchases, Students and Sales.</p>
  </div>${isAdmin()?adminControlHtml():''}

  <div class="metric-grid">
    <div class="metric accent"><div class="label">Total income (fees + sales)</div><div class="value">${fmt(s.totalIncome)}</div></div>
    <div class="metric"><div class="label">Total purchase cost</div><div class="value">${fmt(s.totalPurchaseCost)}</div></div>
    <div class="metric ${profitClass}"><div class="label">Net profit / loss</div><div class="value">${fmt(s.netProfit)}</div></div>
    <div class="metric"><div class="label">Stock value on hand</div><div class="value">${fmt(s.stockValue)}</div></div>
  </div>

  <div class="split-row">
    <div class="card">
      <div class="card-title">Students</div>
      <table>
        <tbody>
          <tr><td class="wrap">LP students enrolled</td><td>${s.lpCount}</td></tr>
          <tr><td class="wrap">UP students enrolled</td><td>${s.upCount}</td></tr>
          <tr><td class="wrap">Total fees billed</td><td>${fmt(s.totalFeeBilled)}</td></tr>
          <tr><td class="wrap">Total fees collected</td><td>${fmt(s.totalFeePaid)}</td></tr>
          <tr><td class="wrap">Balance still due</td><td style="color:${s.balanceDue>0?'var(--danger)':'var(--ink)'}">${fmt(s.balanceDue)}</td></tr>
        </tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Sales &amp; stock</div>
      <table>
        <tbody>
          <tr><td class="wrap">Kits sold (quantity)</td><td>${s.kitsSoldQty}</td></tr>
          <tr><td class="wrap">Sales revenue</td><td>${fmt(s.salesRevenue)}</td></tr>
          <tr><td class="wrap">Distinct items tracked</td><td>${distinctItems().length}</td></tr>
          <tr><td class="wrap">Stock value on hand</td><td>${fmt(s.stockValue)}</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  `;
}

/* =========================================================
   GENERIC TABLE ACTION HELPERS
========================================================= */
function actionButtons(stateKey, id){
  if(!canEdit() && !canDelete()){
    return '<span style="color:var(--ink-faint);font-size:11px;">View only</span>';
  }

  return `<div class="row-actions">
    ${canEdit()?`<button class="icon-btn edit" data-edit="${stateKey}:${id}" title="Edit">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>
    </button>`:''}
    ${canDelete()?`<button class="icon-btn" data-del="${stateKey}:${id}" title="Delete">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
    </button>`:''}
  </div>`;
}

/* =========================================================
   PURCHASES
========================================================= */
const PURCHASE_STATUSES=['Pending','Ordered','Received','Cancelled'];
const PURCHASE_MODES=['Online','Offline'];
const PURCHASE_PAYMENT_METHODS=['COD','UPI','Card','Bank Transfer','Cash','Other'];
const PURCHASE_REFUND_STATUSES=['Not applicable','Pending refund','Refunded'];
let purchaseStatusFilter='All';

function purchaseMode(p){
  return PURCHASE_MODES.includes(p?.purchaseMode) ? p.purchaseMode : (p?.productLink ? 'Online' : 'Offline');
}

function purchaseStatus(p){
  const raw=String(p?.orderStatus||'Pending');
  if(PURCHASE_STATUSES.includes(raw)) return raw;
  const legacy={
    'Order Placed':'Ordered',
    'Confirmed':'Ordered',
    'Processing':'Ordered',
    'Shipped':'Ordered',
    'Out for Delivery':'Ordered',
    'Returned':'Cancelled'
  };
  return legacy[raw]||'Pending';
}
function purchaseStatusBadge(status){
  const map={
    'Pending':['badge-yellow','Pending'],
    'Ordered':['badge-blue','Ordered'],
    'Received':['badge-green','Received'],
    'Cancelled':['badge-red','Cancelled']
  };
  const [cls,label]=map[status]||map.Pending;
  return `<span class="badge ${cls}">${label}</span>`;
}
function getPurchaseOrderCounts(){
  const counts={Pending:0,Ordered:0,Received:0,Cancelled:0};
  (state.purchases||[]).forEach(p=>{counts[purchaseStatus(p)]++;});
  return counts;
}

function normalizeUrl(raw){
  let url=String(raw||'').trim();
  if(url && !/^https?:\/\//i.test(url)) url='https://'+url;
  return url;
}

function pagePurchases(){
  const editing = editingId.purchases ? state.purchases.find(p=>p.id===editingId.purchases) : null;
  const counts=getPurchaseOrderCounts();
  const total = state.purchases.reduce((s,p)=>s+purchaseTotal(p),0);
  const visible = purchaseStatusFilter==='All' ? state.purchases : state.purchases.filter(p=>purchaseStatus(p)===purchaseStatusFilter);
  const currentMode = editing ? purchaseMode(editing) : 'Online';
  const currentStatus = editing ? purchaseStatus(editing) : 'Pending';
  const currentPayment = editing?.paymentMode || 'UPI';
  const currentRefund = editing?.refundStatus || 'Not applicable';
  return `
  <div class="page-head">
    <div>
      <h1>Purchases</h1>
      <p>Record online and offline purchases, save product links and order IDs, and update the order status manually.</p>
    </div>
  </div>

  <div class="order-summary-grid">
    <button type="button" class="order-summary-card ${purchaseStatusFilter==='All'?'active':''}" data-purchase-filter="All"><span class="order-summary-label">All orders</span><b>${state.purchases.length}</b><small>Everything</small></button>
    <button type="button" class="order-summary-card pending ${purchaseStatusFilter==='Pending'?'active':''}" data-purchase-filter="Pending"><span class="order-summary-label">Pending</span><b>${counts.Pending}</b><small>Not ordered yet</small></button>
    <button type="button" class="order-summary-card placed ${purchaseStatusFilter==='Ordered'?'active':''}" data-purchase-filter="Ordered"><span class="order-summary-label">Ordered</span><b>${counts.Ordered}</b><small>Order placed</small></button>
    <button type="button" class="order-summary-card received ${purchaseStatusFilter==='Received'?'active':''}" data-purchase-filter="Received"><span class="order-summary-label">Received</span><b>${counts.Received}</b><small>Delivered</small></button>
    <button type="button" class="order-summary-card cancelled ${purchaseStatusFilter==='Cancelled'?'active':''}" data-purchase-filter="Cancelled"><span class="order-summary-label">Cancelled</span><b>${counts.Cancelled}</b><small>Cancelled orders</small></button>
  </div>

  <div class="card">
    <div class="card-title">${editing? 'Edit purchase' : 'Add a purchase'} <span class="hint">Total = quantity × unit price</span></div>
    <form id="purchaseForm" class="form-grid">
      <div class="purchase-mode-switch field-wide">
        <div><label>Purchase method</label><small class="field-note">Choose where this purchase was made.</small></div>
        <div class="purchase-mode-buttons" role="group" aria-label="Purchase method">
          <button type="button" class="purchase-mode-btn ${currentMode==='Online'?'active':''}" data-purchase-mode="Online">🌐 Online</button>
          <button type="button" class="purchase-mode-btn ${currentMode==='Offline'?'active':''}" data-purchase-mode="Offline">🏪 Offline / Shop</button>
        </div>
      </div>

      <input type="hidden" name="purchaseMode" id="purchaseMode" value="${currentMode}">
      <div class="field"><label>Date</label><input type="date" name="date" required value="${editing?editing.date:todayStr()}"></div>
      <div class="field"><label>Item name</label><input type="text" name="item" required placeholder="e.g. Arduino Uno Board" value="${editing?escapeAttr(editing.item):''}"></div>
      <div class="field"><label>Type</label><select name="type"><option value="Material" ${editing&&editing.type==='Material'?'selected':''}>Material</option><option value="Finished Kit" ${editing&&editing.type==='Finished Kit'?'selected':''}>Finished Kit</option></select></div>
      <div class="field"><label>Quantity</label><input type="number" name="qty" min="0" step="1" required value="${editing?editing.qty:''}"></div>
      <div class="field"><label>Unit price (₹)</label><input type="number" name="unitPrice" min="0" step="0.01" required value="${editing?editing.unitPrice:''}"></div>
      <div class="field"><label>Order status</label><select name="orderStatus">${PURCHASE_STATUSES.map(st=>`<option value="${st}" ${currentStatus===st?'selected':''}>${st}</option>`).join('')}</select></div>
      <div class="field"><label>Payment method</label><select name="paymentMode">${PURCHASE_PAYMENT_METHODS.map(m=>`<option value="${m}" ${currentPayment===m?'selected':''}>${m}</option>`).join('')}</select></div>
      <div class="field"><label>Refund status</label><select name="refundStatus">${PURCHASE_REFUND_STATUSES.map(r=>`<option value="${r}" ${currentRefund===r?'selected':''}>${r}</option>`).join('')}</select></div>

      <div id="onlinePurchaseFields" class="purchase-mode-panel field-wide" ${currentMode==='Online'?'':'hidden'}>
        <div class="purchase-panel-title"><span>🌐 Online purchase</span><small>Save the product page and order reference</small></div>
        <div class="form-grid compact-grid">
          <div class="field"><label>Supplier / website</label><input type="text" name="supplier" placeholder="e.g. Robu.in" value="${editing?escapeAttr(editing.supplier||''):''}"></div>
          <div class="field"><label>Expected / received date</label><input type="date" name="expectedDate" value="${editing?escapeAttr(editing.expectedDate||''):''}"></div>
          <div class="field field-wide"><label>Product link</label><input id="purchaseProductLink" type="url" name="productLink" placeholder="Paste the product URL here" value="${editing?escapeAttr(editing.productLink||''):''}"><small class="field-note">Saved for later. Click More details in the purchase list to open it.</small></div>
          <div class="field field-wide"><label>Order ID</label><input id="purchaseOrderId" type="text" name="orderId" placeholder="Enter your order ID" value="${editing?escapeAttr(editing.orderId||''):''}"><small class="field-note">Manual reference only — status is selected above.</small></div>
        </div>
      </div>

      <div id="offlinePurchaseFields" class="purchase-mode-panel offline-panel field-wide" ${currentMode==='Offline'?'':'hidden'}>
        <div class="purchase-panel-title"><span>🏪 Offline / local shop</span><small>Record the shop transaction</small></div>
        <div class="form-grid compact-grid">
          <div class="field"><label>Shop / supplier name</label><input type="text" name="offlineShop" placeholder="e.g. ABC Electronics" value="${editing?escapeAttr(editing.offlineShop||(!editing.productLink?editing.supplier||'':'')):''}"></div>
          <div class="field"><label>Shop contact</label><input type="text" name="shopContact" placeholder="Phone / WhatsApp (optional)" value="${editing?escapeAttr(editing.shopContact||''):''}"></div>
          <div class="field field-wide"><label>Shop address</label><input type="text" name="shopAddress" placeholder="Locality / address (optional)" value="${editing?escapeAttr(editing.shopAddress||''):''}"></div>
          <div class="field"><label>Bill / invoice number</label><input type="text" name="invoiceNo" placeholder="Optional bill number" value="${editing?escapeAttr(editing.invoiceNo||''):''}"></div>
          <div class="field field-wide"><label>Purchase notes</label><input type="text" name="offlineNotes" placeholder="Any important shop/order note" value="${editing?escapeAttr(editing.offlineNotes||''):''}"></div>
        </div>
      </div>

      <div class="form-actions"><button type="submit" class="btn btn-primary">${editing?'Save changes':'Add purchase'}</button>${editing?'<button type="button" class="btn btn-ghost" id="cancelEdit">Cancel</button>':''}</div>
    </form>
  </div>

  <div class="card">
    <div class="card-title">Purchase log <span class="hint">${visible.length} shown · ${fmt(total)} total cost</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Date</th><th>Method</th><th>Item</th><th>Supplier / Shop</th><th>Qty</th><th>Unit price</th><th>Order status</th><th>Payment</th><th>Total</th><th>Details</th><th></th></tr></thead>
      <tbody>
      ${visible.length===0 ? `<tr class="empty-row"><td colspan="11">No purchases match this order status.</td></tr>` : visible.map(p=>`<tr>
        <td>${p.date||''}</td><td><span class="purchase-method-badge ${purchaseMode(p)==='Online'?'online':'offline'}">${purchaseMode(p)==='Online'?'🌐 Online':'🏪 Offline'}</span></td><td class="wrap">${escapeHtml(p.item)}</td><td class="wrap">${escapeHtml(purchaseMode(p)==='Offline'?(p.offlineShop||p.supplier||''): (p.supplier||''))}</td><td>${p.qty}</td><td>${fmt(p.unitPrice)}</td>
        <td>${purchaseStatusBadge(purchaseStatus(p))}</td><td>${escapeHtml(p.paymentMode||'—')}</td><td>${fmt(purchaseTotal(p))}</td>
        <td><button type="button" class="btn btn-ghost table-detail-btn" data-product-details="${p.id}">More details</button></td><td>${actionButtons('purchases',p.id)}</td>
      </tr>`).join('')}
      </tbody>
      ${visible.length>0?`<tfoot><tr><td colspan="8">Grand total</td><td colspan="3">${fmt(visible.reduce((s,p)=>s+purchaseTotal(p),0))}</td></tr></tfoot>`:''}
    </table></div>
  </div>`;
}

/* =========================================================
   STUDENTS (shared renderer for LP / UP)
========================================================= */
function pageStudents(stateKey, levelCode, levelLabel){
  const rows = state[stateKey];
  const editing = editingId[stateKey] ? rows.find(r=>r.id===editingId[stateKey]) : null;
  const kitOptionsList = kitOptions();
  const feeTotal = rows.reduce((s,x)=> s+(Number(x.fee)||0),0);
  const paidTotal = rows.reduce((s,x)=> s+(Number(x.paid)||0),0);
  const balTotal = feeTotal - paidTotal;
  return `
  <div class="page-head">
    <h1>${levelLabel} Students</h1>
    <p>Roster of ${levelLabel.toLowerCase()} students, the kit they were given, and their fee status.</p>
  </div>

  <div class="card">
    <div class="card-title">${editing? 'Edit student' : 'Add a student'}</div>
    <form id="studentForm" data-level="${stateKey}" class="form-grid">
      <div class="field"><label>Student name</label><input type="text" name="name" required value="${editing?escapeAttr(editing.name):''}"></div>
      <div class="field"><label>Grade</label><input type="text" name="grade" placeholder="e.g. Grade ${levelCode==='LP'?'3':'6'}" value="${editing?escapeAttr(editing.grade):''}"></div>
      <div class="field"><label>Parent contact</label><input type="text" name="contact" value="${editing?escapeAttr(editing.contact):''}"></div>
      <div class="field"><label>Admission date</label><input type="date" name="admissionDate" value="${editing?editing.admissionDate:todayStr()}"></div>
      <div class="field"><label>Kit assigned</label>
        <input list="kitList-${stateKey}" name="kit" placeholder="Type or pick a kit" value="${editing?escapeAttr(editing.kit):''}">
        <datalist id="kitList-${stateKey}">${kitOptionsList.map(k=>`<option value="${escapeAttr(k)}">`).join('')}</datalist>
      </div>
      <div class="field"><label>Kit fee (₹)</label><input type="number" name="fee" min="0" step="0.01" value="${editing?editing.fee:''}"></div>
      <div class="field"><label>Amount paid (₹)</label><input type="number" name="paid" min="0" step="0.01" value="${editing?editing.paid:''}"></div>
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">${editing?'Save changes':'Add student'}</button>
        ${editing?'<button type="button" class="btn btn-ghost" id="cancelEdit">Cancel</button>':''}
      </div>
    </form>
  </div>

  <div class="card">
    <div class="card-title">${levelLabel} roster <span class="hint">${rows.length} student${rows.length===1?'':'s'}</span></div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Name</th><th>Grade</th><th>Contact</th><th>Admitted</th><th>Kit</th><th>Fee</th><th>Paid</th><th>Balance</th><th>Status</th><th></th></tr></thead>
      <tbody>
      ${rows.length===0 ? `<tr class="empty-row"><td colspan="10">No ${levelLabel.toLowerCase()} students yet — add one above.</td></tr>` :
        rows.map(x=>`
        <tr>
          <td class="wrap">${escapeHtml(x.name)}</td>
          <td>${escapeHtml(x.grade||'')}</td>
          <td>${escapeHtml(x.contact||'')}</td>
          <td>${x.admissionDate||''}</td>
          <td class="wrap">${escapeHtml(x.kit||'')}</td>
          <td>${fmt(x.fee)}</td>
          <td>${fmt(x.paid)}</td>
          <td style="color:${balance(x)>0?'var(--danger)':'var(--ink)'}">${fmt(balance(x))}</td>
          <td>${statusBadge(payStatus(x))}</td>
          <td>${actionButtons(stateKey, x.id)}</td>
        </tr>`).join('')}
      </tbody>
      ${rows.length>0?`<tfoot><tr><td colspan="5">Total</td><td>${fmt(feeTotal)}</td><td>${fmt(paidTotal)}</td><td colspan="3">${fmt(balTotal)} due</td></tr></tfoot>`:''}
    </table>
    </div>
  </div>
  `;
}

/* =========================================================
   KITS SOLD
========================================================= */
function pageSold(){
  const rows = state.kitsSold;
  const editing = editingId.kitsSold ? rows.find(r=>r.id===editingId.kitsSold) : null;
  const kitOptionsList = kitOptions();
  const studentOptions = [...state.lpStudents.map(s=>s.name), ...state.upStudents.map(s=>s.name)];
  const total = rows.reduce((s,k)=> s+soldTotal(k),0);
  return `
  <div class="page-head">
    <h1>Kits Sold</h1>
    <p>Every sale — one row per kit sold. Feeds the Dashboard and Available Stock automatically.</p>
  </div>

  <div class="card">
    <div class="card-title">${editing? 'Edit sale' : 'Record a sale'}</div>
    <form id="soldForm" class="form-grid">
      <div class="field"><label>Date</label><input type="date" name="date" required value="${editing?editing.date:todayStr()}"></div>
      <div class="field"><label>Student name</label>
        <input list="studentList" name="studentName" required value="${editing?escapeAttr(editing.studentName):''}">
        <datalist id="studentList">${studentOptions.map(n=>`<option value="${escapeAttr(n)}">`).join('')}</datalist>
      </div>
      <div class="field"><label>Level</label>
        <select name="level">
          <option value="LP" ${editing&&editing.level==='LP'?'selected':''}>LP</option>
          <option value="UP" ${editing&&editing.level==='UP'?'selected':''}>UP</option>
        </select>
      </div>
      <div class="field"><label>Kit name</label>
        <input list="kitList-sold" name="kitName" required value="${editing?escapeAttr(editing.kitName):''}">
        <datalist id="kitList-sold">${kitOptionsList.map(k=>`<option value="${escapeAttr(k)}">`).join('')}</datalist>
      </div>
      <div class="field"><label>Quantity</label><input type="number" name="qty" min="1" step="1" required value="${editing?editing.qty:1}"></div>
      <div class="field"><label>Selling price (₹)</label><input type="number" name="price" min="0" step="0.01" required value="${editing?editing.price:''}"></div>
      <div class="field"><label>Payment mode</label>
        <select name="paymentMode">
          ${['Cash','UPI','Card','Bank Transfer','Cheque'].map(m=>`<option ${editing&&editing.paymentMode===m?'selected':''}>${m}</option>`).join('')}
        </select>
      </div>
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">${editing?'Save changes':'Record sale'}</button>
        ${editing?'<button type="button" class="btn btn-ghost" id="cancelEdit">Cancel</button>':''}
      </div>
    </form>
  </div>

  <div class="card">
    <div class="card-title">Sales log <span class="hint">${rows.length} sale${rows.length===1?'':'s'}</span></div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Date</th><th>Student</th><th>Level</th><th>Kit</th><th>Qty</th><th>Price</th><th>Total</th><th>Payment</th><th></th></tr></thead>
      <tbody>
      ${rows.length===0 ? `<tr class="empty-row"><td colspan="9">No sales recorded yet.</td></tr>` :
        rows.map(k=>`
        <tr>
          <td>${k.date||''}</td>
          <td class="wrap">${escapeHtml(k.studentName)}</td>
          <td>${k.level||''}</td>
          <td class="wrap">${escapeHtml(k.kitName)}</td>
          <td>${k.qty}</td>
          <td>${fmt(k.price)}</td>
          <td>${fmt(soldTotal(k))}</td>
          <td>${k.paymentMode||''}</td>
          <td>${actionButtons('kitsSold', k.id)}</td>
        </tr>`).join('')}
      </tbody>
      ${rows.length>0?`<tfoot><tr><td colspan="6">Grand total</td><td colspan="3">${fmt(total)}</td></tr></tfoot>`:''}
    </table>
    </div>
  </div>
  `;
}

/* =========================================================
   AVAILABLE STOCK (read-only, computed)
========================================================= */

function kitItemRowHtml(item={name:'',qty:1}, index=0){
  return `
    <div class="kit-item-row" data-item-row>
      <div class="kit-item-number">${index+1}</div>
      <input class="kit-item-name" name="kitItemName" type="text"
        placeholder="Item name e.g. ESP32 Board"
        value="${escapeAttr(item.name||'')}">
      <input class="kit-item-qty" name="kitItemQty" type="number"
        min="1" step="1" placeholder="Qty"
        value="${Math.max(1,Number(item.qty)||1)}">
      <button type="button" class="icon-btn kit-remove-item"
        title="Remove item" aria-label="Remove item">×</button>
    </div>`;
}

function renumberKitItems(){
  const list=document.getElementById('kitItemsList');
  if(!list)return;
  list.querySelectorAll('[data-item-row]').forEach((row,i)=>{
    const n=row.querySelector('.kit-item-number');
    if(n)n.textContent=i+1;
  });
}

function pageKits(){
  const rows=state.kits||[];
  const editing=editingId.kits ? rows.find(k=>k.id===editingId.kits) : null;
  const items=editing && Array.isArray(editing.items) && editing.items.length ? editing.items : [{name:'',qty:1}];

  return `
    <div class="page-head">
      <h1>Kit Catalogue</h1>
      <p>Manage kits and define exactly which items and quantities are included in each kit.</p>
    </div>

    ${canEdit()?`
    <div class="card">
      <div class="card-title">${editing?'Edit kit':'Add kit'} <span class="hint">Kit details + contents</span></div>
      <form id="kitForm" class="form-grid">
        <div class="field"><label>Kit name</label><input name="name" required placeholder="e.g. Beginner Electronics Kit" value="${editing?escapeAttr(editing.name):''}"></div>
        <div class="field"><label>Level</label>
          <select name="level">
            <option value="LP" ${editing&&editing.level==='LP'?'selected':''}>LP</option>
            <option value="UP" ${editing&&editing.level==='UP'?'selected':''}>UP</option>
            <option value="General" ${editing&&editing.level==='General'?'selected':''}>General</option>
          </select>
        </div>
        <div class="field"><label>Default selling price (₹)</label><input name="price" type="number" min="0" step="0.01" value="${editing?editing.price:''}" required></div>
        <div class="field"><label>Description</label><input name="description" placeholder="Short description" value="${editing?escapeAttr(editing.description||''):''}"></div>

        <div class="kit-contents-wrap">
          <div class="kit-contents-head">
            <div>
              <div class="kit-contents-title">Items inside this kit</div>
              <div class="kit-contents-subtitle">Add every component/material and the quantity included.</div>
            </div>
            <button type="button" class="btn btn-ghost kit-add-item" id="addKitItem">+ Add item</button>
          </div>
          <div id="kitItemsList" class="kit-items-list">
            ${items.map((item,i)=>kitItemRowHtml(item,i)).join('')}
          </div>
        </div>

        <div class="form-actions">
          <button type="submit" class="btn btn-primary">${editing?'Save changes':'Add kit'}</button>
          ${editing?'<button type="button" class="btn btn-ghost" id="cancelEditKit">Cancel</button>':''}
        </div>
      </form>
    </div>`:''}

    <div class="card">
      <div class="card-title">Kit catalogue <span class="hint">${rows.length} kit${rows.length===1?'':'s'}</span></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Kit</th><th>Level</th><th>Price</th><th>Status</th><th>Items inside</th><th>Description</th><th></th></tr></thead>
          <tbody>
            ${rows.length?rows.map(k=>{
              const list=Array.isArray(k.items)?k.items.filter(i=>i && String(i.name||'').trim()):[];
              const itemText=list.length ? list.map(i=>`${escapeHtml(i.name)} × ${Number(i.qty)||1}`).join(', ') : 'No items added';
              return `<tr>
                <td class="wrap">${escapeHtml(k.name)}</td>
                <td>${escapeHtml(k.level||'General')}</td>
                <td>${fmt(k.price)}</td>
                <td>${k.active!==false?'<span class="badge badge-green">Active</span>':'<span class="badge badge-red">Disabled</span>'}</td>
                <td class="wrap">${itemText}</td>
                <td class="wrap">${escapeHtml(k.description||'')}</td>
                <td>${canEdit()?`<div class="row-actions">
                  <button class="icon-btn edit" data-edit-kit="${k.id}" title="Edit kit">✎</button>
                  ${isAdmin()?`<button class="icon-btn" data-toggle-kit="${k.id}" title="${k.active!==false?'Disable':'Enable'}">${k.active!==false?'⏸':'▶'}</button>
                  <button class="icon-btn" data-delete-kit="${k.id}" title="Delete kit" aria-label="Delete kit">×</button>`:''}
                </div>`:'<span style="color:var(--ink-faint);font-size:11px;">View only</span>'}</td>
              </tr>`;
            }).join(''):`<tr class="empty-row"><td colspan="7">No kits yet. ${isAdmin()?'Add your first kit above.':'Ask an Administrator to create kits.'}</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>`;
}

function pageStock(){
  const rows = stockRows();
  const totalValue = rows.reduce((s,r)=> s+r.stockValue,0);
  return `
  <div class="page-head">
    <h1>Available Stock</h1>
    <p>Calculated automatically from Purchases minus Kits Sold — nothing to fill in here.</p>
  </div>

  <div class="card">
    <div class="card-title">Stock on hand <span class="hint">${rows.length} item${rows.length===1?'':'s'}</span></div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Item</th><th>Type</th><th>Purchased</th><th>Sold</th><th>Available</th><th>Avg. unit cost</th><th>Stock value</th></tr></thead>
      <tbody>
      ${rows.length===0 ? `<tr class="empty-row"><td colspan="7">Add purchases to see stock here.</td></tr>` :
        rows.map(r=>{
          let badge = r.available<=0 ? '<span class="badge badge-red">Out of stock</span>'
                    : r.available<5 ? '<span class="badge badge-yellow">Low stock</span>'
                    : '<span class="badge badge-green">In stock</span>';
          return `<tr>
            <td class="wrap">${escapeHtml(r.name)}</td>
            <td>${r.type}</td>
            <td>${r.purchasedQty}</td>
            <td>${r.soldQty}</td>
            <td>${r.available} ${badge}</td>
            <td>${fmt(r.avgCost)}</td>
            <td>${fmt(r.stockValue)}</td>
          </tr>`;
        }).join('')}
      </tbody>
      ${rows.length>0?`<tfoot><tr><td colspan="6">Total stock value</td><td>${fmt(totalValue)}</td></tr></tfoot>`:''}
    </table>
    </div>
  </div>
  `;
}

/* =========================================================
   HANDLERS
========================================================= */

function protectUserForm(form){
  if(canEdit() || !form) return;
  form.querySelectorAll('input, select, button[type="submit"]').forEach(el=>el.disabled=true);
  const note=document.createElement('div');
  note.style.cssText='margin-top:10px;color:var(--ink-soft);font-size:11.5px;';
  note.textContent='Viewer access is read-only. An Editor or Administrator is required to add or edit records.';
  form.appendChild(note);
}


function showSimpleModal(title,body){
  const back=document.createElement('div'); back.className='admin-modal-backdrop';
  back.innerHTML=`<div class="admin-modal" role="dialog" aria-modal="true"><div class="admin-modal-header"><div class="admin-modal-icon">i</div><div class="admin-modal-heading"><h3>${escapeHtml(title)}</h3><p>Information saved in this tracker</p></div><button type="button" class="admin-modal-close" data-close>×</button></div><div class="admin-modal-body">${body}</div><div class="admin-modal-footer"><button type="button" class="btn btn-ghost" data-close>Close</button></div></div>`;
  document.body.appendChild(back); back.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>back.remove())); back.addEventListener('click',e=>{if(e.target===back)back.remove();});
}
function showUserSettings(){
  const me=currentAccount(); if(!me)return;
  const isAdm=isAdmin();
  const back=document.createElement('div'); back.className='admin-modal-backdrop';
  back.innerHTML=`<div class="admin-modal" role="dialog" aria-modal="true"><div class="admin-modal-header"><div class="admin-modal-icon">⚙</div><div class="admin-modal-heading"><h3>My Settings</h3><p>Edit your profile and account password</p></div><button type="button" class="admin-modal-close" data-close>×</button></div><div class="admin-modal-body"><form id="mySettingsForm"><div class="modal-field"><label>Full name</label><input name="name" value="${escapeAttr(me.name||'')}"></div><div class="modal-field"><label>Username</label><input name="username" value="${escapeAttr(me.username||'')}" required></div><div class="modal-field"><label>Contact</label><input name="contact" value="${escapeAttr(me.contact||'')}" placeholder="Phone or email" required></div><div class="modal-field"><label>Access</label><input value="${escapeAttr(accessLabel(accessLevel()))}" disabled></div><div class="modal-help">Keep your contact updated so the <b>Forgot password?</b> recovery option can verify your account.</div><div class="modal-actions"><button class="btn btn-primary" type="submit">Save profile</button></div></form><div class="settings-divider"></div><h3 style="margin:0 0 8px">Change password</h3><form id="myPasswordForm"><div class="modal-field"><label>Current password</label><input name="current" type="password" required></div><div class="modal-field"><label>New password</label><input name="next" type="password" required minlength="8"></div><div class="modal-field"><label>Confirm new password</label><input name="confirm" type="password" required minlength="8"></div><div class="auth-error" id="settingsError"></div><div class="modal-actions"><button class="btn btn-primary" type="submit">Change password</button></div></form></div><div class="admin-modal-footer"><button type="button" class="btn btn-ghost" data-close>Close</button></div></div>`;
  document.body.appendChild(back); back.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>back.remove()));
  back.querySelector('#mySettingsForm').addEventListener('submit',e=>{e.preventDefault();const fd=new FormData(e.currentTarget),name=String(fd.get('name')||'').trim(),username=String(fd.get('username')||'').trim(),contact=String(fd.get('contact')||'').trim();if(allAccounts().some(a=>a!==me && String(a.username||'').toLowerCase()===username.toLowerCase())){alert('That username is already in use.');return;}me.name=name;me.username=username;me.contact=contact;saveAccounts();audit('Edit profile',username);back.remove();render();alert('Profile updated.');});
  back.querySelector('#myPasswordForm').addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(e.currentTarget),err=back.querySelector('#settingsError');err.style.display='none';if(await hashPassword(fd.get('current'))!==me.passwordHash){err.textContent='Current password is incorrect.';err.style.display='block';return;}if(!validPassword(fd.get('next'))){err.textContent='New password must contain at least 8 characters.';err.style.display='block';return;}if(fd.get('next')!==fd.get('confirm')){err.textContent='Passwords do not match.';err.style.display='block';return;}me.passwordHash=await hashPassword(fd.get('next'));saveAccounts();audit('Change password','User changed own password');back.remove();alert('Password changed successfully.');});
}

function attachHandlers(){
  document.querySelectorAll('[data-admin-action]').forEach(btn=>btn.addEventListener('click',()=>{
    if(!isAdmin())return;
    openAdminTool(btn.dataset.adminAction);
  }));

  const appearanceBtn = document.getElementById('appearanceBtn');
  if(appearanceBtn){
    appearanceBtn.addEventListener('click', window.toggleAppearance);
    window.updateAppearanceButton();
  }

  const hideGuideBtn = document.getElementById('hideGuide');
  if(hideGuideBtn) hideGuideBtn.addEventListener('click', ()=>{ showGuide=false; render(); });

  document.querySelectorAll('[data-edit]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const [stateKey, id] = btn.dataset.edit.split(':');
      editingId[stateKey] = id;
      render();
    });
  });
  document.querySelectorAll('[data-del]').forEach(btn=>{
    btn.addEventListener('click', async ()=>{
      const [stateKey, id] = btn.dataset.del.split(':');
      state[stateKey] = state[stateKey].filter(r=>r.id!==id);
      audit('Delete record',stateKey);
      if(editingId[stateKey]===id) editingId[stateKey]=null;
      await save(stateKey);
      render();
    });
  });
  const cancelBtn = document.getElementById('cancelEdit');
  if(cancelBtn) cancelBtn.addEventListener('click', ()=>{
    editingId.purchases=null; editingId.lpStudents=null; editingId.upStudents=null; editingId.kitsSold=null; editingId.kits=null;
    render();
  });


  const kitForm=document.getElementById('kitForm');

  if(kitForm){
    const itemsList=document.getElementById('kitItemsList');
    const addItemButton=document.getElementById('addKitItem');

    if(itemsList && addItemButton){
      addItemButton.addEventListener('click',()=>{
        const count=itemsList.querySelectorAll('[data-item-row]').length;
        itemsList.insertAdjacentHTML('beforeend',kitItemRowHtml({name:'',qty:1},count));
        renumberKitItems();
        const rows=itemsList.querySelectorAll('[data-item-row]');
        const last=rows[rows.length-1];
        const input=last?.querySelector('.kit-item-name');
        if(input)input.focus();
      });

      itemsList.addEventListener('click',event=>{
        const button=event.target.closest('.kit-remove-item');
        if(!button)return;
        const row=button.closest('[data-item-row]');
        if(!row)return;

        const rows=itemsList.querySelectorAll('[data-item-row]');
        if(rows.length===1){
          const name=row.querySelector('.kit-item-name');
          const qty=row.querySelector('.kit-item-qty');
          if(name)name.value='';
          if(qty)qty.value=1;
          return;
        }

        row.remove();
        renumberKitItems();
      });
    }

    kitForm.addEventListener('submit',async e=>{
    e.preventDefault();
    if(!isAdmin())return;
    const fd=new FormData(kitForm);
    const name=String(fd.get('name')||'').trim();
    const duplicate=state.kits.find(k=>k.id!==editingId.kits && String(k.name||'').toLowerCase()===name.toLowerCase());
    if(duplicate){alert('A kit with this name already exists.');return;}

    const itemNames=[...kitForm.querySelectorAll('input[name="kitItemName"]')];
    const itemQtys=[...kitForm.querySelectorAll('input[name="kitItemQty"]')];
    const items=[];
    itemNames.forEach((input,i)=>{
      const itemName=input.value.trim();
      const qty=Math.max(1,Number(itemQtys[i]?.value)||1);
      if(itemName)items.push({name:itemName,qty});
    });

    const rec={
      id:editingId.kits||uid(),
      name,
      level:fd.get('level'),
      price:Number(fd.get('price'))||0,
      description:String(fd.get('description')||'').trim(),
      active:true,
      items
    };

    if(editingId.kits){
      const i=state.kits.findIndex(k=>k.id===editingId.kits);
      if(i>=0)state.kits[i]={...state.kits[i],...rec};
      audit('Edit kit',rec.name);
      editingId.kits=null;
    }else{
      state.kits.push(rec);
      audit('Add kit',rec.name);
    }
    await save('kits');
    render();
  });
  }

  const cancelEditKit=document.getElementById('cancelEditKit');
  if(cancelEditKit)cancelEditKit.addEventListener('click',()=>{editingId.kits=null;render();});

  document.querySelectorAll('[data-edit-kit]').forEach(btn=>btn.addEventListener('click',()=>{
    editingId.kits=btn.dataset.editKit;
    currentSection='kits';
    render();
  }));

  document.querySelectorAll('[data-toggle-kit]').forEach(btn=>btn.addEventListener('click',async()=>{
    if(!isAdmin())return;
    const kit=state.kits.find(k=>k.id===btn.dataset.toggleKit);
    if(!kit)return;
    kit.active=kit.active===false;
    await save('kits');
    audit(kit.active?'Enable kit':'Disable kit',kit.name);
    render();
  }));

  document.querySelectorAll('[data-delete-kit]').forEach(btn=>btn.addEventListener('click',async()=>{
    if(!isAdmin())return;

    const kit=state.kits.find(k=>k.id===btn.dataset.deleteKit);
    if(!kit)return;

    const usedByStudents=[
      ...(state.lpStudents||[]),
      ...(state.upStudents||[])
    ].some(student=>student.kit===kit.name);

    const usedBySales=(state.kitsSold||[]).some(sale=>sale.kitName===kit.name);

    let message=`Delete "${kit.name}" permanently?\n\nThis removes the kit from the catalogue.`;

    if(usedByStudents || usedBySales){
      message += `\n\nExisting student or sales records reference this kit. Those historical records will NOT be deleted.`;
    }

    if(!confirm(message))return;

    state.kits=state.kits.filter(k=>k.id!==kit.id);

    if(editingId.kits===kit.id){
      editingId.kits=null;
    }

    await save('kits');
    audit('Delete kit',kit.name);
    render();
  }));


  document.querySelectorAll('[data-product-details]').forEach(btn=>btn.addEventListener('click',()=>{
    const p=state.purchases.find(x=>x.id===btn.dataset.productDetails); if(!p)return;
    const mode=purchaseMode(p);
    const seller=mode==='Offline' ? (p.offlineShop||p.supplier||'—') : (p.supplier||'—');
    const link=p.productLink ? `<a class="product-link" href="${escapeAttr(p.productLink)}" target="_blank" rel="noopener noreferrer">Open product link ↗</a>` : '<span class="muted">No product link saved.</span>';
    const extra=mode==='Offline' ? `<div><b>Shop contact</b><span>${escapeHtml(p.shopContact||'—')}</span></div><div><b>Shop address</b><span>${escapeHtml(p.shopAddress||'—')}</span></div><div><b>Bill / invoice</b><span>${escapeHtml(p.invoiceNo||'—')}</span></div>` : `<div><b>Order ID</b><span>${escapeHtml(p.orderId||'—')}</span></div><div><b>Expected / received</b><span>${escapeHtml(p.expectedDate||'—')}</span></div>`;
    const refund=p.refundStatus||'Not applicable';
    showSimpleModal('Purchase details',`<div class="product-detail-mode ${mode==='Online'?'online':'offline'}">${mode==='Online'?'🌐 Online purchase':'🏪 Offline / shop purchase'}</div><div class="product-detail-grid"><div><b>Product</b><span>${escapeHtml(p.item||'—')}</span></div><div><b>Supplier / Shop</b><span>${escapeHtml(seller)}</span></div><div><b>Type</b><span>${escapeHtml(p.type||'—')}</span></div><div><b>Quantity</b><span>${Number(p.qty)||0}</span></div><div><b>Unit price</b><span>${fmt(p.unitPrice)}</span></div><div><b>Total cost</b><span>${fmt(purchaseTotal(p))}</span></div><div><b>Order status</b><span>${escapeHtml(purchaseStatus(p))}</span></div><div><b>Payment method</b><span>${escapeHtml(p.paymentMode||'—')}</span></div><div><b>Refund status</b><span>${escapeHtml(refund)}</span></div>${extra}</div><div class="product-detail-link"><b>Product link</b><div>${link}</div></div>`);
  }));

  document.querySelectorAll('[data-purchase-filter]').forEach(btn=>btn.addEventListener('click',()=>{
    purchaseStatusFilter=btn.dataset.purchaseFilter||'All';
    render();
  }));

  document.querySelectorAll('[data-purchase-mode]').forEach(btn=>btn.addEventListener('click',()=>{
    const mode=btn.dataset.purchaseMode||'Online';
    const hidden=document.getElementById('purchaseMode');
    const online=document.getElementById('onlinePurchaseFields');
    const offline=document.getElementById('offlinePurchaseFields');
    if(hidden) hidden.value=mode;
    document.querySelectorAll('[data-purchase-mode]').forEach(b=>b.classList.toggle('active',b.dataset.purchaseMode===mode));
    if(online) online.hidden=mode!=='Online';
    if(offline) offline.hidden=mode!=='Offline';
  }));

  const purchaseForm = document.getElementById('purchaseForm');
  if(purchaseForm) purchaseForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    if(!canEdit())return;
    const fd = new FormData(purchaseForm);
    const rec = {
      id: editingId.purchases || uid(),
      date: fd.get('date'), item: String(fd.get('item')||'').trim(), type: fd.get('type'),
      purchaseMode: String(fd.get('purchaseMode')||'Online'),
      supplier: String(fd.get('purchaseMode')==='Offline' ? (fd.get('offlineShop')||'') : (fd.get('supplier')||'')).trim(),
      qty: Number(fd.get('qty')), unitPrice: Number(fd.get('unitPrice')),
      productLink: normalizeUrl(fd.get('purchaseMode')==='Online' ? fd.get('productLink') : ''),
      productDetails: '',
      orderStatus: PURCHASE_STATUSES.includes(String(fd.get('orderStatus')||'')) ? String(fd.get('orderStatus')) : 'Pending',
      orderId: String(fd.get('orderId')||'').trim(), expectedDate: String(fd.get('expectedDate')||''),
      paymentMode: PURCHASE_PAYMENT_METHODS.includes(String(fd.get('paymentMode')||'')) ? String(fd.get('paymentMode')) : 'Other',
      refundStatus: PURCHASE_REFUND_STATUSES.includes(String(fd.get('refundStatus')||'')) ? String(fd.get('refundStatus')) : 'Not applicable',
      offlineShop: String(fd.get('offlineShop')||'').trim(), shopContact: String(fd.get('shopContact')||'').trim(), shopAddress: String(fd.get('shopAddress')||'').trim(), invoiceNo: String(fd.get('invoiceNo')||'').trim(), offlineNotes: String(fd.get('offlineNotes')||'').trim(), offlineDetails: ''
    };
    if(rec.orderStatus==='Cancelled' && rec.refundStatus==='Not applicable') rec.refundStatus='Pending refund';
    if(rec.orderStatus!=='Cancelled') rec.refundStatus='Not applicable';
    const wasEditing = Boolean(editingId.purchases);
    if(wasEditing){
      const i = state.purchases.findIndex(p=>p.id===editingId.purchases);
      if(i>=0) state.purchases[i] = rec;
      editingId.purchases = null;
    } else {
      state.purchases.push(rec);
    }
    await save('purchases');
    audit(wasEditing?'Edit purchase':'Add purchase',rec.item);
    render();
  });

  const studentForm = document.getElementById('studentForm');
  if(studentForm) studentForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    if(!canEdit())return;
    const stateKey = studentForm.dataset.level;
    const fd = new FormData(studentForm);
    const rec = {
      id: editingId[stateKey] || uid(),
      name: fd.get('name').trim(), grade: fd.get('grade').trim(), contact: fd.get('contact').trim(),
      admissionDate: fd.get('admissionDate'), kit: fd.get('kit').trim(),
      levelCode: stateKey==='lpStudents' ? 'LP' : 'UP',
      fee: Number(fd.get('fee'))||0, paid: Number(fd.get('paid'))||0,
    };
    if(editingId[stateKey]){
      const i = state[stateKey].findIndex(r=>r.id===editingId[stateKey]);
      state[stateKey][i] = rec;
      editingId[stateKey] = null;
    } else {
      state[stateKey].push(rec);
    }
    await save(stateKey);
    audit(editingId[stateKey]?'Edit student':'Add student',rec.name);
    render();
  });


  const studentKitField = document.querySelector('#studentForm [name="kit"]');
  const studentFeeField = document.querySelector('#studentForm [name="fee"]');
  if(studentKitField && studentFeeField){
    const applyKitPrice=()=>{
      const kit=getKitByName(studentKitField.value.trim());
      if(kit && (!studentFeeField.value || Number(studentFeeField.value)===0)){
        studentFeeField.value=kit.price;
      }
    };
    studentKitField.addEventListener('change',applyKitPrice);
    studentKitField.addEventListener('blur',applyKitPrice);
  }

  const soldKitField=document.querySelector('#soldForm [name="kitName"]');
  const soldPriceField=document.querySelector('#soldForm [name="price"]');
  if(soldKitField){
    const applyKitPrice=()=>{
      const kit=getKitByName(soldKitField.value.trim());
      if(kit && soldPriceField && (!soldPriceField.value || Number(soldPriceField.value)===0)) soldPriceField.value=kit.price;
    };
    soldKitField.addEventListener('change',applyKitPrice);
    soldKitField.addEventListener('blur',applyKitPrice);
  }

  const soldForm = document.getElementById('soldForm');
  if(soldForm){
    const studentNameField=soldForm.querySelector('[name="studentName"]');
    if(studentNameField){
      studentNameField.addEventListener('change',()=>syncStudentIntoSaleForm(studentNameField.value.trim()));
      studentNameField.addEventListener('blur',()=>syncStudentIntoSaleForm(studentNameField.value.trim()));
      if(studentNameField.value) syncStudentIntoSaleForm(studentNameField.value.trim());
    }
  }
  if(soldForm) soldForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    if(!canEdit())return;
    const fd = new FormData(soldForm);
    const rec = {
      id: editingId.kitsSold || uid(),
      date: fd.get('date'), studentName: fd.get('studentName').trim(), level: fd.get('level'),
      kitName: fd.get('kitName').trim(), qty: Number(fd.get('qty')), price: Number(fd.get('price')),
      paymentMode: fd.get('paymentMode'),
    };
    if(editingId.kitsSold){
      const i = state.kitsSold.findIndex(r=>r.id===editingId.kitsSold);
      state.kitsSold[i] = rec;
      editingId.kitsSold = null;
    } else {
      state.kitsSold.push(rec);
    }
    await save('kitsSold');
    audit(editingId.kitsSold?'Edit sale':'Record sale',rec.kitName);
    render();
  });

  protectUserForm(purchaseForm);
  protectUserForm(studentForm);
  protectUserForm(soldForm);

  const settingsBtn=document.getElementById('settingsBtn');
  if(settingsBtn) settingsBtn.addEventListener('click',showUserSettings);

  const logoutBtn = document.getElementById('logoutBtn');
  if(logoutBtn) logoutBtn.addEventListener('click', logoutUser);

  const resetBtn = document.getElementById('resetBtn');
  if(resetBtn) resetBtn.style.display = isAdmin() ? '' : 'none';

  const roleBadge=document.getElementById('roleBadge');
  if(roleBadge){
    const me=allAccounts().find(a=>a.id===currentUserId);
    roleBadge.textContent=isAdmin()?'Administrator':((me?.name||'Operator')+' • '+accessLabel(accessLevel()));
  }
}

/* =========================================================
   UTIL
========================================================= */
function escapeHtml(str){
  if(str===undefined||str===null) return '';
  return String(str).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function escapeAttr(str){ return escapeHtml(str); }

/* =========================================================
   RESET
========================================================= */
function attachResetHandler(){
  const resetBtn = document.getElementById('resetBtn');
  if(!resetBtn) return;
  resetBtn.addEventListener('click', async ()=>{
    if(!isAdmin()) return;
    if(!confirm('This clears ALL data in this tracker (purchases, students, sales). Continue?')) return;
    state = {purchases:[], lpStudents:[], upStudents:[], kitsSold:[], kits:[]};
    editingId = {purchases:null, lpStudents:null, upStudents:null, kitsSold:null, kits:null};
    await saveAll();
    audit('Clear all data','Administrator cleared all tracker data');
    render();
  });
}

/* =========================================================
   INIT
========================================================= */
(async function init(){
  if(!currentRole){
    showLogin();
    return;
  }
  await loadAll();
  render();
  window.updateAppearanceButton();
  startIdleTimer();
})();