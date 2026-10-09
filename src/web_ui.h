#pragma once
#include <Arduino.h>

// Single-page dashboard, embedded in flash and served at "/".
// Vanilla JS, no external dependencies (works on an isolated LAN).
static const char DASHBOARD_HTML[] PROGMEM = R"HTML(<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32-S3 AdBlock</title>
<style>
:root{--bg:#0e1116;--card:#171c24;--line:#232b36;--fg:#e6edf3;--mut:#8b98a9;
--accent:#3fb6ff;--red:#ff5d6c;--green:#3ad29f;--amber:#ffc24b}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line);
position:sticky;top:0;background:var(--bg);z-index:5;flex-wrap:wrap}
header h1{font-size:16px;margin:0;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green)}
.dot.off{background:var(--red)}
.wrap{max-width:1000px;margin:0 auto;padding:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.card .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:26px;font-weight:650;margin-top:4px}
.card .v.red{color:var(--red)}.card .v.green{color:var(--green)}.card .v.blue{color:var(--accent)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin-top:16px}
.panel h2{font-size:13px;margin:0 0 10px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-top:16px}
.tabs button{background:var(--card);border:1px solid var(--line);color:var(--mut);
padding:8px 14px;border-radius:9px;cursor:pointer;font-size:13px}
.tabs button.active{color:var(--fg);border-color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font-weight:500}
td.dom{white-space:normal;word-break:break-all}
.tag{font-size:11px;padding:2px 7px;border-radius:20px;border:1px solid var(--line)}
.tag.b{color:var(--red);border-color:#48262c}.tag.f{color:var(--green);border-color:#1f4538}
.tag.c{color:var(--amber);border-color:#4a3c1c}
.bars{display:flex;align-items:flex-end;gap:3px;height:120px}
.bars .b{flex:1;background:#223}
.bars .b i{display:block;background:var(--red);width:100%}
input,select{background:#0d1117;border:1px solid var(--line);color:var(--fg);
padding:8px 10px;border-radius:8px;font-size:13px;width:100%}
label{display:block;color:var(--mut);font-size:12px;margin:10px 0 4px}
.btn{background:var(--accent);color:#042033;border:0;padding:9px 14px;border-radius:8px;
cursor:pointer;font-weight:600;font-size:13px}
.btn.sec{background:transparent;color:var(--fg);border:1px solid var(--line)}
.btn.danger{background:var(--red);color:#2a0b0f}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.hide{display:none}.right{margin-left:auto}
small.mut{color:var(--mut)}
a.lnk{color:var(--accent);cursor:pointer}
@media(max-width:560px){.grid2{grid-template-columns:1fr}}
</style></head><body>
<header>
  <div class="dot" id="dot"></div><h1>ESP32-S3 AdBlock</h1>
  <small class="mut" id="sub"></small>
  <div class="right row">
    <button class="btn sec" id="toggleBtn" onclick="toggleBlocking()">...</button>
  </div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="k">Queries</div><div class="v blue" id="s_total">-</div></div>
    <div class="card"><div class="k">Blocked</div><div class="v red" id="s_blocked">-</div></div>
    <div class="card"><div class="k">Block rate</div><div class="v" id="s_pct">-</div></div>
    <div class="card"><div class="k">Domains on list</div><div class="v green" id="s_list">-</div></div>
    <div class="card"><div class="k">Clients</div><div class="v" id="s_clients">-</div></div>
    <div class="card"><div class="k">Uptime</div><div class="v" id="s_up">-</div></div>
  </div>

  <div class="panel"><h2>Last 24 hours (red = blocked)</h2><div class="bars" id="bars"></div></div>

  <div class="tabs" id="tabs"></div>
  <div class="panel" id="view"></div>
</div>
<script src="/app.js"></script>
</body></html>)HTML";

// ---- Dashboard JavaScript, served at /app.js ----
static const char DASHBOARD_JS[] PROGMEM = R"JS(
let auth = sessionStorage.getItem('adblock_auth') || '';
const qtypes = {1:'A',28:'AAAA',65:'HTTPS',12:'PTR',16:'TXT',15:'MX',2:'NS',5:'CNAME',6:'SOA'};
const $ = s => document.querySelector(s);

async function authFetch(url, opts={}) {
  opts.headers = Object.assign({'X-Requested-With':'adblock'}, opts.headers||{});
  if (auth) opts.headers['Authorization'] = 'Basic ' + auth;
  let r = await fetch(url, opts);
  if (r.status === 401) {
    const u = prompt('Dashboard username:', 'admin');
    if (u === null) return r;
    const p = prompt('Password:') || '';
    auth = btoa(u + ':' + p);
    sessionStorage.setItem('adblock_auth', auth);
    opts.headers['Authorization'] = 'Basic ' + auth;
    r = await fetch(url, opts);
  }
  return r;
}
const post = (url, obj) => authFetch(url, {method:'POST',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body: new URLSearchParams(obj).toString()});

function fmtDur(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return (d?d+'d ':'')+(h?h+'h ':'')+m+'m';}
function fmtTs(t){if(!t)return '-';const d=new Date(t*1000);
  return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function fmtNum(n){return (n||0).toLocaleString();}

async function loadStats(){
  const s = await (await fetch('/api/stats')).json();
  $('#s_total').textContent = fmtNum(s.total);
  $('#s_blocked').textContent = fmtNum(s.blocked);
  $('#s_pct').textContent = (s.blockedPct||0).toFixed(1) + '%';
  $('#s_list').textContent = fmtNum(s.blocklistCount);
  $('#s_clients').textContent = fmtNum(s.clients);
  $('#s_up').textContent = fmtDur(s.uptime);
  $('#dot').className = 'dot' + (s.blockingEnabled?'':' off');
  $('#toggleBtn').textContent = s.blockingEnabled ? 'Blocking ON' : 'Blocking OFF';
  $('#sub').textContent = 'fw ' + s.fw + ' · heap ' + Math.round(s.heap/1024) + 'k · psram ' +
    Math.round(s.psramFree/1048576*10)/10 + 'M free · ' + s.ip;
  const hist = await (await fetch('/api/hist')).json();
  const max = Math.max(1, ...hist.map(b=>b.total));
  $('#bars').innerHTML = hist.map(b=>{
    const th = Math.round(b.total/max*100), bh = b.total?Math.round(b.blocked/b.total*th):0;
    return '<div class="b" title="'+b.total+' queries, '+b.blocked+' blocked" style="height:'+th+'%">'+
      '<i style="height:'+bh+'%"></i></div>';
  }).join('');
}

async function toggleBlocking(){
  const s = await (await fetch('/api/stats')).json();
  const r = await post('/api/toggle', {enabled: s.blockingEnabled ? 0 : 1});
  if (r.ok) loadStats();
}

const TABS = ['Query Log','Clients','Top Blocked','Lists','Settings'];
let active = 0;
function renderTabs(){
  $('#tabs').innerHTML = TABS.map((t,i)=>
    '<button class="'+(i===active?'active':'')+'" onclick="selectTab('+i+')">'+t+'</button>').join('');
}
function selectTab(i){active=i;renderTabs();renderView();}

async function renderView(){
  const v = $('#view');
  if (active===0) return renderLog(v);
  if (active===1) return renderClients(v);
  if (active===2) return renderTop(v);
  if (active===3) return renderLists(v);
  if (active===4) return renderSettings(v);
}

async function renderLog(v){
  const rows = await (await fetch('/api/log?n=150')).json();
  v.innerHTML = '<h2>Recent queries</h2><table><tr><th>Time</th><th>Client</th><th>Domain</th>'+
    '<th>Type</th><th>Result</th></tr>' + rows.map(r=>{
    const cls = r.result===1?'b':r.result===2?'c':'f';
    const lbl = r.result===1?'blocked':r.result===2?'cached':'forwarded';
    return '<tr><td>'+fmtTs(r.ts)+'</td><td>'+r.ip+'</td><td class="dom">'+r.domain+
      '</td><td>'+(qtypes[r.qtype]||r.qtype)+'</td><td><span class="tag '+cls+'">'+lbl+'</span></td></tr>';
  }).join('') + '</table>';
}

async function renderClients(v){
  const rows = await (await fetch('/api/clients')).json();
  v.innerHTML = '<h2>Clients</h2><table><tr><th>IP</th><th>Queries</th><th>Blocked</th>'+
    '<th>Last seen</th><th></th></tr>' + rows.map(c=>
    '<tr><td>'+c.ip+'</td><td>'+fmtNum(c.total)+'</td><td>'+fmtNum(c.blocked)+'</td><td>'+
    fmtTs(c.lastSeen)+'</td><td><a class="lnk" onclick="ban(\''+c.ip+'\','+(c.banned?0:1)+')">'+
    (c.banned?'unban':'ban')+'</a></td></tr>').join('') + '</table>';
}
async function ban(ip,b){const r=await post('/api/ban',{ip,banned:b});if(r.ok)renderClients($('#view'));}

async function renderTop(v){
  const rows = await (await fetch('/api/top?n=25')).json();
  v.innerHTML = '<h2>Top blocked domains</h2><table><tr><th>#</th><th>Domain</th><th>Hits</th></tr>'+
    rows.map((r,i)=>'<tr><td>'+(i+1)+'</td><td class="dom">'+r.domain+'</td><td>'+
    fmtNum(r.count)+'</td></tr>').join('') + '</table>';
}

async function renderLists(v){
  v.innerHTML = '<div class="grid2"><div><h2>Custom block</h2>'+listBox('block')+
    '</div><div><h2>Allowlist (overrides blocks)</h2>'+listBox('allow')+'</div></div>';
  fillList('block'); fillList('allow');
}
function listBox(kind){
  return '<div class="row"><input id="in_'+kind+'" placeholder="domain.com">'+
    '<button class="btn" onclick="addCustom(\''+kind+'\')">Add</button></div>'+
    '<div id="list_'+kind+'" style="margin-top:10px"></div>';
}
async function fillList(kind){
  const allow = kind==='allow'?1:0;
  const rows = await (await fetch('/api/custom?allow='+allow)).json();
  $('#list_'+kind).innerHTML = rows.length ? '<table>'+rows.map(d=>
    '<tr><td class="dom">'+d+'</td><td><a class="lnk" onclick="rmCustom(\''+kind+'\',\''+d+
    '\')">remove</a></td></tr>').join('')+'</table>' : '<small class="mut">empty</small>';
}
async function addCustom(kind){
  const d = $('#in_'+kind).value.trim(); if(!d) return;
  const r = await post('/api/custom', {allow: kind==='allow'?1:0, action:'add', domain:d});
  if(r.ok){$('#in_'+kind).value='';fillList(kind);}
}
async function rmCustom(kind,d){
  const r = await post('/api/custom', {allow: kind==='allow'?1:0, action:'remove', domain:d});
  if(r.ok) fillList(kind);
}

async function renderSettings(v){
  const c = await (await fetch('/api/config')).json();
  v.innerHTML = `<h2>Settings</h2>
    <div class="grid2">
      <div><label>Primary upstream DNS</label><input id="up1" value="${c.upstream1}"></div>
      <div><label>Secondary upstream DNS</label><input id="up2" value="${c.upstream2}"></div>
      <div><label>Block response</label><select id="bmode">
        <option value="0"${c.blockMode==0?' selected':''}>0.0.0.0 / :: (sinkhole)</option>
        <option value="1"${c.blockMode==1?' selected':''}>NXDOMAIN</option></select></div>
      <div><label>Auto-update interval (hours, 0=off)</label><input id="uphrs" type="number" value="${c.updateHours}"></div>
      <div><label>mDNS hostname</label><input id="host" value="${c.hostname}"></div>
      <div><label>Blocklist .bin URL</label><input id="blurl" value="${c.blocklistUrl}"></div>
      <div><label>Dashboard user</label><input id="wuser" value="${c.webUser}"></div>
      <div><label>Dashboard password</label><input id="wpass" type="password" placeholder="(unchanged)"></div>
    </div>
    <div class="row" style="margin-top:14px">
      <button class="btn" onclick="saveSettings()">Save</button>
      <button class="btn sec" onclick="updateNow()">Update blocklist now</button>
      <small class="mut" id="updmsg">last: ${c.updateLast}</small>
    </div>
    <div class="panel"><h2>Firmware update (OTA)</h2>
      <div class="row"><input type="file" id="fw" accept=".bin">
      <button class="btn" onclick="otaUpload()">Flash</button>
      <small class="mut" id="otamsg"></small></div></div>
    <div class="panel"><h2>Upload blocklist (.bin)</h2>
      <div class="row"><input type="file" id="bl" accept=".bin">
      <button class="btn" onclick="blUpload()">Upload</button>
      <small class="mut" id="blmsg"></small></div>
      <small class="mut">Build one with tools/build_blocklist.py, or use the auto-update URL above.</small></div>
    <div class="row" style="margin-top:14px">
      <button class="btn sec" onclick="act('/api/reset-stats','Reset statistics?')">Reset stats</button>
      <button class="btn sec" onclick="act('/api/reboot','Reboot device?')">Reboot</button>
      <button class="btn danger" onclick="act('/api/forget-wifi','Forget WiFi and reboot into setup?')">Forget WiFi</button>
    </div>`;
}
async function saveSettings(){
  const b = {upstream1:$('#up1').value,upstream2:$('#up2').value,blockMode:$('#bmode').value,
    updateHours:$('#uphrs').value,hostname:$('#host').value,blocklistUrl:$('#blurl').value,
    webUser:$('#wuser').value};
  if($('#wpass').value) b.webPass=$('#wpass').value;
  const r = await post('/api/config', b);
  alert(r.ok?'Saved.':'Failed ('+r.status+')');
}
async function updateNow(){
  await post('/api/update-now',{}); $('#updmsg').textContent='started...';
  setTimeout(async()=>{const c=await(await fetch('/api/config')).json();
    $('#updmsg').textContent='last: '+c.updateLast;},6000);
}
async function act(url,msg){if(!confirm(msg))return;const r=await post(url,{});
  if(r.ok)alert('OK');}
async function otaUpload(){
  const f=$('#fw').files[0]; if(!f){alert('pick a .bin');return;}
  $('#otamsg').textContent='uploading...';
  const fd=new FormData(); fd.append('firmware',f);
  const r=await authFetch('/update',{method:'POST',body:fd});
  $('#otamsg').textContent = r.ok?'done, rebooting...':'failed '+r.status;
}
async function blUpload(){
  const f=$('#bl').files[0]; if(!f){alert('pick a .bin');return;}
  $('#blmsg').textContent='uploading...';
  const fd=new FormData(); fd.append('blocklist',f);
  const r=await authFetch('/upload-blocklist',{method:'POST',body:fd});
  let msg='failed '+r.status;
  try{const j=await r.json(); msg=j.ok?('loaded '+j.domains.toLocaleString()+' domains'):('error: '+(j.error||''));}catch(e){}
  $('#blmsg').textContent=msg;
  if(r.ok) loadStats();
}

renderTabs(); renderView(); loadStats();
setInterval(loadStats, 4000);
setInterval(()=>{if(active===0||active===1)renderView();}, 6000);
)JS";

