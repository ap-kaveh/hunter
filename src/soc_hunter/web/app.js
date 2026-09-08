'use strict';
let csrf = '', selected = null, settings = null, jobs = [], polling = null;
const $ = id => document.getElementById(id);
const stageNames = {searching_firewall:'Screening firewall activity',preparing:'Preparing investigation',reading_demo:'Reading synthetic logs',searching_current_window:'Searching selected window',searching_baseline:'Building historical baseline',gathering_evidence:'Gathering supporting evidence',analyzing_evidence:'Analyzing evidence',investigating:'Investigating candidates',finished:'Run finished',stopped:'Stopped at checkpoint',failed:'Needs attention'};
function el(tag, text, cls) {const node=document.createElement(tag); if(text!==undefined) node.textContent=text;if(cls)node.className=cls;return node;}
function notice(message,error=false){$('notice').textContent=message;$('notice').classList.remove('hidden');$('notice').classList.toggle('error',error);}
async function api(path,options={}){
  const response=await fetch(path,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...options.headers}});
  let data={};try{data=await response.json();}catch{}
  if(!response.ok){if(response.status===401&&path!=='/api/login')signedOut();throw new Error(typeof data.detail==='string'?data.detail:'Request failed. Check the input and try again.');}
  return data;
}
function signedOut(){csrf='';$('workspace').classList.add('hidden');$('login-screen').classList.remove('hidden');clearInterval(polling);}
async function signedIn(session){csrf=session.csrf;$('login-screen').classList.add('hidden');$('workspace').classList.remove('hidden');await loadSettings();await refresh();clearInterval(polling);polling=setInterval(()=>refresh().catch(()=>{}),2000);}
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const form=new FormData(event.target);try{const session=await api('/api/login',{method:'POST',body:JSON.stringify({username:form.get('username'),password:form.get('password')})});event.target.elements.password.value='';$('login-error').textContent='';await signedIn(session);}catch(error){$('login-error').textContent=error.message;}});
$('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST'});}finally{signedOut();}};
document.querySelectorAll('[data-view]').forEach(button=>button.onclick=()=>showView(button.dataset.view));
function showView(view){document.querySelectorAll('.view').forEach(node=>node.classList.toggle('hidden',node.id!=='view-'+view));document.querySelectorAll('.nav').forEach(node=>node.classList.toggle('active',node.dataset.view===view));$('breadcrumb').textContent='Workspace / '+({hunts:'Hunts',connections:'Connections',configuration:'Configuration',rules:'Hunting rules',monitor:'Monitoring',readiness:'Deployment readiness'}[view]);}
function date(value){if(!value)return '—';return new Date(value).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});}
function badge(status){return el('span',status.replaceAll('_',' '),'badge '+status);}
async function refresh(){jobs=await api('/api/jobs');renderJobs();if(selected)renderDetails(jobs.find(job=>job.id===selected));}
function renderJobs(){
  $('metric-active').textContent=jobs.filter(j=>['running','stopping'].includes(j.status)).length;
  $('metric-complete').textContent=jobs.filter(j=>j.status==='complete').length;
  $('metric-findings').textContent=jobs.reduce((sum,j)=>sum+(j.progress.finding_count||0),0);
  $('run-count').textContent=jobs.length+' runs';$('empty-state').classList.toggle('hidden',jobs.length>0);
  const tbody=$('jobs-table');tbody.replaceChildren();
  jobs.forEach(job=>{const row=el('tr');row.classList.toggle('selected',job.id===selected);row.tabIndex=0;row.setAttribute('aria-label','Open '+job.mode+' hunt '+job.id.slice(0,8));
    const first=el('td');first.append(el('span',job.mode==='demo'?'Synthetic hunt':'WAF investigation'));if(job.mode==='demo')first.append(el('span','DEMO','demo-tag'));first.append(el('small',job.id.slice(0,8)+' · '+(job.mode==='demo'?'12-hour fixture':date(job.start)+' → '+date(job.end))));
    const status=el('td');status.append(badge(job.status));row.append(first,status,el('td',String(job.progress.finding_count||0)),el('td',date(job.created_at)));
    const open=()=>{selected=job.id;renderJobs();renderDetails(job);};row.onclick=open;row.onkeydown=e=>{if(e.key==='Enter')open();};tbody.append(row);
  });
}
function renderDetails(job){
  if(!job)return;const root=$('run-detail');root.replaceChildren();const p=job.progress;
  root.append(badge(job.status),el('p',job.mode==='demo'?'Synthetic demo · no tickets':'Live investigation · analyst review required','muted'));
  root.append(el('h3',stageNames[p.stage]||'Starting worker'));
  const total=p.candidate_budget||0, done=(p.finding_count||0)+(p.candidate_failures||[]).length;
  const progress=el('progress');progress.max=Math.max(total,1);progress.value=done;progress.setAttribute('aria-label','Candidates processed');root.append(progress);
  root.append(el('p',total?`${Math.min(done,total)} of ${total} candidates processed`:'Discovering candidates; no completion estimate yet.','muted'));
  if(p.active_candidate)root.append(el('p',p.active_candidate.source+' · '+p.active_candidate.application));
  root.append(el('div','FINDINGS SAVED','detail-label'),el('div',String(p.finding_count||0),'detail-number'));
  if(p.resume_count)root.append(el('p','Resumed '+p.resume_count+' time(s). Completed findings preserved.','muted'));
  const actions=el('div',undefined,'actions');
  if(job.status==='running'){const stop=el('button','Stop hunt','danger');stop.onclick=()=>control(job.id,'stop');actions.append(stop);}
  if(['stopped','failed','partial'].includes(job.status)){const resume=el('button','Resume hunt','primary');resume.onclick=()=>control(job.id,'resume');actions.append(resume);}
  if(job.mode==='live'&&['complete','partial'].includes(job.status)&&(p.finding_count||0)>0){const publish=el('button','Send findings to Zammad','secondary');publish.onclick=async()=>{publish.disabled=true;try{const result=await api('/api/jobs/'+job.id+'/publish',{method:'POST'});notice(`${result.created} tickets created; ${result.already_sent} already sent; ${result.needs_reconciliation} need delivery reconciliation.`);}catch(error){notice(error.message,true);}finally{publish.disabled=false;}};actions.append(publish);}
  root.append(actions);
  if(['complete','partial'].includes(job.status)){const link=el('a','Download report ↗');link.href='/api/jobs/'+job.id+'/report';root.append(link);}
  root.append(el('div','COVERAGE & LIMITATIONS','detail-label'));const list=el('ul');(p.coverage_gaps||[]).forEach(gap=>list.append(el('li',gap)));if(!list.children.length)list.append(el('li','Coverage will be recorded as the hunt progresses.'));root.append(list);
  if(p.error_type)root.append(el('p','Worker stopped: '+p.error_type+'. Check connections and configuration.','error'));
  if((p.candidate_failures||[]).length)root.append(el('p',p.candidate_failures.length+' candidate(s) need another investigation attempt.','error'));
}
async function control(id,action){try{await api('/api/jobs/'+id+'/'+action,{method:'POST'});notice(action==='stop'?'Stop requested. Active work will be interrupted and completed findings retained.':'Resuming with the original configuration. Initial searches may run again.');await refresh();}catch(error){notice(error.message,true);}}
$('demo-start').onclick=async()=>{try{const job=await api('/api/jobs',{method:'POST',body:JSON.stringify({mode:'demo'})});selected=job.id;notice('Synthetic demo started. It runs slowly enough to try stop and resume.');await refresh();}catch(error){notice(error.message,true);}};
function localInput(value){const local=new Date(value.getTime()-value.getTimezoneOffset()*60000);return local.toISOString().slice(0,16);}
$('new-hunt').onclick=()=>{const end=new Date();$('hunt-end').value=localInput(end);$('hunt-start').value=localInput(new Date(end.getTime()-12*3600000));$('hunt-dialog').showModal();};
$('close-dialog').onclick=()=>$('hunt-dialog').close();
$('hunt-form').onsubmit=async event=>{event.preventDefault();try{const job=await api('/api/jobs',{method:'POST',body:JSON.stringify({mode:'live',start:new Date($('hunt-start').value).toISOString(),end:new Date($('hunt-end').value).toISOString()})});selected=job.id;$('hunt-dialog').close();notice('Live hunt started. Findings will be saved for review.');await refresh();}catch(error){$('hunt-dialog').close();notice(error.message,true);}};
const serviceNames={splunk:'Splunk · sh3',postgres:'PostgreSQL',model:'Local model',zammad:'Zammad'};
async function loadSettings(){const data=await api('/api/config');settings=data.config;$('yaml-editor').value=data.yaml;renderConnections();renderSettings();await loadRules();}
function renderConnections(){const root=$('connection-cards');root.replaceChildren();
  Object.keys(serviceNames).forEach(service=>{const card=el('article',undefined,'panel connection-card');card.append(el('div',service==='model'?'AI':serviceNames[service][0],'service-icon'),el('h2',serviceNames[service]));const config=settings[service];
    card.append(el('p',service==='postgres'?config.host+':'+config.port:config.url||config.base_url,'endpoint'));
    const result=el('p','Not tested in this session.','connection-result');const actions=el('div',undefined,'actions');const test=el('button','Test connection','secondary');test.onclick=async()=>{test.disabled=true;result.textContent='Testing…';try{const data=await api('/api/check/'+service,{method:'POST'});result.textContent=data.ok?'Connection verified.':data.message+(data.error_type?' ('+data.error_type+')':'');result.classList.toggle('error',!data.ok);}catch(error){result.textContent=error.message;}finally{test.disabled=false;}};
    const configure=el('button','Edit settings','secondary');configure.onclick=()=>showView('configuration');actions.append(test,configure);card.append(actions,result);
    const label=el('label',service==='postgres'?'Replace database password':'Replace API token / key');const input=el('input');input.type='password';input.autocomplete='new-password';input.placeholder='Leave blank to keep the saved secret';label.append(input);card.append(label);
    const save=el('button','Save secret','secondary');save.onclick=async()=>{if(!input.value)return;save.disabled=true;try{const result=await api('/api/secrets/'+service,{method:'PUT',body:JSON.stringify({value:input.value})});input.value='';notice(result.message);await loadSettings();}catch(error){notice(error.message,true);}finally{save.disabled=false;}};card.append(save);root.append(card);
  });
}
const formSections=[
  ['splunk','Splunk search connection',[['url','Management API URL'],['web_url','Splunk Web URL (optional)'],['ca_file','Trusted CA file'],['search_timeout_seconds','Search timeout (seconds)','number'],['max_results','Maximum aggregate rows','number'],['timestamp_validated','Event timestamp alignment verified','checkbox']]],
  ['postgres','PostgreSQL persistence',[['host','Writable cluster endpoint'],['port','Port','number'],['database','Database'],['username','Service account'],['ca_file','Trusted CA file']]],
  ['model','Model server',[['mode','Mode','select',['mock','live']],['base_url','Model API URL'],['name','Served model name'],['ca_file','Trusted CA file (HTTPS only)'],['max_tokens','Maximum output tokens','number']]],
  ['zammad','Finding tickets',[['url','Zammad URL'],['group_id','SOC group ID','number'],['customer_id','Internal service customer ID','number'],['ca_file','Trusted CA file'],['enabled','Enable finding publication','checkbox'],['approval_enforcement_verified','Tier 2 closure permissions tested in Zammad','checkbox']]],
  ['hunts','Hunt limits',[['firewall_enabled','Enable FortiGate screening','checkbox'],['max_window_hours','Maximum window (hours)','number'],['baseline_days','Historical baseline (days)','number'],['max_candidates','Candidates per hunt','number'],['evidence_per_candidate','Selected events per candidate','number'],['max_followups','Follow-up searches per candidate','number']]]
];
function renderSettings(){const root=$('settings-form');root.replaceChildren();formSections.forEach(([section,title,fields])=>{const panel=el('section',undefined,'panel settings-section');panel.append(el('h2',title));fields.forEach(([key,label,type='text',values])=>{const wrap=el('label',type==='checkbox'?undefined:label);let input;if(type==='select'){input=el('select');values.forEach(value=>{const option=el('option',value);option.value=value;input.append(option);});}else{input=el('input');input.type=type;}
    if(type==='checkbox'){input.checked=!!settings[section][key];wrap.append(input,document.createTextNode(label));}else{input.value=settings[section][key]??'';wrap.append(input);}
    input.onchange=()=>{settings[section][key]=type==='checkbox'?input.checked:type==='number'?(input.value===''?null:Number(input.value)):(input.value||null);};panel.append(wrap);});root.append(panel);});}
$('settings-form').onsubmit=event=>event.preventDefault();
async function saveConfig(text){try{const result=await api('/api/config',{method:'PUT',body:JSON.stringify({yaml:text})});notice(result.message);await loadSettings();}catch(error){notice(error.message,true);}}
$('save-config').onclick=()=>saveConfig(JSON.stringify(settings));$('save-yaml').onclick=()=>saveConfig($('yaml-editor').value);
api('/api/session').then(signedIn).catch(()=>signedOut());
async function loadRules(){const data=await api('/api/rules');$('rules-version').textContent='Ruleset '+data.version+' · '+data.rules.length+' rules';const root=$('rule-cards');root.replaceChildren();data.rules.forEach(rule=>{const card=el('article',undefined,'panel connection-card');card.append(el('small',rule.source==='firewall'?'FORTIGATE':'FORTIWEB'),el('h2',rule.title),badge(rule.enabled?'enabled':'disabled'),el('p',rule.id,'endpoint'),el('p','Needs: '+rule.fields),el('p','Consider: '+rule.alternatives,'muted'));if(rule.attack)card.append(el('p',rule.attack));Object.entries(rule.settings).forEach(([name,value])=>card.append(el('p',name+': '+JSON.stringify(value),'endpoint')));root.append(card);});}

let monitorBusy=false;
function metricNumber(value,suffix=''){return value===null||value===undefined?'Unavailable':Number(value).toLocaleString(undefined,{maximumFractionDigits:1})+suffix;}
function metricBytes(value){if(value===null||value===undefined)return 'Unavailable';const units=['B','KiB','MiB','GiB','TiB'];let unit=0;while(value>=1024&&unit<units.length-1){value/=1024;unit++;}return metricNumber(value,' '+units[unit]);}
function monitorTable(id,headers,rows){const root=$(id);root.replaceChildren();if(!rows.length){root.append(el('p','No devices or counters visible.','muted'));return;}const table=el('table'),head=el('thead'),tr=el('tr'),body=el('tbody');headers.forEach(h=>tr.append(el('th',h)));head.append(tr);rows.forEach(row=>{const r=el('tr');row.forEach(value=>r.append(el('td',value)));body.append(r);});table.append(head,body);root.append(table);}
function monitorChart(history){const canvas=$('monitor-chart'),ctx=canvas.getContext('2d');ctx.clearRect(0,0,canvas.width,canvas.height);ctx.strokeStyle='#dbe5e5';[0,50,100].forEach(n=>{ctx.beginPath();ctx.moveTo(0,150-n*1.4);ctx.lineTo(1000,150-n*1.4);ctx.stroke();});if(history.length<2)return;const first=Date.parse(history[0].timestamp),last=Date.parse(history.at(-1).timestamp);if(last<=first)return;const gpuIds=[...new Set(history.flatMap(s=>Object.keys(s.gpu_pct)))];const series=[['#0d9488',s=>s.cpu_pct],['#2563eb',s=>s.memory_pct],...gpuIds.map((id,i)=>[['#ea580c','#9333ea','#c026d3','#ca8a04'][i%4],s=>s.gpu_pct[id]])];series.forEach(([color,get])=>{ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();let previous=null;history.forEach(sample=>{const value=get(sample),time=Date.parse(sample.timestamp);if(value===null||value===undefined){previous=null;return;}const x=(time-first)/(last-first)*1000,y=150-Math.max(0,Math.min(100,value))*1.4;if(previous===null||time-previous>15000)ctx.moveTo(x,y);else ctx.lineTo(x,y);previous=time;});ctx.stroke();});}
function renderMonitor(data){$('monitor-status').textContent='Updated '+new Date(data.timestamp).toLocaleTimeString()+' · five-second samples';$('monitor-status').classList.remove('error');$('monitor-scope').textContent=data.scope;const root=$('monitor-metrics');root.replaceChildren();[['CPU busy',metricNumber(data.cpu.busy_pct,'%'),metricNumber(data.cpu.logical_cpus,' visible logical CPUs')],['RAM used',metricNumber(data.memory.used_pct,'%'),metricBytes(data.memory.available_bytes)+' available'],['CPU I/O wait',metricNumber(data.cpu.iowait_pct,'%'),'Time waiting for I/O; not disk latency'],['Swap used',metricBytes(data.memory.swap_used_bytes),metricBytes(data.memory.swap_total_bytes)+' total']].forEach(([title,value,detail])=>{const card=el('article');card.append(el('span',title),el('strong',value),el('small',detail));root.append(card);});
$('gpu-message').textContent=data.gpu.message;const cards=$('gpu-cards');cards.replaceChildren();data.gpu.devices.forEach(gpu=>{const card=el('article',undefined,'panel connection-card');card.append(el('h2','GPU '+gpu.index+' · '+gpu.name),el('p','Utilization: '+metricNumber(gpu.utilization_pct,'%')),el('p','VRAM: '+metricNumber(gpu.memory_used_mib,' MiB')+' / '+metricNumber(gpu.memory_total_mib,' MiB')),el('p','Temperature: '+metricNumber(gpu.temperature_c,' °C')),el('p','Power: '+metricNumber(gpu.power_w,' W')+' / '+metricNumber(gpu.power_limit_w,' W')));cards.append(card);});
monitorTable('monitor-filesystems',['Filesystem','Used','Free','Total'],data.filesystems.map(d=>[d.label,metricNumber(d.used_pct,'%'),metricBytes(d.free_bytes),metricBytes(d.total_bytes)]));const limits=$('monitor-limits');limits.replaceChildren();if(data.cgroup){limits.append(el('p','Current cgroup memory: '+metricBytes(data.cgroup.memory_used_bytes)),el('p','Configured cgroup memory ceiling: '+(data.cgroup.memory_limit_bytes===null?'No local ceiling / unavailable':metricBytes(data.cgroup.memory_limit_bytes))),el('p','Configured CPU quota: '+(data.cgroup.cpu_quota_cores===null?'No local quota / unavailable':metricNumber(data.cgroup.cpu_quota_cores,' cores'))),el('small','Ancestor limits may be tighter. This is not total host usage.','muted'));}else limits.append(el('p','Cgroup v2 resource limits are not visible.','muted'));
monitorTable('monitor-disks',['Device','Read / s','Write / s','Read IOPS','Write IOPS','Busy ms / s'],data.disk_io.map(d=>[d.device,metricBytes(d.read_bytes),metricBytes(d.write_bytes),metricNumber(d.read_ops),metricNumber(d.write_ops),metricNumber(d.busy_ms)]));
monitorTable('monitor-network',['Interface','Receive / s','Send / s','RX errors / s','TX errors / s','RX drops / s','TX drops / s'],data.network.map(n=>[n.interface,metricBytes(n.rx_bytes),metricBytes(n.tx_bytes),metricNumber(n.rx_errors),metricNumber(n.tx_errors),metricNumber(n.rx_drops),metricNumber(n.tx_drops)]));$('monitor-notes').textContent=data.notes.join(' ');$('monitor-history').textContent=data.history.length+' samples in memory · '+new Date(data.history[0].timestamp).toLocaleTimeString()+' to '+new Date(data.timestamp).toLocaleTimeString();monitorChart(data.history);}
async function refreshMonitor(){if(!csrf||document.hidden||$('view-monitor').classList.contains('hidden')||monitorBusy)return;monitorBusy=true;try{const data=await api('/api/monitor');if(csrf)renderMonitor(data);}catch(error){$('monitor-status').textContent='Monitoring unavailable; displayed readings may be stale. '+error.message;$('monitor-status').classList.add('error');}finally{monitorBusy=false;}}
document.querySelector('[data-view="monitor"]').addEventListener('click',()=>refreshMonitor());
document.addEventListener('visibilitychange',()=>refreshMonitor());
setInterval(refreshMonitor,5000);
