(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const state = {
    mode: 'live', snapshot: null, selected: 'queue', tab: 'events', zoom: 1,
    demoPlaying: false, demoQueue: 14, demoInFlight: 2, demoWorkers: 2, demoStored: 37,
    events: [], demoTimer: null, refreshing: false, initialSnapshot: true,
  };
  let eventCursor = null;
  let modeGeneration = 0;
  let workerTopology = '';
  function streamIdAfter(a,b) {
    const [at,as] = a.split('-').map(Number);
    const [bt,bs] = b.split('-').map(Number);
    return at > bt || (at === bt && as > bs);
  }
  const nodes = {
    source: {name:'LTA DataMall', type:'External camera API', icon:'↯', description:'Live traffic camera metadata supplied by LTA DataMall. Camera coordinates represent camera locations, not vehicle GPS readings.', attributes:()=>[['API', 'Traffic-Imagesv2'],['Monitoring','Not instrumented'],['Data type','Camera metadata']]},
    producer: {name:'Producer', type:'Python ingestion service', icon:'⇣', description:'Fetches a camera record from LTA, writes a JSON object to S3, and sends its S3 reference to SQS.',attributes:()=>[['Container','Not monitored'],['Writes to','S3 + SQS'],['Source','LTA DataMall']]},
    s3:{name:'S3 Storage',type:'LocalStack object storage',icon:'▧',description:'Stores raw JSON objects. The SQS message carries the object reference (Claim-Check), not the entire payload.',attributes:()=>[['Endpoint','LocalStack'],['Bucket','lta-traffic-raw'],['Object monitoring','Not connected']]},
    queue:{name:'SQS Queue',type:'AWS-compatible message broker',icon:'✉',description:'Holds tasks pointing to S3 objects. Independent workers poll the queue and receive messages.',attributes:()=>[['Connection',serviceLabel('queue')],['Waiting',metric('queue','pending')],['In flight',metric('queue','inflight')],['Queue name','task-queue']]},
    database:{name:'PostgreSQL',type:'Cleaned-data store',icon:'▤',description:'Stores the latest observation for each unique vehicle_id. Current code uses camera IDs in vehicle_id; repeated camera IDs overwrite earlier rows.',attributes:()=>[['Connection',serviceLabel('database')],['Stored rows',metric('database','records')],['Uniqueness','vehicle_id'],['Schema','cleansed_traffic']]},
  };
  const edges = [
    {id:'source-producer',from:'source',to:'producer',style:'strong'},
    {id:'producer-s3',from:'producer',to:'s3',style:'storage-link'},
    {id:'producer-queue',from:'producer',to:'queue',style:'strong'},
    {id:'s3-worker1',from:'s3',to:'worker1',style:'storage-link'},
    {id:'queue-worker1',from:'queue',to:'worker1',style:'strong'},
    {id:'queue-worker2',from:'queue',to:'worker2',style:''},
    {id:'queue-worker3',from:'queue',to:'worker3',style:''},
    {id:'queue-worker4',from:'queue',to:'worker4',style:''},
    {id:'worker1-database',from:'worker1',to:'database',style:'strong'},
    {id:'worker2-database',from:'worker2',to:'database',style:''},
    {id:'worker3-database',from:'worker3',to:'database',style:''},
    {id:'worker4-database',from:'worker4',to:'database',style:''},
  ];
  const boxes = {
    source:[42,268,178,91], producer:[257,268,178,91], s3:[483,127,178,91],queue:[483,409,178,91],
    worker1:[746,174,178,59],worker2:[746,243,178,59],worker3:[746,312,178,59],worker4:[746,381,178,59],database:[970,268,177,91]
  };
  const activeNodes = new Set();
  const svgNS = 'http://www.w3.org/2000/svg';
  const fmt = x => x === null || x === undefined ? '—' : Number(x).toLocaleString();
  const time = () => new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  function metric(group,key) {
    if(state.mode==='demo') {
      if(group==='queue') return fmt(key==='pending'?state.demoQueue:state.demoInFlight);
      if(group==='database') return fmt(state.demoStored);
    }
    return fmt(state.snapshot?.[group]?.[key]);
  }
  function serviceLabel(group){if(state.mode==='demo')return 'Simulated';const s=state.snapshot?.[group];return !s?'Unknown':s.online?'Online':'Offline';}
  function log(message,level='info'){
    state.events.unshift({message,level,time:time()});state.events=state.events.slice(0,45);
    if(state.tab==='events')renderEvents();
  }
  function renderEvents(){
    const root=$('eventFeed');root.replaceChildren();
    if(!state.events.length){root.innerHTML='<div class="empty">Waiting for real service data…<br/>Switch to Demo mode to preview message flow.</div>';return;}
    for(const item of state.events){
      const el=document.createElement('div');el.className='feed-item';
      const dot=document.createElement('span');dot.className='feed-dot '+(item.level==='success'?'success':item.level==='warn'?'warn':item.level==='error'?'error':'');
      const copy=document.createElement('div');copy.className='feed-copy';copy.textContent=item.message;
      const t=document.createElement('time');t.textContent=item.time;copy.append(t);el.append(dot,copy);root.append(el);
    }
  }
  function renderRecords(){
    const root=$('recordFeed');root.replaceChildren();let rows=[];
    if(state.mode==='demo'){
      rows=[{vehicle_id:'CAM-5795', recorded_timestamp:new Date().toISOString(),latitude:1.3473,longitude:103.8191,speed_kmh:0},{vehicle_id:'CAM-2701',recorded_timestamp:new Date().toISOString(),latitude:1.3191,longitude:103.8957,speed_kmh:0}];
    }else{rows=state.snapshot?.database?.latest??[];}
    if(!rows.length){root.innerHTML='<div class="empty">No database records available.<br/>Start the worker and producer, or use Demo mode.</div>';return;}
    for(const row of rows){
      const card=document.createElement('div');card.className='record-card';
      const name=document.createElement('h4');name.textContent=row.vehicle_id+'  '+(state.mode==='demo'?'(DEMO)':'');
      const fields=document.createElement('p');fields.textContent=`${row.latitude.toFixed(5)}, ${row.longitude.toFixed(5)} · ${row.speed_kmh} km/h (placeholder)\n${(row.recorded_timestamp??'').replace('T',' ').slice(0,19)}`;
      card.append(name,fields);root.append(card);
    }
  }
  function renderInspect(){
    const entry = nodes[state.selected] || nodes.queue;
    $('inspectTitle').textContent=entry.name;$('inspectType').textContent=entry.type;$('inspectGlyph').textContent=entry.icon;$('inspectDescription').textContent=entry.description;
    $('inspectAttributes').replaceChildren();
    for(const [key,value] of entry.attributes()){
      const row=document.createElement('div');row.className='attr-row';const lab=document.createElement('span');lab.textContent=key;const val=document.createElement('strong');val.textContent=value;
      if(value==='Online'||value==='Simulated')val.classList.add('ok');if(value==='Offline')val.classList.add('bad');row.append(lab,val);$('inspectAttributes').append(row);
    }
    document.querySelectorAll('.graph-node, .worker-row').forEach(n=>n.classList.toggle('selected',n.dataset.node===state.selected));
  }
  function renderWorkers() {
    const root = $('workerNodes');
    const demo = state.mode === 'demo';
    const telemetry = state.snapshot?.workers;
    const workers = demo
      ? Array.from({length: state.demoWorkers}, (_,i) => ({
          id: `demo-${i+1}`, nodeKey: `worker${i+1}`,
          status: 'simulated', online: true, task: null,
        }))
      : (telemetry?.items ?? []).map(w => ({...w,nodeKey:`worker-${w.id}`}));
    const keys = new Set(workers.map(w=>w.nodeKey));
    const signature = workers.map(w=>w.nodeKey).join('|');
    const layoutChanged = signature !== workerTopology;
    for (const el of [...root.children]) {
      if (!keys.has(el.dataset.node)) el.remove();
    }
    for (const key of Object.keys(nodes)) {
      if (key.startsWith('worker') && !keys.has(key)) delete nodes[key];
    }
    if (layoutChanged || !workers.length) {
      for (let i=edges.length-1;i>=0;i--) {
        if (edges[i].from.startsWith('worker') || edges[i].to.startsWith('worker')) edges.splice(i,1);
      }
      for (const key of Object.keys(boxes)) {
        if (key.startsWith('worker')) delete boxes[key];
      }
    }
    workers.forEach((worker,index) => {
      const key=worker.nodeKey;
      nodes[key]={
        name:`Worker ${worker.id}`,type:demo?'Simulated worker':'Reporting Docker worker',icon:'⬡',
        description:'Consumes SQS tasks, validates S3 records and writes to PostgreSQL. Kubernetes deployment and autoscaling are not connected.',
        attributes:()=>[
          ['Status',worker.status],['Worker ID',worker.id],['Current task',worker.task||'None'],
          ['Last heartbeat',demo?'Simulated':new Date(worker.last_seen*1000).toLocaleTimeString()],
        ],
      };
      let row=[...root.children].find(el=>el.dataset.node===key);
      if(!row){
        row=document.createElement('button');row.type='button';row.className='worker-row';row.dataset.node=key;
        const icon=document.createElement('span');icon.className='worker-icon';icon.textContent='⬡';
        const label=document.createElement('span');label.className='worker-label';
        label.append(document.createElement('strong'),document.createElement('small'));
        const led=document.createElement('span');led.className='led';row.append(icon,label,led);
        row.addEventListener('click',()=>selectNode(key));root.append(row);
      }
      // Keep stable DOM nodes so polling does not steal focus or close inspectors.
      row.title=worker.id;
      row.querySelector('strong').textContent=demo?`worker-${index+1}`:`worker-${worker.id.slice(0,8)}`;
      row.querySelector('small').textContent=worker.status;
      row.classList.toggle('active',worker.online);
      row.classList.toggle('processing',worker.status==='processing');
      row.classList.toggle('unavailable',!worker.online);
      row.classList.toggle('selected',state.selected===key);
      if(layoutChanged){
        root.append(row);
        boxes[key]=[746,200+index*69,178,59];
        edges.push(
          {id:`queue-${key}`,from:'queue',to:key,style:'strong'},
          {id:`s3-${key}`,from:'s3',to:key,style:'storage-link'},
          {id:`${key}-database`,from:key,to:'database',style:'strong'},
        );
      }
    });
    if(!workers.length){
      const empty=document.createElement('div');empty.className='empty';
      empty.textContent=telemetry?.connected?'No workers reporting yet.':'Worker monitoring unavailable.';
      root.append(empty);
    }
    $('clusterPill').textContent=demo?`${workers.length} simulated`:telemetry?.connected?`${telemetry.replicas} online`:'Unknown';
    $('clusterFoot').textContent=demo?'Browser simulation':'Docker Compose · Kubernetes integration pending';
    if(layoutChanged || !workers.length){
      workerTopology=signature;
      const height=Math.max(660,320+workers.length*69);
      $('canvas').dataset.height=String(height);$('canvas').style.height=`${height}px`;
      $('connections').style.height=`${height}px`;
      $('connections').setAttribute('viewBox',`0 0 1160 ${height}`);
      $('packetLayer').replaceChildren();drawEdges();
      if(layoutChanged)window.dispatchEvent(new Event('topology-resized'));
    }
    if(!nodes[state.selected]){
      state.selected='queue';
      const popup=document.querySelector('.node-popup');if(popup)popup.hidden=true;
    }
  }

  function updateMetrics(){
    $('pendingMetric').textContent=metric('queue','pending');
    $('inflightMetric').textContent=metric('queue','inflight');
    $('recordsMetric').textContent=metric('database','records');
    $('workersMetric').textContent=state.mode==='demo'?state.demoWorkers:fmt(state.snapshot?.workers?.replicas);
    $('workersHelp').textContent=state.mode==='demo'?'Simulated workers':state.snapshot?.workers?.connected?'Workers with recent heartbeats':'Worker monitoring unavailable';
    $('queueNodeTag').textContent=metric('queue','pending');
    renderInspect(); if(state.tab==='records')renderRecords();
  }
  function selectNode(key){state.selected=key;renderInspect()}
  function setTab(tab){state.tab=tab;$('eventsPanel').classList.toggle('hidden',tab!=='events');$('recordsPanel').classList.toggle('hidden',tab!=='records');$('eventsTab').classList.toggle('active',tab==='events');$('recordsTab').classList.toggle('active',tab==='records');$('eventsTab').setAttribute('aria-selected',String(tab==='events'));$('recordsTab').setAttribute('aria-selected',String(tab==='records'));if(tab==='events')renderEvents();else renderRecords()}
  function makeSvg(tag,attrs){const e=document.createElementNS(svgNS,tag);for(const [key,value] of Object.entries(attrs||{}))e.setAttribute(key,String(value));return e}
  function drawEdges(){
    const layer=$('edgeLayer');layer.replaceChildren();
    for(const edge of edges){const a=boxes[edge.from],b=boxes[edge.to];const startX=a[0]+a[2],startY=a[1]+a[3]/2,endX=b[0],endY=b[1]+b[3]/2;
      let dx=(endX-startX);const c=Math.max(45,Math.abs(dx)*.43);
      const d=`M ${startX} ${startY} C ${startX+c} ${startY}, ${endX-c} ${endY}, ${endX} ${endY}`;
      const path=makeSvg('path',{id:`edge-${edge.id}`,d,class:`edge ${edge.style}`});layer.append(path);
    }
  }
  function spawnPacket(edgeId,color='#80bfff',duration=1900){
    const path=$(`edge-${edgeId}`);if(!path)return;
    const g=makeSvg('g',{class:'packet-envelope'});g.style.setProperty('--packet-color',color);
    const rect=makeSvg('rect',{x:-9,y:-6,width:18,height:12,rx:2,fill:'#1c3450',stroke:color,'stroke-width':1.6});
    const flap=makeSvg('path',{d:'M -7 -3 L 0 2 L 7 -3',fill:'none',stroke:color,'stroke-width':1.25});
    const movement=makeSvg('animateMotion',{dur:`${duration}ms`,fill:'freeze',repeatCount:1,rotate:'auto'});
    const mpath=makeSvg('mpath',{href:`#edge-${edgeId}`});movement.append(mpath);g.append(rect,flap,movement);$('packetLayer').append(g);
    // Must be connected to DOM before starting in Chromium.
    try{movement.beginElement()}catch(_){/* SVG animation may be disabled */}
    setTimeout(()=>g.remove(),duration+150);
  }
  function pulseSequence(steps){
    for(const [delay,edge,color] of steps)setTimeout(()=>{if(state.mode==='demo')spawnPacket(edge,color)},delay);
  }
  function demoTick(){
    if(state.mode!=='demo'||!state.demoPlaying)return;
    const phases=[
      ['source-producer','#86b8ff'],['producer-s3','#b89aff'],['producer-queue','#7bc8ff'],
      ['queue-worker1','#7bc8ff'],['s3-worker1','#b89aff'],['worker1-database','#56e7b7'],
    ];
    const phase=demoTick.counter++%phases.length;const [edge,color]=phases[phase];spawnPacket(edge,color,1250);
    if(phase===0){state.demoQueue=Math.min(80,state.demoQueue+4);log('Demo: producer ingested camera observations.');}
    if(phase===3){state.demoInFlight=Math.min(6,state.demoInFlight+1);state.demoQueue=Math.max(0,state.demoQueue-1);log('Demo: worker claimed an SQS message.');}
    if(phase===5){state.demoStored++;state.demoInFlight=Math.max(0,state.demoInFlight-1);state.demoQueue=Math.max(0,state.demoQueue-1);log('Demo: cleaned record persisted to PostgreSQL.','success');}
    const target=Math.min(4,Math.max(1,Math.ceil(state.demoQueue/10)));
    if(target!==state.demoWorkers){state.demoWorkers=target;log(`Demo: event-driven scaling target changed to ${target} pods.`,'warn');renderWorkers();}
    updateMetrics();
  }
  demoTick.counter=0;
  function startDemo(){
    if(state.demoTimer)clearInterval(state.demoTimer);
    state.demoPlaying=true;demoTick();state.demoTimer=setInterval(demoTick,1400);
    $('playPause').textContent='Ⅱ Pause demo';
  }
  function stopDemo(){state.demoPlaying=false;clearInterval(state.demoTimer);state.demoTimer=null;$('playPause').textContent='▶ Resume demo';}
  function setMode(mode){
    if(mode===state.mode)return;state.mode=mode;
    modeGeneration++;eventCursor=null;$('packetLayer').replaceChildren();
    $('liveMode').classList.toggle('active',mode==='live');$('demoMode').classList.toggle('active',mode==='demo');
    $('modeNotice').classList.toggle('is-demo',mode==='demo');
    $('modeNotice').textContent=mode==='demo'?'SIMULATION ONLY · Synthetic queue metrics, pod counts and animations. This does not start Kubernetes pods or modify real records.':'LIVE · Worker envelopes replay reported events; producer-to-queue activity is inferred from backlog changes.';
    $('playPause').disabled=mode!=='demo';$('demoBurst').disabled=mode!=='demo';
    $('connectionDot').className='status-dot '+(mode==='demo'?'demo':'pending');
    $('connectionLabel').textContent=mode==='demo'?'Demo simulation':'Connecting';
    $('footerNote').textContent=mode==='demo'?'Demo mode: all metrics and packets are synthetic':'Live worker reports · Kubernetes integration pending';
    state.events=[];
    if(mode==='demo'){log('Demo mode enabled: previewing an illustrative distributed system.','warn');startDemo();}else{stopDemo();log('Live mode: querying LocalStack and PostgreSQL.');void fetchSnapshot();}
    renderWorkers();updateMetrics();renderEvents();renderRecords();
  }
  function consumeWorkerEvents(telemetry) {
    if(!telemetry?.connected)return;
    const events=telemetry.events??[];
    const latest=events.at(-1)?.id;
    if(eventCursor===null){eventCursor=latest??'0-0';return;}
    if(latest && streamIdAfter(eventCursor,latest)) {
      log('Worker event feed restarted; resynchronizing.','warn');eventCursor=latest;return;
    }
    if(events.length===200 && streamIdAfter(events[0].id,eventCursor) && eventCursor!=='0-0') {
      log('Recent event window exceeded; some events may be missing.','warn');
    }
    for(const event of events){
      if(!streamIdAfter(event.id,eventCursor))continue;
      eventCursor=event.id;
      const key=`worker-${event.worker_id}`;
      const occurred=new Date(Number(event.timestamp)*1000).toLocaleTimeString();
      const descriptions={claimed:'claimed a task',downloaded:'downloaded its S3 record',stored:`stored ${event.detail}`,unchanged:`kept existing/newer record for ${event.detail}`,failed:`failed: ${event.detail}; task retained for retry`};
      log(`${occurred} · ${event.worker_id.slice(0,8)} · ${(event.task||'').slice(0,8)}: ${descriptions[event.kind]||event.kind}`,event.kind==='failed'?'error':event.kind==='stored'?'success':'info');
      if(!boxes[key])continue;
      if(event.kind==='claimed')spawnPacket(`queue-${key}`,'#2563eb',1200);
      if(event.kind==='downloaded')spawnPacket(`s3-${key}`,'#7c3aed',1200);
      if(event.kind==='stored')spawnPacket(`${key}-database`,'#059669',1200);
      const row=[...document.querySelectorAll('.worker-row')].find(el=>el.dataset.node===key);
      if(row){row.classList.remove('recent-event');void row.offsetWidth;row.classList.add('recent-event');}
    }
  }
  async function fetchSnapshot(){
    if(state.mode!=='live'||state.refreshing)return;
    const generation=modeGeneration;state.refreshing=true;
    try{
      const response=await fetch('/api/snapshot',{cache:'no-store',signal:AbortSignal.timeout(15000)});
      if(!response.ok)throw new Error(`HTTP ${response.status}`);
      const next=await response.json();
      if(state.mode!=='live'||generation!==modeGeneration)return;
      const previous=state.snapshot;
      if(!next.workers.connected && previous?.workers?.items){
        next.workers.items=previous.workers.items.map(w=>({...w,online:false,status:'unknown'}));
      }
      state.snapshot=next;
      $('connectionDot').className='status-dot online';$('connectionLabel').textContent='API connected';
      $('lastSynced').textContent=`Last sync ${new Date(next.timestamp).toLocaleTimeString()} · SQS ${next.queue.online?'online':'offline'} · DB ${next.database.online?'online':'offline'}`;
      $('modeNotice').textContent='LIVE · Worker envelopes replay reported events; producer-to-queue activity is inferred from backlog changes.';
      $('footerNote').textContent='Real worker reporting · Kubernetes integration pending';
      if(state.initialSnapshot){log('Connected to live pipeline monitoring.','success');state.initialSnapshot=false;}
      renderWorkers();updateMetrics();consumeWorkerEvents(next.workers);
      if(previous?.queue.online && next.queue.online && next.queue.pending>previous.queue.pending){
        log('Queue backlog increased (producer activity inferred).');spawnPacket('producer-queue','#2563eb',1200);
      }
    }catch(error){
      if(state.mode!=='live'||generation!==modeGeneration)return;
      $('connectionDot').className='status-dot offline';$('connectionLabel').textContent='API unavailable';
      $('lastSynced').textContent='Connection lost. Previously displayed metrics may be stale.';
      if(state.snapshot){state.snapshot.workers={connected:false,replicas:null,items:(state.snapshot.workers?.items??[]).map(w=>({...w,online:false,status:'unknown'})),events:[]};}
      renderWorkers();updateMetrics();
    }finally{state.refreshing=false;}
  }

  function adjustZoom(step){state.zoom=Math.min(1.4,Math.max(.65,Math.round((state.zoom+step)*100)/100));$('canvas').style.transform=`scale(${state.zoom})`;$('scroller').style.minHeight='400px';$('zoomPct').textContent=`${Math.round(state.zoom*100)}%`;
    // Scale takes visual space but not layout space; scroll size is maintained by canvas wrapper size.
    $('canvas').parentElement.style.setProperty('--canvas-zoom',state.zoom);
  }
  function wire(){
    document.querySelectorAll('.graph-node').forEach(el=>el.addEventListener('click',()=>selectNode(el.dataset.node)));
    $('liveMode').addEventListener('click',()=>setMode('live'));
    $('demoMode').addEventListener('click',()=>setMode('demo'));
    $('eventsTab').addEventListener('click',()=>setTab('events'));
    $('recordsTab').addEventListener('click',()=>setTab('records'));
    $('navRecords').addEventListener('click',()=>setTab('records'));
    $('navEvents').addEventListener('click',()=>setTab('events'));
    $('zoomIn').addEventListener('click',()=>adjustZoom(.1));$('zoomOut').addEventListener('click',()=>adjustZoom(-.1));$('zoomReset').addEventListener('click',()=>adjustZoom(1-state.zoom));
    $('playPause').addEventListener('click',()=>state.demoPlaying?stopDemo():startDemo());
    $('demoBurst').addEventListener('click',()=>{
      if(state.mode!=='demo')return;state.demoQueue=Math.min(100,state.demoQueue+25);
      log('Demo: injected 25 synthetic pending messages.','warn');
      const target=Math.min(4,Math.max(1,Math.ceil(state.demoQueue/10)));
      if(target!==state.demoWorkers){state.demoWorkers=target;renderWorkers();}
      updateMetrics();pulseSequence([[0,'source-producer','#8bc5ff'],[300,'producer-queue','#8bc5ff']]);
    });
  }
  drawEdges();wire();renderWorkers();renderEvents();renderRecords();renderInspect();log('Dashboard loaded. Connecting to read-only backend…');void fetchSnapshot();setInterval(fetchSnapshot,3000);
})();

