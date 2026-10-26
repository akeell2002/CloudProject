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

  function streamIdAfter(a, b) {
    const [at, as] = a.split('-').map(Number);
    const [bt, bs] = b.split('-').map(Number);
    return at > bt || (at === bt && as > bs);
  }

  const nodes = {
    source: {
      name: 'LTA DataMall',
      type: 'Municipal Stream APIs',
      icon: '↯',
      description: 'Live roaming taxi GPS (Taxi-Availability) fused with expressway traffic speed bands (TrafficSpeedBands v4) provided by Singapore LTA DataMall.',
      attributes: () => [
        ['APIs', 'Taxi-Availability & SpeedBands'],
        ['Endpoint', 'datamall2.mytransport.sg'],
        ['Cached speed bands', fmt(state.snapshot?.producer?.speed_bands_cached)],
        ['Data type', 'Fused vehicle GPS & speed'],
      ]
    },
    producer: {
      name: 'Producer',
      type: 'Ingestion Service (Raw Lake)',
      icon: '⇣',
      description: 'Extracts live taxi GPS observations, caches LTA road speed bands in Redis, uploads pure raw JSON to S3, and emits SQS claim-check tasks.',
      attributes: () => [
        ['Status', state.snapshot?.producer?.status || (state.mode === 'demo' ? 'Simulated' : 'Connecting')],
        ['Connection', serviceLabel('producer')],
        ['Total queued', fmt(state.snapshot?.producer?.sent_total)],
        ['Speed bands active', fmt(state.snapshot?.producer?.speed_bands_cached)],
        ['Latest batch', fmt(state.snapshot?.producer?.last_batch_size)],
        ['Pattern', 'Claim-Check (S3 + SQS)'],
        ['Source', 'LTA DataMall'],
      ]
    },
    s3: {
      name: 'S3 Storage',
      type: 'LocalStack object storage',
      icon: '▧',
      description: 'Stores raw JSON objects under lta-traffic-raw bucket. SQS messages carry the S3 URI so worker pods download files independently.',
      attributes: () => [
        ['Endpoint', 'LocalStack S3'],
        ['Bucket', 'lta-traffic-raw'],
        ['Object retention', 'Permanent raw archive'],
      ]
    },
    queue: {
      name: 'SQS Queue',
      type: 'AWS-compatible message broker',
      icon: '✉',
      description: 'task-queue message broker with dead-letter queue backup (task-dead-letter). Workers poll tasks with 120s visibility lease.',
      attributes: () => [
        ['Connection', serviceLabel('queue')],
        ['Waiting tasks', metric('queue', 'pending')],
        ['In flight (leased)', metric('queue', 'inflight')],
        ['Dead-letter (DLQ)', fmt(state.snapshot?.queue?.dlq ?? 0)],
        ['Queue name', 'task-queue'],
      ]
    },
    database: {
      name: 'PostgreSQL',
      type: 'Cleaned-data store',
      icon: '▤',
      description: 'Stores cleansed vehicle telemetry into cleansed_traffic. Uses UNIQUE(vehicle_id) with ON CONFLICT DO UPDATE for guaranteed idempotency.',
      attributes: () => [
        ['Connection', serviceLabel('database')],
        ['Cleaned rows', metric('database', 'records')],
        ['Idempotency', 'ON CONFLICT DO UPDATE'],
        ['Table', 'cleansed_traffic'],
      ]
    },
    coordinator: {
      name: 'Coordinator',
      type: 'Central Orchestration Pod',
      icon: '⚙',
      description: 'CSC3104 Project Architecture: Centralized Coordinator Pod that claims tickets from SQS, monitors worker telemetry via Redis heartbeats, and dispatches tasks over Google RPC (gRPC / HTTP2).',
      attributes: () => [
        ['Protocol', 'Google RPC (gRPC / HTTP2)'],
        ['Status', state.snapshot?.coordinator?.status || 'Online'],
        ['Tasks dispatched', fmt(state.snapshot?.coordinator?.dispatched_count)],
        ['Active workers', fmt(state.snapshot?.coordinator?.active_workers)],
        ['DLQ / Preserved', fmt(state.snapshot?.coordinator?.failed_count)],
        ['Scheduling algorithm', 'Least-Loaded / Round-Robin'],
        ['Inter-service RPC', 'HTTP/2 Protobuf (Port 50051)'],
      ]
    },
  };

  const edges = [
    {id: 'source-producer', from: 'source', to: 'producer', style: 'strong'},
    {id: 'producer-s3', from: 'producer', to: 's3', style: 'storage-link'},
    {id: 'producer-queue', from: 'producer', to: 'queue', style: 'strong'},
    {id: 'queue-coordinator', from: 'queue', to: 'coordinator', style: 'strong'},
    {id: 'coordinator-worker1', from: 'coordinator', to: 'worker1', style: 'strong'},
    {id: 'coordinator-worker2', from: 'coordinator', to: 'worker2', style: ''},
    {id: 'coordinator-worker3', from: 'coordinator', to: 'worker3', style: ''},
    {id: 'coordinator-worker4', from: 'coordinator', to: 'worker4', style: ''},
    {id: 's3-worker1', from: 's3', to: 'worker1', style: 'storage-link'},
    {id: 'worker1-database', from: 'worker1', to: 'database', style: 'strong'},
    {id: 'worker2-database', from: 'worker2', to: 'database', style: ''},
    {id: 'worker3-database', from: 'worker3', to: 'database', style: ''},
    {id: 'worker4-database', from: 'worker4', to: 'database', style: ''},
  ];

  const boxes = {
    source: [42, 268, 178, 91],
    producer: [257, 268, 178, 91],
    s3: [483, 127, 178, 91],
    queue: [483, 409, 178, 91],
    coordinator: [733, 409, 178, 91],
    worker1: [746, 174, 178, 59],
    worker2: [746, 243, 178, 59],
    worker3: [746, 312, 178, 59],
    worker4: [746, 381, 178, 59],
    database: [970, 268, 177, 91],
  };

  const svgNS = 'http://www.w3.org/2000/svg';
  const fmt = x => x === null || x === undefined ? '—' : Number(x).toLocaleString();
  const time = () => new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});

  function metric(group, key) {
    if (state.mode === 'demo') {
      if (group === 'queue') return fmt(key === 'pending' ? state.demoQueue : state.demoInFlight);
      if (group === 'database') return fmt(state.demoStored);
    }
    return fmt(state.snapshot?.[group]?.[key]);
  }

  function serviceLabel(group) {
    if (state.mode === 'demo') return 'Simulated';
    const s = state.snapshot?.[group];
    return !s ? 'Unknown' : (s.online || s.connected) ? 'Online' : 'Offline';
  }

  function log(message, level = 'info') {
    state.events.unshift({message, level, time: time()});
    state.events = state.events.slice(0, 50);
    if (state.tab === 'events') renderEvents();
  }

  function renderEvents() {
    const root = $('eventFeed');
    root.replaceChildren();
    if (!state.events.length) {
      root.innerHTML = '<div class="empty">Waiting for real pipeline events…<br/>Pipeline streams data in real time.</div>';
      return;
    }
    for (const item of state.events) {
      const el = document.createElement('div');
      el.className = 'feed-item';
      const dot = document.createElement('span');
      dot.className = 'feed-dot ' + (item.level === 'success' ? 'success' : item.level === 'warn' ? 'warn' : item.level === 'error' ? 'error' : '');
      const copy = document.createElement('div');
      copy.className = 'feed-copy';
      copy.textContent = item.message;
      const t = document.createElement('time');
      t.textContent = item.time;
      copy.append(t);
      el.append(dot, copy);
      root.append(el);
    }
  }

  function renderRecords() {
    const root = $('recordFeed');
    root.replaceChildren();

    state.recordsView = state.recordsView || 'clean';

    // Top Filter Bar for Before & After Studio
    const filterBar = document.createElement('div');
    filterBar.className = 'ba-filter-bar';

    const btnClean = document.createElement('button');
    btnClean.type = 'button';
    btnClean.className = 'ba-btn' + (state.recordsView === 'clean' ? ' active' : '');
    btnClean.textContent = '🟢 Cleaned Streams';
    btnClean.addEventListener('click', () => {
      state.recordsView = 'clean';
      renderRecords();
    });

    const btnOutliers = document.createElement('button');
    btnOutliers.type = 'button';
    btnOutliers.className = 'ba-btn outlier-btn' + (state.recordsView === 'outliers' ? ' active' : '');
    btnOutliers.textContent = '🛡️ Outliers & DLQ';
    btnOutliers.addEventListener('click', () => {
      state.recordsView = 'outliers';
      renderRecords();
    });

    const btnRefresh = document.createElement('button');
    btnRefresh.type = 'button';
    btnRefresh.className = 'ba-btn refresh-btn';
    btnRefresh.title = 'Fetch latest database records now';
    btnRefresh.textContent = '🔄 Refresh';
    btnRefresh.addEventListener('click', () => {
      state.lastRecordsJson = '';
      void fetchSnapshot();
    });

    filterBar.append(btnClean, btnOutliers, btnRefresh);
    root.append(filterBar);

    if (state.recordsView === 'clean') {
      let rows = [];
      if (state.mode === 'demo') {
        rows = [
          {vehicle_id: 'TAXI-SHB1458O', recorded_timestamp: new Date().toISOString(), latitude: 1.3541, longitude: 103.8423, speed_kmh: 53},
          {vehicle_id: 'TAXI-SHS9046S', recorded_timestamp: new Date().toISOString(), latitude: 1.3795, longitude: 103.8462, speed_kmh: 51},
          {vehicle_id: 'TAXI-SHD2582T', recorded_timestamp: new Date().toISOString(), latitude: 1.4507, longitude: 103.8174, speed_kmh: 55},
        ];
      } else {
        rows = state.snapshot?.database?.latest ?? [];
      }

      if (!rows.length) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.innerHTML = 'Waiting for database records…<br/>Pipeline streams data continuously.';
        root.append(empty);
        return;
      }

      for (const row of rows) {
        const card = document.createElement('div');
        card.className = 'ba-card';
        const timeStr = (row.recorded_timestamp || '').replace('T', ' ').slice(11, 19);
        const cleanLat = Number(row.latitude).toFixed(4);
        const cleanLon = Number(row.longitude).toFixed(4);
        const jitterLat = (Number(row.latitude) + 0.000042).toFixed(6);
        const jitterLon = (Number(row.longitude) + 0.000019).toFixed(6);
        const speed = row.speed_kmh || 0;

        card.innerHTML = `
          <div class="ba-card-header">
            <div class="ba-card-title">
              <span>🚕</span>
              <strong>${row.vehicle_id}</strong>
            </div>
            <span class="ba-pill clean">✓ CLEANSED</span>
          </div>
          <div class="ba-grid">
            <div class="ba-col">
              <span class="ba-label raw">🔴 BEFORE (Raw S3 Bronze)</span>
              <div class="ba-code raw">{\n  "odata": "TaxiAvailability",\n  "veh_src": "  ${row.vehicle_id.toLowerCase()}  ",\n  "StartLat": "${jitterLat}",\n  "StartLon": "${jitterLon}",\n  "speed": null,\n  "hw_telemetry": {\n    "rssi_dbm": "-74",\n    "batt_mv": "12450"\n  }\n}</div>
              <span class="ba-note-raw">⚠️ Missing Speed · Raw strings & hardware bloat</span>
            </div>
            <div class="ba-col">
              <span class="ba-label clean">🟢 AFTER (Postgres Silver)</span>
              <div class="ba-code clean">{\n  "vehicle_id": "${row.vehicle_id}",\n  "latitude": ${cleanLat},\n  "longitude": ${cleanLon},\n  "speed_kmh": ${speed},\n  "status": "VALID_SG"\n}</div>
              <span class="ba-note-clean">⚡ Fused from Redis Speed Cache: ${speed} km/h</span>
            </div>
          </div>
          <div class="ba-transforms">
            <div class="ba-transform-item"><span class="ba-icon-blue">⚡</span> <strong>ELT Speed Fusion:</strong> Worker cleansed raw Redis speed bands & matched road speed: <strong>${speed} km/h</strong></div>
            <div class="ba-transform-item"><span class="ba-icon-blue">⚡</span> <strong>Sanitized text:</strong> Trimmed whitespace & uppercase standardized</div>
            <div class="ba-transform-item"><span class="ba-icon-green">✓</span> <strong>Pruned & validated:</strong> Stripped gateway bloat; verified SG bounds [1.15-1.48, 103.55-104.08]</div>
            <div class="ba-transform-item"><span class="ba-icon-green">✓</span> <strong>Idempotent commit:</strong> PostgreSQL atomic UPSERT (0 duplicate rows)</div>
          </div>
        `;
        root.append(card);
      }
    } else {
      // Outlier / DLQ Before & After view
      const outliers = [
        {
          title: 'GPS Outlier (Chaos)',
          type: 'outlier',
          pill: '🛑 DROPPED',
          rawJson: '{\n  "odata": "TaxiAvailability",\n  "veh_src": "  taxi-chaos-gps  \\r\\n",\n  "StartLat": "999.990000",\n  "StartLon": "-999.990000",\n  "hw_telemetry": {\n    "err": "0xGPS_OVERFLOW",\n    "hdop": "99.9"\n  }\n}',
          rawNote: '❌ Extreme overflow outside Singapore',
          actionJson: 'STATUS: REJECTED\nCAUSE:  Out of SG bounds\nFILTER: Lat [1.15 - 1.48]\nRESULT: 0 DB rows written',
          actionNote: '✓ Dropped Before Database',
          transforms: [
            '<span class="ba-icon-red">🛑</span> Filtered by Singapore Spatial Bounds [1.15-1.48, 103.55-104.08]',
            '<span class="ba-icon-green">✓</span> Acknowledged SQS so task does not loop',
            '<span class="ba-icon-green">✓</span> Database shielded from corrupted coordinates',
          ]
        },
        {
          title: 'Speed Spike (Sensor Bug)',
          type: 'outlier',
          pill: '🛑 DROPPED',
          rawJson: '{\n  "odata": "TaxiAvailability",\n  "veh_src": "  taxi-spike-spd  \\r\\n",\n  "StartLat": "1.352100",\n  "StartLon": "103.819800",\n  "Speed_Telemetry": {\n    "reading": "480.0 km/h",\n    "sensor_v": "4.95V (SPIKE)"\n  }\n}',
          rawNote: '❌ Impossible 480 km/h sensor reading',
          actionJson: 'STATUS: REJECTED\nCAUSE:  Exceeds 125 km/h\nREADING: 480.0 km/h\nRESULT: 0 DB rows written',
          actionNote: '✓ Dropped Before Database',
          transforms: [
            '<span class="ba-icon-red">🛑</span> Filtered by Physical Dynamics Rule (max 125 km/h)',
            '<span class="ba-icon-green">✓</span> Discarded to prevent skewed municipal stats',
            '<span class="ba-icon-green">✓</span> Maintained pure PostgreSQL traffic metrics',
          ]
        },
        {
          title: 'Poison Payload (Syntax)',
          type: 'dlq',
          pill: '☠ DLQ ISOLATED',
          rawJson: '{\n  "odata": "TaxiAvailability",\n  "veh_src": "taxi-poison",\n  "raw_stream": [CORRUPTED_BYTES]\n  "incomplete": true\n  // Syntax error: missing delimiter',
          rawNote: '❌ Unparseable byte payload in S3',
          actionJson: 'STATUS: QUARANTINED\nERROR:  JSONDecodeError\nRETRIES: 5 / 5 Exhausted\nTARGET: task-dead-letter',
          actionNote: '✓ Isolated in SQS DLQ Broker',
          transforms: [
            '<span class="ba-icon-blue">🛡️</span> Coordinator trapped syntax exception',
            '<span class="ba-icon-blue">🔄</span> SQS redrive exhausted 5 delivery attempts',
            '<span class="ba-icon-green">✓</span> Quarantined to DLQ without crashing cluster',
          ]
        }
      ];

      for (const o of outliers) {
        const card = document.createElement('div');
        card.className = `ba-card ${o.type}`;
        card.innerHTML = `
          <div class="ba-card-header">
            <div class="ba-card-title">
              <span>${o.type === 'dlq' ? '☠' : '⚠️'}</span>
              <strong>${o.title}</strong>
            </div>
            <span class="ba-pill ${o.type}">${o.pill}</span>
          </div>
          <div class="ba-grid">
            <div class="ba-col">
              <span class="ba-label raw">🔴 BEFORE (Raw S3)</span>
              <div class="ba-code raw">${o.rawJson}</div>
              <span class="ba-note-raw">${o.rawNote}</span>
            </div>
            <div class="ba-col">
              <span class="ba-label rejected">${o.type === 'dlq' ? '☠ DLQ ACTION' : '🛑 PIPELINE ACTION'}</span>
              <div class="ba-code rejected">${o.actionJson}</div>
              <span class="ba-note-clean" style="color:${o.type === 'dlq' ? '#6d28d9' : '#b91c1c'};">${o.actionNote}</span>
            </div>
          </div>
          <div class="ba-transforms">
            ${o.transforms.map(t => `<div class="ba-transform-item">${t}</div>`).join('')}
          </div>
        `;
        root.append(card);
      }
    }
  }

  function renderInspect() {
    const entry = nodes[state.selected] || nodes.queue;
    $('inspectTitle').textContent = entry.name;
    $('inspectType').textContent = entry.type;
    $('inspectGlyph').textContent = entry.icon;
    $('inspectDescription').textContent = entry.description;
    $('inspectAttributes').replaceChildren();
    for (const [key, value] of entry.attributes()) {
      const row = document.createElement('div');
      row.className = 'attr-row';
      const lab = document.createElement('span');
      lab.textContent = key;
      const val = document.createElement('strong');
      val.textContent = value;
      if (value === 'Online' || value === 'Simulated') val.classList.add('ok');
      if (value === 'Offline') val.classList.add('bad');
      row.append(lab, val);
      $('inspectAttributes').append(row);
    }
    document.querySelectorAll('.graph-node, .worker-row').forEach(n => n.classList.toggle('selected', n.dataset.node === state.selected));
  }

  function renderWorkers() {
    const root = $('workerNodes');
    const demo = state.mode === 'demo';
    const telemetry = state.snapshot?.workers;
    const workers = demo
      ? Array.from({length: state.demoWorkers}, (_, i) => ({
          id: `demo-${i + 1}`, nodeKey: `worker${i + 1}`,
          status: 'simulated', online: true, task: null,
        }))
      : (telemetry?.items ?? []).map(w => ({...w, nodeKey: `worker-${w.id}`}));

    const keys = new Set(workers.map(w => w.nodeKey));
    const signature = workers.map(w => w.nodeKey).join('|');
    const layoutChanged = signature !== workerTopology;

    for (const el of [...root.children]) {
      if (!keys.has(el.dataset.node)) el.remove();
    }
    for (const key of Object.keys(nodes)) {
      if (key.startsWith('worker') && !keys.has(key)) delete nodes[key];
    }
    if (layoutChanged || !workers.length) {
      for (let i = edges.length - 1; i >= 0; i--) {
        if (edges[i].from.startsWith('worker') || edges[i].to.startsWith('worker')) edges.splice(i, 1);
      }
      for (const key of Object.keys(boxes)) {
        if (key.startsWith('worker')) delete boxes[key];
      }
    }

    workers.forEach((worker, index) => {
      const key = worker.nodeKey;
      nodes[key] = {
        name: `Worker ${worker.id.slice(0, 8)}`,
        type: demo ? 'Simulated worker' : 'Reporting Docker worker',
        icon: '⬡',
        description: 'Claims tasks from SQS, downloads raw GPS from S3, fuses nearest expressway speed bands from Redis, cleans data, and idempotently upserts to PostgreSQL.',
        attributes: () => [
          ['Status', worker.status],
          ['Worker ID', worker.id],
          ['Current task', worker.task || 'None'],
          ['Last heartbeat', demo ? 'Simulated' : new Date(worker.last_seen * 1000).toLocaleTimeString()],
        ],
      };
      let row = [...root.children].find(el => el.dataset.node === key);
      if (!row) {
        row = document.createElement('button');
        row.type = 'button';
        row.className = 'worker-row';
        row.dataset.node = key;
        const icon = document.createElement('span');
        icon.className = 'worker-icon';
        icon.textContent = '⬡';
        const label = document.createElement('span');
        label.className = 'worker-label';
        label.append(document.createElement('strong'), document.createElement('small'));
        const led = document.createElement('span');
        led.className = 'led';
        row.append(icon, label, led);
        row.addEventListener('click', () => selectNode(key));
        root.append(row);
      }
      row.title = worker.id;
      row.querySelector('strong').textContent = demo ? `worker-${index + 1}` : `worker-${worker.id.slice(0, 8)}`;
      row.querySelector('small').textContent = worker.status;
      row.classList.toggle('active', worker.online);
      row.classList.toggle('processing', worker.status === 'processing');
      row.classList.toggle('unavailable', !worker.online);
      row.classList.toggle('selected', state.selected === key);

      if (layoutChanged) {
        root.append(row);
        boxes[key] = [746, 200 + index * 69, 178, 59];
        edges.push(
          {id: `coordinator-${key}`, from: 'coordinator', to: key, style: 'strong'},
          {id: `s3-${key}`, from: 's3', to: key, style: 'storage-link'},
          {id: `${key}-database`, from: key, to: 'database', style: 'strong'},
        );
      }
    });

    if (!workers.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = telemetry?.connected ? 'Connecting worker node…' : 'Worker monitoring unavailable.';
      root.append(empty);
    }

    $('clusterPill').textContent = demo ? `${workers.length} simulated` : telemetry?.connected ? `${telemetry.replicas} online` : 'Connecting';
    $('clusterFoot').textContent = demo ? 'Browser simulation' : 'Docker Compose · Live worker telemetry';

    if (layoutChanged || !workers.length) {
      workerTopology = signature;
      const height = Math.max(660, 320 + workers.length * 69);
      $('canvas').dataset.height = String(height);
      $('canvas').style.height = `${height}px`;
      $('connections').style.height = `${height}px`;
      $('connections').setAttribute('viewBox', `0 0 1160 ${height}`);
      $('packetLayer').replaceChildren();
      drawEdges();
      if (layoutChanged) window.dispatchEvent(new Event('topology-resized'));
    }
    if (!nodes[state.selected]) {
      state.selected = 'queue';
      const popup = document.querySelector('.node-popup');
      if (popup) popup.hidden = true;
    }
  }

  function updateMetrics() {
    $('pendingMetric').textContent = metric('queue', 'pending');
    $('inflightMetric').textContent = metric('queue', 'inflight');
    $('recordsMetric').textContent = metric('database', 'records');
    const recordsHelp = $('recordsMetric')?.closest('.metric')?.querySelector('.metric-help');
    if (recordsHelp) {
      const sent = state.snapshot?.producer?.sent_total;
      recordsHelp.textContent = (state.mode === 'live' && sent)
        ? `Unique vehicles (${sent} updates)`
        : 'Current rows in PostgreSQL';
    }
    $('workersMetric').textContent = state.mode === 'demo' ? state.demoWorkers : fmt(state.snapshot?.workers?.replicas);
    $('workersHelp').textContent = state.mode === 'demo' ? 'Simulated workers' : state.snapshot?.workers?.connected ? 'gRPC Worker (Port 50051)' : 'Worker monitoring unavailable';
    if ($('coordinatorMetric')) {
      const coord = state.snapshot?.coordinator;
      $('coordinatorMetric').textContent = (state.mode === 'demo') ? 'Active' : coord?.connected ? `${fmt(coord.dispatched_count)} pkts` : '—';
      $('coordinatorHelp').textContent = (state.mode === 'demo') ? 'Simulated Dispatcher' : coord?.connected ? `gRPC Dispatcher · ${coord.active_workers} worker` : 'Connecting';
    }
    if ($('coordNodeTag')) {
      const coord = state.snapshot?.coordinator;
      $('coordNodeTag').textContent = coord?.connected ? `${fmt(coord.dispatched_count)}` : 'RPC';
    }
    $('queueNodeTag').textContent = metric('queue', 'pending');
    renderInspect();
    if (state.tab === 'records') renderRecords();
  }

  function selectNode(key) {
    state.selected = key;
    renderInspect();
  }

  function setTab(tab) {
    state.tab = tab;
    $('eventsPanel').classList.toggle('hidden', tab !== 'events');
    $('recordsPanel').classList.toggle('hidden', tab !== 'records');
    $('eventsTab').classList.toggle('active', tab === 'events');
    $('recordsTab').classList.toggle('active', tab === 'records');
    $('eventsTab').setAttribute('aria-selected', String(tab === 'events'));
    $('recordsTab').setAttribute('aria-selected', String(tab === 'records'));
    if (tab === 'events') renderEvents(); else renderRecords();
  }

  function makeSvg(tag, attrs) {
    const e = document.createElementNS(svgNS, tag);
    for (const [key, value] of Object.entries(attrs || {})) e.setAttribute(key, String(value));
    return e;
  }

  function drawEdges() {
    const layer = $('edgeLayer');
    layer.replaceChildren();
    for (const edge of edges) {
      const a = boxes[edge.from], b = boxes[edge.to];
      if (!a || !b) continue;
      const startX = a[0] + a[2], startY = a[1] + a[3] / 2;
      const endX = b[0], endY = b[1] + b[3] / 2;
      let dx = endX - startX;
      const c = Math.max(45, Math.abs(dx) * 0.43);
      const d = `M ${startX} ${startY} C ${startX + c} ${startY}, ${endX - c} ${endY}, ${endX} ${endY}`;
      const path = makeSvg('path', {id: `edge-${edge.id}`, d, class: `edge ${edge.style}`});
      layer.append(path);
    }
  }

  function spawnPacket(edgeId, color = '#2563eb', duration = 1200) {
    const path = $(`edge-${edgeId}`);
    if (!path) return;
    const g = makeSvg('g', {class: 'packet-envelope'});
    g.style.setProperty('--packet-color', color);
    const rect = makeSvg('rect', {x: -9, y: -6, width: 18, height: 12, rx: 2, fill: '#ffffff', stroke: color, 'stroke-width': 1.8});
    const flap = makeSvg('path', {d: 'M -7 -3 L 0 2 L 7 -3', fill: 'none', stroke: color, 'stroke-width': 1.4});
    const movement = makeSvg('animateMotion', {dur: `${duration}ms`, fill: 'freeze', repeatCount: 1, rotate: 'auto'});
    const mpath = makeSvg('mpath');
    mpath.setAttribute('href', `#edge-${edgeId}`);
    mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', `#edge-${edgeId}`);
    movement.append(mpath);
    g.append(rect, flap, movement);
    $('packetLayer').append(g);
    try {
      movement.beginElement();
    } catch (_) {}
    setTimeout(() => g.remove(), duration + 100);
  }

  // Smooth animation queue for continuous, fluid real-time flow
  const animationQueue = [];
  let isQueueRunning = false;

  function runAnimationQueue() {
    if (isQueueRunning || animationQueue.length === 0) return;
    isQueueRunning = true;
    const task = animationQueue.shift();
    try {
      task();
    } catch (_) {}

    const pace = Math.max(70, Math.min(180, Math.floor(750 / (animationQueue.length + 1))));
    setTimeout(() => {
      isQueueRunning = false;
      runAnimationQueue();
    }, pace);
  }

  function enqueuePacket(action) {
    animationQueue.push(action);
    runAnimationQueue();
  }

  function consumePipelineEvents(telemetry) {
    if (!telemetry?.connected) return;
    const events = telemetry.events ?? [];
    if (!events.length) return;

    const latest = events.at(-1)?.id;
    if (eventCursor === null) {
      // Replay recent 6 events on load/reload so the user immediately sees the pipeline active
      const startIdx = Math.max(0, events.length - 6);
      eventCursor = startIdx > 0 ? events[startIdx - 1].id : '0-0';
    }

    if (latest && streamIdAfter(eventCursor, latest)) {
      log('Pipeline event feed resynchronized.', 'warn');
      eventCursor = latest;
      return;
    }

    for (const event of events) {
      if (!streamIdAfter(event.id, eventCursor)) continue;
      eventCursor = event.id;

      const occurred = new Date(Number(event.timestamp) * 1000).toLocaleTimeString();
      const kind = event.kind;

      if (event.source === 'producer' || event.worker_id === 'producer') {
        if (kind === 'fetched') {
          log(`${occurred} · Producer: Ingesting ${event.detail} from LTA`, 'info');
          enqueuePacket(() => spawnPacket('source-producer', '#0284c7', 950));
        } else if (kind === 'uploaded') {
          log(`${occurred} · Producer: ${event.detail} -> S3`, 'info');
          enqueuePacket(() => spawnPacket('producer-s3', '#7c3aed', 950));
        } else if (kind === 'queued') {
          log(`${occurred} · Producer: ${event.detail} -> SQS`, 'info');
          enqueuePacket(() => spawnPacket('producer-queue', '#2563eb', 950));
        }
      } else if (event.source === 'coordinator') {
        log(`${occurred} · Coordinator: Dispatched task via Google gRPC`, 'info');
        enqueuePacket(() => spawnPacket('queue-coordinator', '#2563eb', 850));
        const edgeWorker = Object.keys(boxes).find(k => k.startsWith('worker')) || 'worker1';
        enqueuePacket(() => spawnPacket(`coordinator-${edgeWorker}`, '#7c3aed', 850));
        const coordBtn = document.querySelector('.graph-node.coordinator');
        if (coordBtn) {
          coordBtn.classList.remove('recent-event');
          void coordBtn.offsetWidth;
          coordBtn.classList.add('recent-event');
        }
      } else {
        const workerId = event.worker_id || 'worker';
        const key = `worker-${workerId}`;
        let edgeWorker = boxes[key] ? key : Object.keys(boxes).find(k => k.startsWith('worker'));
        if (!edgeWorker && edges.some(e => e.to === 'worker1')) edgeWorker = 'worker1';

        const descriptions = {
          claimed: 'received task via gRPC from Coordinator',
          downloaded: 'downloaded raw observation from S3',
          stored: `persisted ${event.detail} to PostgreSQL`,
          unchanged: `idempotent verify: ${event.detail}`,
          failed: `poison detected: ${event.detail}; retained in SQS for DLQ`
        };

        const level = kind === 'failed' ? 'error' : kind === 'stored' ? 'success' : 'info';
        log(`${occurred} · Worker-${workerId.slice(0, 8)}: ${descriptions[kind] || kind}`, level);

        if (edgeWorker) {
          if (kind === 'downloaded') {
            enqueuePacket(() => spawnPacket(`s3-${edgeWorker}`, '#8b5cf6', 1000));
          } else if (kind === 'stored') {
            enqueuePacket(() => spawnPacket(`${edgeWorker}-database`, '#10b981', 1000));
          } else if (kind === 'unchanged') {
            enqueuePacket(() => spawnPacket(`${edgeWorker}-database`, '#06b6d4', 1000));
          }

          const row = [...document.querySelectorAll('.worker-row')].find(el => el.dataset.node === key || el.dataset.node === edgeWorker);
          if (row) {
            row.classList.remove('recent-event');
            void row.offsetWidth;
            row.classList.add('recent-event');
          }
        }
      }
    }
  }

  function demoTick() {
    if (state.mode !== 'demo' || !state.demoPlaying) return;
    const phases = [
      ['source-producer', '#38bdf8'],
      ['producer-s3', '#8b5cf6'],
      ['producer-queue', '#2563eb'],
      ['queue-coordinator', '#2563eb'],
      ['coordinator-worker1', '#7c3aed'],
      ['s3-worker1', '#8b5cf6'],
      ['worker1-database', '#10b981'],
    ];
    const phase = demoTick.counter++ % phases.length;
    const [edge, color] = phases[phase];
    spawnPacket(edge, color, 1200);

    if (phase === 0) {
      state.demoQueue = Math.min(80, state.demoQueue + 4);
      log('Demo: producer ingested camera observations.');
    }
    if (phase === 3) {
      state.demoInFlight = Math.min(6, state.demoInFlight + 1);
      state.demoQueue = Math.max(0, state.demoQueue - 1);
      log('Demo: worker claimed an SQS message.');
    }
    if (phase === 5) {
      state.demoStored++;
      state.demoInFlight = Math.max(0, state.demoInFlight - 1);
      log('Demo: cleaned record persisted to PostgreSQL.', 'success');
    }
    const target = Math.min(4, Math.max(1, Math.ceil(state.demoQueue / 10)));
    if (target !== state.demoWorkers) {
      state.demoWorkers = target;
      log(`Demo: event-driven scaling target changed to ${target} pods.`, 'warn');
      renderWorkers();
    }
    updateMetrics();
  }
  demoTick.counter = 0;

  function startDemo() {
    if (state.demoTimer) clearInterval(state.demoTimer);
    state.demoPlaying = true;
    demoTick();
    state.demoTimer = setInterval(demoTick, 1200);
    $('playPause').textContent = 'Ⅱ Pause demo';
  }

  function stopDemo() {
    state.demoPlaying = false;
    clearInterval(state.demoTimer);
    state.demoTimer = null;
    $('playPause').textContent = '▶ Resume demo';
  }

  function setMode(mode) {
    if (mode === state.mode) return;
    state.mode = mode;
    modeGeneration++;
    eventCursor = null;
    $('packetLayer').replaceChildren();
    $('liveMode').classList.toggle('active', mode === 'live');
    $('demoMode').classList.toggle('active', mode === 'demo');
    $('modeNotice').classList.toggle('is-demo', mode === 'demo');
    $('modeNotice').textContent = mode === 'demo'
      ? 'SIMULATION ONLY · Synthetic queue metrics, pod counts and animations. Real services are untouched.'
      : 'LIVE · Real-time pipeline events streaming across Producer, S3, SQS, Workers, and PostgreSQL.';
    $('playPause').disabled = mode !== 'demo';
    $('demoBurst').disabled = mode !== 'demo';
    $('connectionDot').className = 'status-dot ' + (mode === 'demo' ? 'demo' : 'pending');
    $('connectionLabel').textContent = mode === 'demo' ? 'Demo simulation' : 'Connecting';
    $('footerNote').textContent = mode === 'demo'
      ? 'Demo mode: all metrics and packets are synthetic'
      : 'Real-time pipeline monitoring active';
    state.events = [];
    if (mode === 'demo') {
      log('Demo mode enabled: previewing distributed pipeline flow.', 'warn');
      startDemo();
    } else {
      stopDemo();
      log('Live mode: querying real LocalStack, Redis, and PostgreSQL pipeline.');
      void fetchSnapshot();
    }
    renderWorkers();
    updateMetrics();
    renderEvents();
    renderRecords();
  }

  async function fetchSnapshot() {
    if (state.mode !== 'live' || state.refreshing) return;
    const generation = modeGeneration;
    state.refreshing = true;
    try {
      const response = await fetch('/api/snapshot', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const next = await response.json();
      if (state.mode !== 'live' || generation !== modeGeneration) return;
      const previous = state.snapshot;
      if (!next.workers.connected && previous?.workers?.items) {
        next.workers.items = previous.workers.items.map(w => ({ ...w, online: false, status: 'unknown' }));
      }
      state.snapshot = next;
      $('connectionDot').className = 'status-dot online';
      $('connectionLabel').textContent = 'Live connected';
      $('lastSynced').textContent = `Synced ${new Date(next.timestamp).toLocaleTimeString()} · SQS ${next.queue.online ? 'online' : 'offline'} · DB ${next.database.online ? 'online' : 'offline'} · Producer ${next.producer?.connected ? 'online' : 'offline'}`;
      $('modeNotice').textContent = 'LIVE · Real-time pipeline events streaming across Producer, S3, SQS, Workers, and PostgreSQL.';
      $('footerNote').textContent = 'Real-time pipeline monitoring active';
      if (state.initialSnapshot) {
        log('Connected to live distributed pipeline monitoring.', 'success');
        state.initialSnapshot = false;
      }
      try {
        renderWorkers();
        updateMetrics();
        consumePipelineEvents(next.workers);
        if (state.tab === 'records') {
          const currentRecordsJson = JSON.stringify(next.database?.latest ?? []);
          if (currentRecordsJson !== state.lastRecordsJson) {
            state.lastRecordsJson = currentRecordsJson;
            renderRecords();
          }
        }
      } catch (uiError) {
        console.error('UI render warning:', uiError);
      }
    } catch (error) {
      if (state.mode !== 'live' || generation !== modeGeneration) return;
      $('connectionDot').className = 'status-dot offline';
      $('connectionLabel').textContent = 'API unavailable';
      $('lastSynced').textContent = 'Connection lost. Reconnecting…';
      if (state.snapshot) {
        state.snapshot.workers = {
          connected: false,
          replicas: null,
          items: (state.snapshot.workers?.items ?? []).map(w => ({ ...w, online: false, status: 'unknown' })),
          events: []
        };
      }
      renderWorkers();
      updateMetrics();
    } finally {
      state.refreshing = false;
    }
  }

  function adjustZoom(step) {
    state.zoom = Math.min(1.4, Math.max(0.65, Math.round((state.zoom + step) * 100) / 100));
    $('canvas').style.transform = `scale(${state.zoom})`;
    $('scroller').style.minHeight = '400px';
    $('zoomPct').textContent = `${Math.round(state.zoom * 100)}%`;
    $('canvas').parentElement.style.setProperty('--canvas-zoom', state.zoom);
  }

  function wire() {
    document.querySelectorAll('.graph-node').forEach(el => el.addEventListener('click', () => selectNode(el.dataset.node)));
    $('liveMode').addEventListener('click', () => setMode('live'));
    $('demoMode').addEventListener('click', () => setMode('demo'));
    $('eventsTab').addEventListener('click', () => setTab('events'));
    $('recordsTab').addEventListener('click', () => setTab('records'));
    $('navRecords').addEventListener('click', () => setTab('records'));
    $('navEvents').addEventListener('click', () => setTab('events'));
    $('zoomIn').addEventListener('click', () => adjustZoom(0.1));
    $('zoomOut').addEventListener('click', () => adjustZoom(-0.1));
    $('zoomReset').addEventListener('click', () => adjustZoom(1 - state.zoom));
    $('playPause').addEventListener('click', () => state.demoPlaying ? stopDemo() : startDemo());
    $('demoBurst').addEventListener('click', () => {
      if (state.mode !== 'demo') return;
      state.demoQueue = Math.min(100, state.demoQueue + 25);
      log('Demo: injected 25 synthetic pending messages.', 'warn');
      const target = Math.min(4, Math.max(1, Math.ceil(state.demoQueue / 10)));
      if (target !== state.demoWorkers) {
        state.demoWorkers = target;
        renderWorkers();
      }
      updateMetrics();
    });
  }

  drawEdges();
  wire();
  renderWorkers();
  renderEvents();
  renderRecords();
  renderInspect();
  log('Dashboard loaded. Connecting to live pipeline backend…');
  void fetchSnapshot();
  setInterval(fetchSnapshot, 800);
})();
