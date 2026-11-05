/* Live data is read-only. Demo data is explicitly isolated in demo.js. */
(function () {
  "use strict";
  function networkRoute(event, positions) {
    if (!event) return null;
    function resolve(endpoint) {
      const exact = positions.find(function (p) { return p.node.node_id === endpoint; });
      if (exact) return exact;
      try {
        const address = new URL(/^https?:\/\//.test(endpoint) ? endpoint : "http://" + endpoint);
        return positions.find(function (p) {
          return address.hostname === p.node.node_id || address.host === new URL(p.node.address).host;
        });
      } catch (_) { return undefined; }
    }
    const source = resolve(event.source);
    const target = resolve(event.target);
    const services = ["consortium", "firewall"];
    const external = ["message", "threat", "blocked"].includes(event.kind);
    return {
      source: source ? {x: source.x, y: source.y, kind: "node", label: source.node.node_id} :
        services.includes(event.source) ? {x: 65, y: 50, kind: "service", label: event.source} :
        {x: 26, y: 50, kind: external ? "external" : "endpoint", label: event.source || "Unknown sender"},
      target: target ? {x: target.x, y: target.y, kind: "node", label: target.node.node_id} :
        {x: 65, y: 50, kind: "service", label: event.target || "Unknown receiver"},
      attack: ["threat", "invalid", "blocked"].includes(event.kind),
    };
  }
  function rememberSender(events, positions, previous) {
    for (let i = events.length - 1; i >= 0; i--) {
      const route = networkRoute(events[i], positions);
      if (["external", "endpoint"].includes(route.source.kind)) {
        return {source: route.source, attack: route.attack};
      }
    }
    return previous || null;
  }
  if (typeof module !== "undefined" && module.exports) module.exports = {networkRoute, rememberSender};
  if (typeof document === "undefined") return;
  const $ = function (id) { return document.getElementById(id); };
  let data = {nodes: [], events: [], bans: [], updated_at: null};
  let selectedProposal = "";
  let selectedObserver = "";
  let selectedNode = "";
  let fetching = false;
  let networkKey = "";
  let incidentKey = "";
  let lastSender = null;
  let controls = {enabled: false, connected: false, runtime: {}};
  let actionBusy = false;
  let controlledNode = "";
  const points = [[65, 11], [88, 37], [79, 74], [51, 74], [42, 37]];
  const securityKinds = ["threat", "blocked", "invalid", "proposal", "vote", "commit"];
  const reasonNames = {1: "Spam", 2: "Bot activity", 3: "Phishing", 4: "Suspicious file", 5: "Hate speech"};

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }
  function time(value) {
    return value ? new Date(value).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "Unknown";
  }
  function isAttack(event) { return ["threat", "invalid", "blocked"].includes(event.kind); }
  function empty(symbol, title, description) {
    const box = el("div", "empty-state");
    box.append(el("span", "empty-symbol", symbol), el("h3", "", title), el("p", "", description));
    return box;
  }
  function onlineNodes() { return data.nodes.filter(function (node) { return node.online; }); }
  function proposals() {
    return data.nodes.filter(function (node) { return node.online && node.telemetry_available; })
      .flatMap(function (node) {
        return (node.proposals || []).map(function (p) { return Object.assign({}, p, {observer: node.node_id}); });
      }).sort(function (a, b) { return b.created_at - a.created_at; });
  }
  function openNode(nodeId) {
    selectedNode = nodeId;
    renderNodeDetails();
    if (!$("node-dialog").open) $("node-dialog").showModal();
  }
  function renderNodeDetails() {
    const node = data.nodes.find(function (n) { return n.node_id === selectedNode; });
    if (!node) return;
    $("node-dialog-title").textContent = node.node_id;
    const details = $("node-details");
    details.replaceChildren();
    const grid = el("div", "detail-grid");
    [
      ["Connection", node.online ? "Active / reachable" : "Inactive / unreachable"],
      ["Reported role", node.online ? node.state : node.last_known_state || "Unknown"],
      ["Endpoint", node.address],
      ["Last committed sequence", node.last_sequence === undefined ? "Unknown" : node.last_sequence],
      ["Epoch", node.epoch === undefined ? "Unknown" : node.epoch],
      ["Last seen", time(node.last_seen)]
    ].forEach(function (item) {
      const field = el("div", "detail-item");
      field.append(el("span", "", item[0]), el("strong", "", item[1]));
      grid.append(field);
    });
    details.append(grid, el("h3", "ledger-heading", node.node_id + "'s peer reputation ledger"),
      el("p", "ledger-note", "These are this node's observations, not a shared trust percentage." +
        (node.online ? "" : " Showing last-known data.")));
    if ((node.quarantined_by || []).length) {
      details.append(el("p", "ledger-note", "Quarantine reported by: " + node.quarantined_by.join(", ")));
    }
    if (!(node.reputations || []).length) {
      details.append(el("p", "ledger-note", "No peer reputation records reported."));
      return;
    }
    const table = el("table");
    const head = el("thead");
    const header = el("tr");
    ["Peer", "Score", "Voting eligibility"].forEach(function (text) { header.append(el("th", "", text)); });
    head.append(header);
    const body = el("tbody");
    node.reputations.forEach(function (rep) {
      const row = el("tr");
      const eligible = rep.trust_score >= 30 && Boolean(rep.is_active);
      row.append(el("td", "", rep.peer_id), el("td", "", rep.trust_score + " / 100"),
        el("td", "", eligible ? "Eligible" : "Quarantined"));
      body.append(row);
    });
    table.append(head, body);
    details.append(table);
  }
  function svgLine(x1, y1, x2, y2, className) {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    Object.entries({x1: x1, y1: y1, x2: x2, y2: y2, class: className}).forEach(function (entry) {
      line.setAttribute(entry[0], String(entry[1]));
    });
    return line;
  }
  function transmission(svg, route, recent) {
    const ns = "http://www.w3.org/2000/svg";
    const defs = document.createElementNS(ns, "defs");
    const marker = document.createElementNS(ns, "marker");
    Object.entries({id: "message-arrow", viewBox: "0 0 10 10", refX: 5, refY: 5,
      markerWidth: 8, markerHeight: 8, orient: "auto", markerUnits: "userSpaceOnUse"}).forEach(function (entry) {
      marker.setAttribute(entry[0], String(entry[1]));
    });
    const arrow = document.createElementNS(ns, "path");
    arrow.setAttribute("d", "M 0 0 L 10 5 L 0 10 Z");
    arrow.setAttribute("fill", route.attack ? "var(--red)" : "var(--cyan)");
    marker.append(arrow);
    defs.append(marker);
    svg.append(defs);
    const line = document.createElementNS(ns, "polyline");
    const from = route.source, to = route.target;
    line.setAttribute("points", [
      [from.x * 6, from.y * 3.1], [(from.x + to.x) * 3, (from.y + to.y) * 1.55],
      [to.x * 6, to.y * 3.1]
    ].map(function (point) { return point.join(","); }).join(" "));
    line.setAttribute("class", "message-path" + (route.attack ? " attack" : "") + (recent ? "" : " historical"));
    line.setAttribute("marker-mid", "url(#message-arrow)");
    svg.append(line);
  }
  function renderNetwork() {
    const latest = data.events[data.events.length - 1];
    const positions = data.nodes.map(function (node, index) {
      const point = data.nodes.length <= 5 ? points[index] :
        [65 + 23 * Math.cos(2 * Math.PI * index / data.nodes.length - Math.PI / 2),
         43 + 31 * Math.sin(2 * Math.PI * index / data.nodes.length - Math.PI / 2)];
      return {node: node, x: point[0], y: point[1]};
    });
    lastSender = rememberSender(data.events, positions, lastSender);
    const nextKey = JSON.stringify([
      data.nodes.map(function (n) { return [n.node_id, n.online, n.state, n.quarantined]; }),
      latest, lastSender, Boolean(latest && Date.now() - latest.timestamp < 8000)
    ]);
    if (nextKey === networkKey) return;
    networkKey = nextKey;
    const svg = $("network-lines");
    const layer = $("network-nodes");
    svg.replaceChildren();
    layer.replaceChildren();
    positions.forEach(function (point) {
      svg.append(svgLine(point.x * 6, point.y * 3.1, 390, 155,
        "mesh-line" + (point.node.online ? "" : " offline")));
      const node = point.node;
      const fault = node.online && (node.quarantined || String(node.state).startsWith("BYZANTINE"));
      const button = el("button", "mesh-node" + (!node.online ? " offline" : fault ? " fault" : ""));
      button.style.left = point.x + "%";
      button.style.top = point.y + "%";
      button.setAttribute("aria-label", "Inspect " + node.node_id + ", " + (node.online ? node.state : "inactive"));
      const circle = el("span", "node-circle", node.node_id.split("-").pop());
      if (node.online && node.state === "LEADER") circle.append(el("span", "node-star", "★"));
      const role = !node.online ? "INACTIVE" : node.quarantined ? "QUARANTINE REPORTED" : fault ? "FAULT MODE" :
        node.state === "LEADER" ? "LEADER" : node.state === "UNKNOWN" ? "ROLE UNKNOWN" : "FOLLOWER";
      button.append(circle, el("span", "node-name", node.node_id), el("span", "node-role", role));
      button.addEventListener("click", function () { openNode(node.node_id); });
      layer.append(button);
    });
    $("mesh-caption").textContent = onlineNodes().length + " / " + data.nodes.length + " reachable";
    const label = $("message-label");
    label.classList.toggle("attack", Boolean(latest && isAttack(latest)));
    label.textContent = latest ? "Latest: " + latest.source + " → " + latest.target + " · " + latest.kind :
      "No observed transmissions yet";
    label.title = latest ? label.textContent + " · " + time(latest.timestamp) : label.textContent;
    const route = networkRoute(latest, positions);
    const sender = $("external-sender");
    const serviceEndpoint = $("service-endpoint");
    sender.classList.toggle("attack", Boolean(lastSender && lastSender.attack));
    $("sender-type").textContent = lastSender && lastSender.source.kind === "endpoint" ? "SENDER ENDPOINT" : "EXTERNAL SERVER";
    $("sender-domain").textContent = lastSender ? lastSender.source.label : "Awaiting sender";
    $("sender-domain").title = lastSender ? lastSender.source.label : "";
    $("sender-status").textContent = !lastSender ? "Waiting for traffic" :
      lastSender.attack ? "Last message flagged" : "Last message received";
    sender.setAttribute("aria-label", lastSender ? "Last sender: " + lastSender.source.label : "External server: waiting for traffic");
    serviceEndpoint.hidden = !route || (route.source.kind !== "service" && route.target.kind !== "service");
    $("mesh-center").hidden = !serviceEndpoint.hidden;
    if (route) {
      const endpoint = route.target.kind === "service" ? route.target : route.source;
      $("service-label").textContent = endpoint.label;
      $("service-type").textContent = route.target.kind === "service" ? "DESTINATION" : "SOURCE";
      transmission(svg, route, Date.now() - latest.timestamp < 8000);
    }
    [["active", true], ["inactive", false]].forEach(function (group) {
      const nodes = data.nodes.filter(function (node) { return Boolean(node.online) === group[1]; });
      $(group[0] + "-group-count").textContent = nodes.length;
      const list = $(group[0] + "-servers");
      list.replaceChildren();
      nodes.forEach(function (node) {
        const fault = node.online && (node.quarantined || String(node.state).startsWith("BYZANTINE"));
        const button = el("button", "server-tag" + (!node.online ? " offline" : fault ? " fault" : ""), node.node_id);
        button.title = node.online ? node.state : "Unreachable at the last check";
        button.addEventListener("click", function () { openNode(node.node_id); });
        list.append(button);
      });
      if (!nodes.length) list.append(el("span", "empty-inline", group[1] ? "No servers reachable" : "All servers reachable"));
    });
  }
  function updateOptions(select, options) {
    const existing = Array.from(select.options).map(function (option) { return [option.text, option.value]; });
    if (JSON.stringify(existing) !== JSON.stringify(options)) {
      select.replaceChildren();
      options.forEach(function (option) { select.append(new Option(option[0], option[1])); });
    }
  }
  function renderIncident() {
    const all = proposals();
    const unique = Array.from(new Map(all.map(function (p) { return [p.proposal_id, p]; })).values());
    const select = $("proposal-select");
    if (!unique.some(function (p) { return p.proposal_id === selectedProposal; })) {
      selectedProposal = unique.length ? unique[0].proposal_id : "";
    }
    updateOptions(select, unique.length ? unique.map(function (p) {
      return [p.domain + (p.committed ? " · committed" : " · pending"), p.proposal_id];
    }) : [["No proposals observed", ""]]);
    select.value = selectedProposal;
    select.disabled = !unique.length;
    const observations = all.filter(function (p) { return p.proposal_id === selectedProposal; })
      .sort(function (a, b) { return Number(b.observer === b.proposer) - Number(a.observer === a.proposer); });
    let proposal = observations.find(function (p) { return p.observer === selectedObserver; }) || observations[0];
    selectedObserver = proposal ? proposal.observer : "";
    const nextKey = JSON.stringify([proposal, observations.map(function (p) { return p.observer; }),
      data.nodes.map(function (n) { return [n.node_id, n.online]; }),
      data.events.filter(function (e) { return proposal ? e.domain === proposal.domain : e.kind === "threat"; })]);
    if (nextKey === incidentKey) return;
    incidentKey = nextKey;
    const content = $("incident-content");
    content.replaceChildren();
    const state = $("incident-state");
    $("incident-panel").classList.toggle("has-threat", Boolean(proposal && !proposal.committed));
    if (!proposal) {
      const latestThreat = data.events.slice().reverse().find(function (e) { return e.kind === "threat"; });
      state.className = "pill " + (latestThreat ? "danger" : "neutral");
      state.textContent = latestThreat ? "THREAT DETECTED" : "MONITORING";
      content.append(empty(latestThreat ? "!" : "◇", latestThreat ? latestThreat.domain || latestThreat.source : "Waiting for a proposal",
        latestThreat ? latestThreat.message + " No proposal state is available yet." :
        "When a node proposes a domain block, its reported votes and outcome appear here."));
      return;
    }
    state.className = "pill " + (proposal.committed ? "success" : "danger");
    state.textContent = proposal.committed ? "BLOCK REPORTED" : "THREAT FLAGGED";
    const inner = el("div", "incident-content-inner");
    inner.append(el("span", "threat-eyebrow", proposal.committed ? "REPORTED DOMAIN BLOCK" : "DOMAIN UNDER REVIEW"),
      el("h3", "threat-domain", proposal.domain));
    const evidence = data.events.slice().reverse().find(function (e) {
      return e.domain === proposal.domain && ["threat", "proposal"].includes(e.kind);
    });
    inner.append(el("div", "evidence", evidence ? evidence.message : reasonNames[proposal.reason] || "Domain moderation proposal"));
    const status = el("div", "decision-status");
    status.append(el("span", "", "Recorded approvals"), el("strong", "", proposal.approvals.length + " / " + proposal.quorum + " needed"));
    inner.append(status);
    const progress = el("div", "progress");
    progress.setAttribute("role", "progressbar");
    progress.setAttribute("aria-label", "Recorded approvals");
    progress.setAttribute("aria-valuemin", "0");
    progress.setAttribute("aria-valuemax", String(proposal.quorum));
    progress.setAttribute("aria-valuenow", String(Math.min(proposal.approvals.length, proposal.quorum)));
    const fill = el("div", "progress-fill");
    fill.style.width = Math.min(100, proposal.approvals.length / proposal.quorum * 100) + "%";
    progress.append(fill);
    inner.append(progress);
    const votes = el("div", "vote-grid");
    const voteEvents = data.events.filter(function (e) {
      return e.proposal_id === proposal.proposal_id && e.observer === proposal.observer && e.decision;
    });
    const voterIds = Array.from(new Set(data.nodes.map(function (n) { return n.node_id; }).concat(proposal.approvals)));
    voterIds.forEach(function (id) {
      const node = data.nodes.find(function (n) { return n.node_id === id; });
      const event = voteEvents.slice().reverse().find(function (e) { return e.source === id; });
      const decision = event ? event.decision : proposal.approvals.includes(id) ? "APPROVE" :
        node && !node.online ? "OFFLINE" : "WAITING";
      const names = {APPROVE: "Approve", REJECT: "Reject", INVALID: "Invalid", QUARANTINED: "Excluded", OFFLINE: "Offline", WAITING: "Waiting"};
      const card = el("div", "vote-card " + decision.toLowerCase());
      card.append(el("span", "vote-icon", decision === "APPROVE" ? "✓" : ["INVALID", "REJECT", "QUARANTINED"].includes(decision) ? "×" : "…"),
        el("span", "vote-name", id), el("span", "vote-state", names[decision] || decision));
      if (event) card.title = event.message;
      votes.append(card);
    });
    inner.append(votes);
    const observer = el("div", "observer-row");
    const label = el("label", "field-label", "Observed by");
    label.htmlFor = "observer-select";
    const observerSelect = el("select");
    observerSelect.id = "observer-select";
    observations.forEach(function (p) { observerSelect.append(new Option(p.observer, p.observer)); });
    observerSelect.value = selectedObserver;
    observerSelect.addEventListener("change", function () { selectedObserver = observerSelect.value; renderIncident(); });
    observer.append(label, observerSelect);
    inner.append(observer, el("p", "observation",
      proposal.committed ? "This observer reports a local commit. Check the banned list for coverage on other servers." :
      "Votes are this observer's local records. Waiting does not mean rejection; a proposal is not a committed ban."));
    content.append(inner);
  }
  function renderEvents() {
    const rows = $("event-rows");
    rows.replaceChildren();
    const events = data.events.filter(function (event) {
      return $("event-filter").value === "all" || securityKinds.includes(event.kind);
    }).slice(-40).reverse();
    events.forEach(function (event) {
      const row = el("tr", isAttack(event) ? "attack-row" : "");
      const route = el("td", "traffic-route");
      route.append(el("span", "", event.source), el("span", "arrow", " → "), el("span", "", event.target));
      const kind = el("td");
      kind.append(el("span", "activity-tag", event.kind.toUpperCase()));
      const detail = el("td", "traffic-detail", event.message);
      detail.title = "Observed by " + event.observer;
      row.append(el("td", "", time(event.timestamp)), route, kind, detail);
      rows.append(row);
    });
    if (!events.length) {
      const row = el("tr");
      const cell = el("td", "table-empty", "No activity observed yet. Incoming posts and consensus messages will appear here.");
      cell.colSpan = 4;
      row.append(cell);
      rows.append(row);
    }
  }
  function renderBans() {
    const list = $("banned-list");
    list.replaceChildren();
    const query = $("ban-search").value.trim().toLowerCase();
    const bans = data.bans.filter(function (ban) { return ban.domain.toLowerCase().includes(query); });
    $("banned-badge").textContent = data.bans.length;
    bans.forEach(function (ban) {
      const row = el("div", "ban-item");
      const text = el("div");
      const complete = ban.applied_on.length === data.nodes.length;
      text.append(el("div", "ban-domain", ban.domain),
        el("div", "ban-coverage" + (complete ? " complete" : ""),
          "Reported on " + ban.applied_on.length + " / " + data.nodes.length + " configured servers"),
        el("div", "ban-nodes", ban.applied_on.join(" · ") || "No current confirmations"));
      if (ban.last_known_on.length) text.append(el("div", "ban-nodes", "Last known: " + ban.last_known_on.join(" · ")));
      row.append(el("span", "ban-icon", "⊘"), text);
      list.append(row);
    });
    if (!bans.length) list.append(el("div", "ban-empty", query ? "No domains match your search." : "No reported domain blocks."));
  }
  function render() {
    const active = onlineNodes().length;
    const allProposals = proposals();
    const committed = new Set(allProposals.filter(function (p) { return p.committed; }).map(function (p) { return p.proposal_id; }));
    const pending = new Set(allProposals.filter(function (p) { return !p.committed && !committed.has(p.proposal_id); }).map(function (p) { return p.proposal_id; }));
    $("active-count").textContent = active;
    $("inactive-count").textContent = data.nodes.length - active;
    $("total-label").textContent = "/ " + data.nodes.length + " configured";
    $("threat-count").textContent = pending.size;
    $("ban-count").textContent = data.bans.length;
    $("updated").textContent = "Updated " + time(data.updated_at);
    $("connection").textContent = "";
    $("connection").append(el("i"), document.createTextNode(active ? "Live observations" : "No nodes reachable"));
    $("connection").classList.toggle("connected", active > 0);
    const notice = $("live-notice");
    const oldNodes = data.nodes.filter(function (n) { return n.online && !n.telemetry_available; }).length;
    notice.hidden = active > 0 && !oldNodes;
    notice.textContent = !active ? "No servers are reachable. Start the cluster with start-cluster.bat." :
      oldNodes + " server(s) are online without telemetry. Rebuild or restart updated nodes to see votes and activity.";
    renderNetwork();
    renderIncident();
    renderEvents();
    renderBans();
    renderControls();
    if ($("node-dialog").open) renderNodeDetails();
  }
  async function refresh() {
    if (fetching) return;
    fetching = true;
    $("refresh").disabled = true;
    try {
      const responses = await Promise.all([
        fetch("/api/cluster", {cache: "no-store", signal: AbortSignal.timeout(5000)}),
        fetch("/api/controls", {cache: "no-store", signal: AbortSignal.timeout(5000)})
      ]);
      const response = responses[0];
      if (!response.ok) throw new Error("Dashboard API unavailable");
      const next = await response.json();
      if (responses[1].ok) controls = await responses[1].json();
      else controls = {enabled: false, connected: false, runtime: {}, message: "Restart the updated dashboard to enable live controls."};
      data = next;
      if (controls.enabled && !controls.connected && data.nodes && data.nodes.some(function (n) { return n.online; })) {
        runAction({action: "connect", leader: "fednode-0"});
      }
      render();
    } catch (error) {
      $("connection").textContent = "Connection lost";
      $("connection").classList.remove("connected");
      $("live-notice").hidden = false;
      $("live-notice").textContent = "Dashboard connection lost. Displayed observations are stale; retrying automatically.";
    } finally {
      fetching = false;
      $("refresh").disabled = false;
    }
  }
  function renderControls() {
    const options = data.nodes.map(function (node) {
      return [node.node_id + (node.online ? "" : " · offline"), node.node_id];
    });
    ["control-node", "leader-node", "source-node", "trust-peer"].forEach(function (id) {
      const select = $(id);
      if (!select) return;
      const previous = select.value;
      updateOptions(select, options.length ? options : [["No configured nodes", ""]]);
      if (options.some(function (o) { return o[1] === previous; })) select.value = previous;
    });
    const selected = $("control-node") ? $("control-node").value : "";
    const node = data.nodes.find(function (item) { return item.node_id === selected; });
    if (controlledNode !== selected && node) {
      controlledNode = selected;
      if ($("fault-mode")) $("fault-mode").value = String(node.state).startsWith("BYZANTINE_") ? node.state.slice(10) : "NONE";
    }
    if ($("controlled-node-status")) {
      $("controlled-node-status").textContent = node ? (node.online ? "Online" : "Offline") +
        " · " + (node.quarantined ? "Quarantine reported by " + (node.quarantined_by || []).join(", ") : node.state) : "";
    }
    if ($("controls-state")) {
      $("controls-state").textContent = controls.connected ? "Connected · Actions use real node identities" : controls.message || "Connecting…";
    }
    if ($("runtime-status")) {
      $("runtime-status").textContent = controls.runtime.message || "Runtime ready";
    }
    if ($("source-node") && $("traffic-source")) {
      $("source-node").disabled = $("traffic-source").value !== "internal";
    }
    const buttons = document.querySelectorAll(".control-body button");
    buttons.forEach(function (button) {
      const independent = ["connect-controls", "select-runtime"].includes(button.id);
      const runtimeAction = ["stop-node", "revive-node"].includes(button.id) || button.closest("#scale-form");
      button.disabled = actionBusy || !controls.enabled || (!independent && !controls.connected) ||
        (runtimeAction && !controls.runtime.available);
    });
    if ($("stop-node")) $("stop-node").disabled = actionBusy || !node || !node.online || !controls.runtime.available;
    if ($("revive-node")) $("revive-node").disabled = actionBusy || !node || !controls.runtime.available;
    if ($("apply-settings")) $("apply-settings").disabled = actionBusy || !controls.connected || !node;
    if ($("trust-form")) {
      const tb = $("trust-form").querySelector("button");
      if (tb) tb.disabled = actionBusy || !controls.connected;
    }
  }
  async function runAction(body) {
    if (actionBusy) return;
    actionBusy = true;
    const result = $("action-result");
    result.className = "action-result busy";
    result.textContent = "Working: " + body.action + "…";
    renderControls();
    try {
      const response = await fetch("/api/actions", {
        method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": controls.csrf},
        body: JSON.stringify(body), signal: AbortSignal.timeout(120000)
      });
      const value = await response.json();
      if (!response.ok) throw new Error(value.error || "Action failed");
      result.className = "action-result " + (value.accepted === false ? "failure-result" : "success-result");
      result.textContent = value.message || "Action completed";
      if (value.inbox_results) result.textContent += " · " + value.inbox_results.map(function (r) {
        return "HTTP " + r.http_status + " / " + (r.status || "unknown");
      }).filter(function (item, index, all) { return all.indexOf(item) === index; }).join(", ");
      if (value.outcomes && body.action === "trust") result.textContent += " in " + value.outcomes.length + " ledger(s)";
    } catch (error) {
      result.className = "action-result failure-result";
      result.textContent = error.name === "TimeoutError" ? "Action timed out. Refresh and inspect actual node state before retrying." : error.message;
    } finally {
      actionBusy = false;
      await refresh();
      renderControls();
    }
  }
  function actor() { return $("control-node") ? $("control-node").value : "fednode-0"; }
  function traffic(scenario) {
    return runAction({action: "inject", node: actor(), scenario: scenario,
      source: $("traffic-source") ? $("traffic-source").value : "external",
      source_node: $("source-node") ? $("source-node").value : "",
      domain: $("traffic-domain") ? $("traffic-domain").value.trim() : "",
      content: $("traffic-content") ? $("traffic-content").value : ""});
  }
  if ($("connect-controls")) {
    $("connect-controls").addEventListener("click", function () {
      runAction({action: "connect", leader: $("leader-node") ? $("leader-node").value : "fednode-0"});
    });
  }
  if ($("control-node")) $("control-node").addEventListener("change", function () { renderControls(); });
  if ($("traffic-source")) $("traffic-source").addEventListener("change", renderControls);
  document.querySelectorAll("[data-scenario]").forEach(function (button) {
    button.addEventListener("click", function () { traffic(button.dataset.scenario); });
  });
  if ($("send-custom")) $("send-custom").addEventListener("click", function () { traffic("custom"); });
  if ($("proposal-form")) {
    $("proposal-form").addEventListener("submit", function (event) {
      event.preventDefault();
      runAction({action: "propose", node: actor(), domain: $("proposal-domain").value.trim(),
        justification: $("proposal-justification").value.trim()});
    });
  }
  ["approve", "reject"].forEach(function (decision) {
    const btn = $(decision + "-vote");
    if (btn) {
      btn.addEventListener("click", function () {
        runAction({action: "vote", node: actor(), receiver: selectedObserver,
          proposal_id: selectedProposal, decision: decision.toUpperCase()});
      });
    }
  });
  if ($("elect-leader")) {
    $("elect-leader").addEventListener("click", function () {
      runAction({action: "leader", leader: $("leader-node") ? $("leader-node").value : "fednode-0"});
    });
  }
  if ($("apply-settings")) {
    $("apply-settings").addEventListener("click", function () {
      runAction({action: "settings", node: actor(), fault: $("fault-mode").value});
    });
  }
  ["stop", "revive", "sync"].forEach(function (action) {
    const btn = $(action + "-node");
    if (btn) {
      btn.addEventListener("click", function () { runAction({action: action, node: actor()}); });
    }
  });
  if ($("trust-form")) {
    $("trust-form").addEventListener("submit", function (event) {
      event.preventDefault();
      runAction({action: "trust", node: actor(), peer: $("trust-peer").value,
        score: Number($("trust-score").value), scope: $("trust-scope").value});
    });
  }
  if ($("scale-form")) {
    $("scale-form").addEventListener("submit", function (event) {
      event.preventDefault();
      runAction({action: "scale", replicas: Number($("replica-count").value), leader: $("leader-node") ? $("leader-node").value : "fednode-0"});
    });
  }
  if ($("select-runtime")) {
    $("select-runtime").addEventListener("click", function () {
      runAction({action: "runtime", runtime: $("runtime-kind").value});
    });
  }
  $("refresh").addEventListener("click", refresh);
  $("proposal-select").addEventListener("change", function () { selectedProposal = this.value; selectedObserver = ""; renderIncident(); renderControls(); });
  $("event-filter").addEventListener("change", renderEvents);
  $("ban-search").addEventListener("input", renderBans);
  $("close-dialog").addEventListener("click", function () { $("node-dialog").close(); });
  $("node-dialog").addEventListener("click", function (event) { if (event.target === this) this.close(); });
  refresh();
  setInterval(refresh, 2000);
})();
