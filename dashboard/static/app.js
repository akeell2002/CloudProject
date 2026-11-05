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
  let selectedDomain = "";
  let selectedNode = "";
  let fetching = false;
  let networkKey = "";
  let incidentKey = "";
  let lastSender = null;
  let controls = {enabled: false, connected: false, runtime: {}};
  let actionBusy = false;
  let controlledNode = "";
  let initialLoadDone = false;
  const seenDomains = new Set();
  let liveVoteAnim = null;
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
    const byDomain = new Map();
    (data.nodes || []).forEach(function (node) {
      if (!node.online || !node.proposals) return;
      node.proposals.forEach(function (p) {
        const key = p.domain || p.proposal_id;
        if (!byDomain.has(key)) {
          byDomain.set(key, {
            proposal_id: p.proposal_id,
            domain: p.domain,
            proposer: p.proposer || "fednode-0",
            reason: p.reason,
            quorum: p.quorum || 4,
            created_at: p.created_at || 0,
            committed: Boolean(p.committed),
            approvals: new Set(),
            rejections: new Set(),
            invalid: new Set(),
            quarantined: new Set()
          });
        }
        const entry = byDomain.get(key);
        if ((p.created_at || 0) >= entry.created_at) {
          entry.created_at = p.created_at || entry.created_at;
          entry.proposal_id = p.proposal_id;
          entry.proposer = p.proposer || entry.proposer;
        }
        if (p.committed) entry.committed = true;
        // Prefer proposer's verified approvals or honest nodes' approvals
        const isFaulty = String(node.state).startsWith("BYZANTINE_") || node.quarantined;
        if (!isFaulty && p.approvals) {
          p.approvals.forEach(function (v) { entry.approvals.add(v); });
        }
      });
    });

    (data.events || []).forEach(function (e) {
      if (!e.domain && !e.proposal_id) return;
      const key = e.domain || e.proposal_id;
      if (!byDomain.has(key) && e.domain && ["proposal", "vote", "commit"].includes(e.kind)) {
        byDomain.set(key, {
          proposal_id: e.proposal_id || key,
          domain: e.domain,
          proposer: e.observer || e.source || "fednode-0",
          reason: e.reason || 4,
          quorum: 4,
          created_at: e.timestamp || 0,
          committed: false,
          approvals: new Set(),
          rejections: new Set(),
          invalid: new Set(),
          quarantined: new Set()
        });
      }
      const entry = byDomain.get(key);
      if (!entry) return;
      if ((e.timestamp || 0) > entry.created_at) entry.created_at = e.timestamp;
      if (e.kind === "commit") entry.committed = true;
      if (e.decision === "APPROVE") entry.approvals.add(e.source);
      else if (e.decision === "REJECT") entry.rejections.add(e.source);
      else if (e.decision === "INVALID") entry.invalid.add(e.source);
      else if (e.decision === "QUARANTINED") entry.quarantined.add(e.source);
    });

    const bannedDomains = new Set((data.bans || []).map(function (b) { return b.domain; }));
    byDomain.forEach(function (entry) {
      if (bannedDomains.has(entry.domain)) {
        entry.committed = true;
      }
      entry.rejections.forEach(function (v) { entry.approvals.delete(v); });
      entry.invalid.forEach(function (v) { entry.approvals.delete(v); });
      entry.quarantined.forEach(function (v) { entry.approvals.delete(v); });
      (data.nodes || []).forEach(function (n) {
        if (n.quarantined) {
          entry.approvals.delete(n.node_id);
          entry.quarantined.add(n.node_id);
        } else if (n.state === "BYZANTINE_LIAR") {
          entry.approvals.delete(n.node_id);
          entry.rejections.add(n.node_id);
        } else if (n.state === "BYZANTINE_FORGER") {
          entry.approvals.delete(n.node_id);
          entry.invalid.add(n.node_id);
        } else if (n.state === "BYZANTINE_SILENT" || !n.online) {
          entry.approvals.delete(n.node_id);
        }
      });
    });

    return Array.from(byDomain.values()).sort(function (a, b) {
      return b.created_at - a.created_at;
    });
  }

  function startLiveVoteAnimation(proposal) {
    if (liveVoteAnim && liveVoteAnim.timer) {
      clearInterval(liveVoteAnim.timer);
    }
    const proposer = proposal.proposer || "fednode-0";
    const order = [proposer];
    (data.nodes || []).forEach(function (n) {
      if (n.node_id !== proposer) {
        if (proposal.approvals.has(n.node_id) ||
            proposal.rejections.has(n.node_id) ||
            proposal.invalid.has(n.node_id) ||
            proposal.quarantined.has(n.node_id) ||
            n.quarantined) {
          order.push(n.node_id);
        }
      }
    });
    liveVoteAnim = {
      domain: proposal.domain,
      proposer: proposer,
      order: order,
      step: 0,
      maxSteps: order.length
    };
    liveVoteAnim.timer = setInterval(function () {
      if (!liveVoteAnim) return;
      liveVoteAnim.step += 1;
      incidentKey = "";
      networkKey = "";
      try {
        renderIncident();
        renderNetwork();
      } catch (_) {}
      if (liveVoteAnim && liveVoteAnim.step >= liveVoteAnim.maxSteps) {
        clearInterval(liveVoteAnim.timer);
        liveVoteAnim.timer = null;
      }
    }, 520);
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
    let latest = data.events[data.events.length - 1];
    if (liveVoteAnim && liveVoteAnim.step < liveVoteAnim.maxSteps) {
      const voter = liveVoteAnim.order[liveVoteAnim.step];
      latest = {
        source: voter,
        target: liveVoteAnim.step === 0 ? "consortium" : liveVoteAnim.proposer,
        kind: liveVoteAnim.step === 0 ? "proposal" : "vote",
        timestamp: Date.now()
      };
    }
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
  }
  function updateOptions(select, options) {
    if (!select || !select.options) return;
    const existing = Array.from(select.options).map(function (option) { return [option.text, option.value]; });
    if (JSON.stringify(existing) !== JSON.stringify(options)) {
      select.replaceChildren();
      options.forEach(function (option) { select.append(new Option(option[0], option[1])); });
    }
  }
  function renderIncident() {
    const all = proposals();
    if (!initialLoadDone) {
      all.forEach(function (p) { seenDomains.add(p.domain); });
      initialLoadDone = true;
    } else if (all.length && !seenDomains.has(all[0].domain)) {
      seenDomains.add(all[0].domain);
      selectedDomain = all[0].domain;
      startLiveVoteAnimation(all[0]);
    }

    if (!selectedDomain || !all.some(function (p) { return p.domain === selectedDomain; })) {
      selectedDomain = all.length ? all[0].domain : "";
    }
    const proposal = all.find(function (p) { return p.domain === selectedDomain; }) || all[0];

    const isAnimating = Boolean(liveVoteAnim && proposal && liveVoteAnim.domain === proposal.domain && liveVoteAnim.step < liveVoteAnim.maxSteps);
    const animStep = isAnimating ? liveVoteAnim.step : -1;

    const nextKey = JSON.stringify([
      proposal ? [proposal.domain, proposal.committed, Array.from(proposal.approvals).sort(),
                  Array.from(proposal.rejections).sort(), Array.from(proposal.invalid).sort()] : null,
      animStep,
      data.nodes.map(function (n) { return [n.node_id, n.online, n.quarantined, n.state]; })
    ]);
    if (nextKey === incidentKey) return;
    incidentKey = nextKey;

    const content = $("incident-content");
    content.replaceChildren();
    const state = $("incident-state");

    if (!proposal) {
      $("incident-panel").classList.remove("has-threat");
      const latestThreat = data.events.slice().reverse().find(function (e) { return e.kind === "threat"; });
      state.className = "pill " + (latestThreat ? "danger" : "neutral");
      state.textContent = latestThreat ? "THREAT DETECTED" : "FLEET IDLE";
      content.append(empty(latestThreat ? "!" : "◇", latestThreat ? latestThreat.domain || latestThreat.source : "Consensus Engine Idle",
        latestThreat ? latestThreat.message + " Voting proposal will start shortly." :
        "Trigger a phishing or malware attack on the left to watch live 3-phase Byzantine consensus voting across all 5 nodes."));
      return;
    }

    const revealedSet = isAnimating
      ? new Set(liveVoteAnim.order.slice(0, liveVoteAnim.step + 1))
      : new Set((data.nodes || []).map(function (n) { return n.node_id; }));
    const activeVoter = isAnimating ? liveVoteAnim.order[liveVoteAnim.step] : null;

    const visibleApprovals = Array.from(proposal.approvals).filter(function (id) { return revealedSet.has(id); }).length;
    const quorumNeeded = proposal.quorum || 4;
    const isFinalCommitted = !isAnimating && (proposal.committed || visibleApprovals >= quorumNeeded);

    $("incident-panel").classList.toggle("has-threat", isAnimating || !isFinalCommitted);

    if (isAnimating && liveVoteAnim.step === 0) {
      state.className = "pill danger";
      state.textContent = "PHASE 1 · PROPOSING BLOCK";
    } else if (isAnimating) {
      state.className = "pill danger";
      state.textContent = "PHASE 2 · LIVE VOTING (" + visibleApprovals + "/" + quorumNeeded + ")";
    } else if (isFinalCommitted) {
      state.className = "pill success";
      state.textContent = "PHASE 3 · QUORUM REACHED & BANNED";
    } else {
      state.className = "pill danger";
      state.textContent = "QUORUM FAILED (" + visibleApprovals + "/" + quorumNeeded + ")";
    }

    const inner = el("div", "incident-content-inner");
    inner.append(
      el("span", "threat-eyebrow",
        isAnimating ? "LIVE BYZANTINE VOTING ROUND IN PROGRESS" :
        isFinalCommitted ? "CONSORTIUM DEFEDERATION (COMMITTED)" : "CONSENSUS THRESHOLD NOT REACHED"),
      el("h3", "threat-domain", proposal.domain)
    );

    const evidence = data.events.slice().reverse().find(function (e) {
      return e.domain === proposal.domain && ["threat", "proposal"].includes(e.kind);
    });
    inner.append(el("div", "evidence", evidence ? evidence.message : reasonNames[proposal.reason] || "Domain moderation proposal"));

    const status = el("div", "decision-status");
    status.append(
      el("span", "",
        isAnimating ? "Collecting signed ballots from peers…" :
        isFinalCommitted ? "Quorum threshold achieved" : "Insufficient honest approvals"),
      el("strong", "", visibleApprovals + " / " + quorumNeeded + " needed")
    );
    inner.append(status);

    const progress = el("div", "progress");
    progress.setAttribute("role", "progressbar");
    progress.setAttribute("aria-label", "Recorded approvals");
    progress.setAttribute("aria-valuemin", "0");
    progress.setAttribute("aria-valuemax", String(quorumNeeded));
    const currentProgress = Math.min(visibleApprovals, quorumNeeded);
    progress.setAttribute("aria-valuenow", String(currentProgress));
    const fill = el("div", "progress-fill");
    fill.style.width = Math.min(100, (currentProgress / quorumNeeded) * 100) + "%";
    progress.append(fill);
    inner.append(progress);

    const votes = el("div", "vote-grid");
    (data.nodes || []).forEach(function (node) {
      const id = node.node_id;
      let decision = "WAITING";
      let title = "Awaiting ballot in current consensus round";

      if (!revealedSet.has(id)) {
        if (!node.online) {
          decision = "OFFLINE";
          title = "Node unreachable";
        } else {
          decision = "WAITING";
          title = "Verifying origin signature and auditing threat score…";
        }
      } else if (proposal.approvals.has(id)) {
        decision = "APPROVE";
        title = "Signed and verified Ed25519 approval ballot";
      } else if (proposal.rejections && proposal.rejections.has(id)) {
        decision = "REJECT";
        title = "Byzantine LIAR: cast dissenting REJECT ballot";
      } else if (proposal.invalid && proposal.invalid.has(id)) {
        decision = "INVALID";
        title = "Byzantine FORGER: ballot rejected due to invalid signature";
      } else if ((proposal.quarantined && proposal.quarantined.has(id)) || node.quarantined) {
        decision = "QUARANTINED";
        title = "Quarantined (score < 30): ballot excluded from quorum";
      } else if (!node.online) {
        decision = "OFFLINE";
        title = "Node offline / killed";
      } else if (String(node.state) === "BYZANTINE_SILENT") {
        decision = "OFFLINE";
        title = "Byzantine SILENT: dropped gRPC proposal";
      }

      const names = {
        APPROVE: "Approved",
        REJECT: "Rejected",
        INVALID: "Forged",
        QUARANTINED: "Excluded",
        OFFLINE: "Dropped",
        WAITING: "Waiting…"
      };

      const card = el("div", "vote-card " + decision.toLowerCase() + (activeVoter === id ? " voting-now" : ""));
      card.append(
        el("span", "vote-icon", decision === "APPROVE" ? "✓" : ["INVALID", "REJECT", "QUARANTINED", "OFFLINE"].includes(decision) ? "×" : "…"),
        el("span", "vote-name", id),
        el("span", "vote-state", names[decision] || decision)
      );
      card.title = title;
      votes.append(card);
    });
    inner.append(votes);

    inner.append(el("p", "observation",
      isAnimating
        ? "⚡ Step " + (liveVoteAnim.step + 1) + " of " + liveVoteAnim.maxSteps + ": " + activeVoter + " broadcasting signed cryptographic ballot…"
        : isFinalCommitted
        ? "✓ Quorum Proof verified (N=5, f=1, Q=4). Defederation rule committed to SQLite WAL and in-memory firewall across active nodes."
        : "⚠ Quorum threshold (Q=" + quorumNeeded + ") was not met. Domain remains unblocked due to insufficient honest votes."));

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
      row.addEventListener("click", function () {
        selectedDomain = ban.domain;
        incidentKey = "";
        renderIncident();
      });
      list.append(row);
    });
    if (!bans.length) list.append(el("div", "ban-empty", query ? "No domains match your search." : "No reported domain blocks."));
  }
  function render() {
    const active = onlineNodes().length;
    const allProposals = proposals();
    const committed = new Set(allProposals.filter(function (p) { return p.committed; }).map(function (p) { return p.domain; }));
    const pending = new Set(allProposals.filter(function (p) { return !p.committed && !committed.has(p.domain); }).map(function (p) { return p.domain; }));
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
    } catch (error) {
      $("connection").textContent = "Connection lost";
      $("connection").classList.remove("connected");
      $("live-notice").hidden = false;
      $("live-notice").textContent = "Dashboard connection lost. Displayed observations are stale; retrying automatically.";
      return;
    } finally {
      fetching = false;
      $("refresh").disabled = false;
    }

    try {
      render();
    } catch (renderError) {
      console.error("Dashboard render error:", renderError);
    }
  }
  function renderControls() {
    const options = data.nodes.map(function (node) {
      return [node.node_id + (node.online ? "" : " · offline"), node.node_id];
    });
    const select = $("control-node");
    if (select) {
      const previous = select.value;
      updateOptions(select, options.length ? options : [["No configured nodes", ""]]);
      if (options.some(function (o) { return o[1] === previous; })) select.value = previous;
    }
    const selected = select ? select.value : "";
    if ($("trust-peer")) $("trust-peer").value = selected || "fednode-0";
    const node = data.nodes.find(function (item) { return item.node_id === selected; });
    if (controlledNode !== selected && node) {
      controlledNode = selected;
      if ($("fault-mode")) $("fault-mode").value = String(node.state).startsWith("BYZANTINE_") ? node.state.slice(10) : "NONE";
    }
    if ($("controlled-node-status")) {
      $("controlled-node-status").textContent = node ? (node.online ? "Online" : "Offline") +
        " · " + (node.quarantined ? "Quarantined (score < 30)" : node.state) : "";
    }
    if ($("controls-state")) {
      $("controls-state").textContent = controls.connected ? "Connected · Actions use real node identities" : controls.message || "Connecting…";
    }
    const buttons = document.querySelectorAll(".control-body button");
    buttons.forEach(function (button) {
      button.disabled = actionBusy || !controls.enabled || !controls.connected;
    });
    if ($("stop-node")) $("stop-node").disabled = actionBusy || !node || !node.online;
    if ($("revive-node")) $("revive-node").disabled = actionBusy || !node || node.online;
    if ($("apply-settings")) $("apply-settings").disabled = actionBusy || !controls.connected || !node;
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
      if (body.action === "inject" && value.domain) {
        seenDomains.delete(value.domain);
        selectedDomain = value.domain;
      }
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
      source: "external", source_node: "", domain: "",
      content: $("traffic-content") ? $("traffic-content").value : ""});
  }
  if ($("control-node")) $("control-node").addEventListener("change", renderControls);
  document.querySelectorAll("[data-scenario]").forEach(function (button) {
    button.addEventListener("click", function () { traffic(button.dataset.scenario); });
  });
  if ($("send-custom")) $("send-custom").addEventListener("click", function () { traffic("custom"); });
  if ($("apply-settings")) {
    $("apply-settings").addEventListener("click", function () {
      runAction({action: "settings", node: actor(), fault: $("fault-mode").value});
    });
  }
  ["stop", "revive"].forEach(function (action) {
    const btn = $(action + "-node");
    if (btn) {
      btn.addEventListener("click", function () { runAction({action: action, node: actor()}); });
    }
  });
  if ($("quarantine-peer")) {
    $("quarantine-peer").addEventListener("click", function () {
      if ($("trust-score")) $("trust-score").value = "20";
      runAction({action: "trust", node: "fednode-0", peer: actor(), score: 20, scope: "all"});
    });
  }
  if ($("restore-peer")) {
    $("restore-peer").addEventListener("click", function () {
      if ($("trust-score")) $("trust-score").value = "100";
      runAction({action: "trust", node: "fednode-0", peer: actor(), score: 100, scope: "all"});
    });
  }
  if ($("trust-form")) {
    $("trust-form").addEventListener("submit", function (event) {
      event.preventDefault();
      runAction({action: "trust", node: "fednode-0", peer: actor(),
        score: Number($("trust-score").value), scope: "all"});
    });
  }
  $("refresh").addEventListener("click", refresh);
  $("event-filter").addEventListener("change", renderEvents);
  $("ban-search").addEventListener("input", renderBans);
  $("close-dialog").addEventListener("click", function () { $("node-dialog").close(); });
  $("node-dialog").addEventListener("click", function (event) { if (event.target === this) this.close(); });
  refresh();
  setInterval(refresh, 2000);
})();
