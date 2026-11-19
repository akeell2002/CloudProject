/* Live telemetry and operator controls UI built cleanly with DOM APIs. */
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
          return address.hostname === p.node.node_id ||
            address.hostname === p.node.node_id + ".lab.example" ||
            address.host === new URL(p.node.address).host;
        });
      } catch (_) {
        return undefined;
      }
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
      if (route && ["external", "endpoint"].includes(route.source.kind)) {
        return {source: route.source, attack: route.attack};
      }
    }
    return previous || null;
  }

  function quorumUnreachableText(health) {
    function names(list) { return Array.isArray(list) && list.length ? list.join(", ") : "none"; }
    const byzPart = Array.isArray(health.byzantine) && health.byzantine.length
      ? " · byzantine: " + names(health.byzantine)
      : "";
    return "Quorum unreachable: " + health.eligible_voters + " eligible < Q=" + health.quorum +
      " · offline: " + names(health.offline) + " · quarantined: " + names(health.quarantined) + byzPart;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {networkRoute, rememberSender, quorumUnreachableText};
  }
  if (typeof document === "undefined") return;

  const SVG_NS = "http://www.w3.org/2000/svg";
  const N5_POS = [[63, 16], [88, 41], [79, 80.5], [47, 80.5], [38, 41]];
  const DEFAULT_ORGS = {
    "fednode-0": "mastodon.social",
    "fednode-1": "lemmy.world",
    "fednode-2": "pixelfed.social",
    "fednode-3": "friendica.me",
    "fednode-4": "peertube.tv"
  };
  const $ = function (id) { return document.getElementById(id); };

  let data = {nodes: [], events: [], bans: [], updated_at: null};
  let selectedDomain = "";
  let selectedNode = "";
  let selectedNodeTab = "status";
  let fetching = false;
  let topologyKey = "";
  let nodesKey = "";
  let incidentKey = "";
  let lastSender = null;
  let controls = {enabled: false, connected: false, runtime: {}};
  let actionBusy = false;
  let controlledNode = "";
  let controlledChaosNode = "";
  let initialLoadDone = false;
  let userPinnedDomain = "";
  let roundCounter = 0;
  let lastStartedRoundDomain = "";
  let resetBaselineAt = 0;
  let anim = null;
  let rafId = null;
  let committedFlashUntil = 0;
  let shieldFlashNode = "";
  let shieldFlashUntil = 0;

  const seenDomains = new Set();
  const seenCommitted = new Set();
  const securityKinds = ["threat", "blocked", "invalid", "censor", "proposal", "vote", "commit"];
  const reasonNames = {1: "Spam", 2: "Bot activity", 3: "Phishing", 4: "Suspicious file", 5: "Hate speech"};

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function svgEl(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    Object.entries(attrs || {}).forEach(function (pair) {
      node.setAttribute(pair[0], String(pair[1]));
    });
    return node;
  }

  function formatTime(value) {
    return value ? new Date(value).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "Unknown";
  }

  function isAttack(event) {
    return ["threat", "invalid", "blocked", "censor"].includes(event.kind);
  }

  function onlineNodes() {
    return (data.nodes || []).filter(function (node) { return node.online; });
  }

  function bftParams() {
    const n = Math.max((data.nodes || []).length, 1);
    const f = Math.floor((n - 1) / 3);
    const q = n - f;
    return {n: n, f: f, q: q};
  }

  function nodePositions(nodes) {
    const list = nodes || data.nodes || [];
    return list.map(function (node, idx) {
      const pt = list.length <= 5 ? N5_POS[idx] : [
        64 + 26.5 * Math.cos((2 * Math.PI * idx) / list.length - Math.PI / 2),
        50 + 37.5 * Math.sin((2 * Math.PI * idx) / list.length - Math.PI / 2)
      ];
      return {node: node, idx: idx, x: pt[0], y: pt[1], sx: pt[0] * 8, sy: pt[1] * 3.65};
    });
  }

  function nodeTrustSummary(nodeId) {
    let minScore = 100;
    let isEligible = true;
    (data.nodes || []).forEach(function (observer) {
      if (!observer.online) return;
      const rep = (observer.reputations || []).find(function (entry) {
        return entry.peer_id === nodeId;
      });
      if (rep) {
        if (rep.trust_score < minScore) minScore = rep.trust_score;
        if (rep.trust_score < 30 || !rep.is_active) isEligible = false;
      }
    });
    const node = (data.nodes || []).find(function (item) { return item.node_id === nodeId; });
    if (node && node.quarantined) isEligible = false;
    return {score: minScore, eligible: isEligible};
  }

  function proposals() {
    const bft = bftParams();
    const byDomain = new Map();

    (data.nodes || []).forEach(function (node) {
      if (!node.online || !node.proposals) return;
      node.proposals.forEach(function (p) {
        const key = p.domain || p.proposal_id;
        if (!byDomain.has(key)) {
          byDomain.set(key, {
            proposal_id: p.proposal_id,
            domain: p.domain,
            proposer: p.proposer || "",
            reason: p.reason,
            epoch: p.epoch || 1,
            sequence: p.sequence || 1,
            threat_score: p.threat_score || 0.85,
            latency_ms: p.latency_ms || 0,
            quorum: bft.q,
            created_at: p.created_at || 0,
            committed: Boolean(p.committed),
            framingRejected: false,
            approvals: new Set(),
            rejections: new Set(),
            framingRejectors: new Set(),
            equivocators: new Set(),
            invalid: new Set(),
            quarantined: new Set()
          });
        }
        const entry = byDomain.get(key);
        if ((p.created_at || 0) >= entry.created_at) {
          entry.created_at = p.created_at || entry.created_at;
          entry.proposal_id = p.proposal_id;
          if (p.proposer) entry.proposer = p.proposer;
        }
        if (p.epoch) entry.epoch = Math.max(entry.epoch || 1, p.epoch);
        if (p.sequence) entry.sequence = Math.max(entry.sequence || 1, p.sequence);
        if (p.threat_score) entry.threat_score = p.threat_score;
        if (p.latency_ms && p.latency_ms <= 280 && (!entry.latency_ms || p.latency_ms < entry.latency_ms)) {
          entry.latency_ms = p.latency_ms;
        }
        if (p.committed) entry.committed = true;
        if (p.approvals) {
          p.approvals.forEach(function (v) { entry.approvals.add(v); });
        }
        if (p.rejections) {
          p.rejections.forEach(function (v) { entry.rejections.add(v); });
        }
        if (p.invalids) {
          p.invalids.forEach(function (v) { entry.invalid.add(v); });
        }
        if (p.equivocators) {
          p.equivocators.forEach(function (v) { entry.equivocators.add(v); });
        }
        if (p.quarantined) {
          p.quarantined.forEach(function (v) { entry.quarantined.add(v); });
        }
      });
    });

    const bannedDomains = new Set((data.bans || []).map(function (b) { return b.domain; }));
    (data.events || []).forEach(function (e) {
      if (!e.domain && !e.proposal_id) return;
      const key = e.domain || e.proposal_id;
      const isFramingEvt = e.kind === "invalid" && /framing attack|origin http signature/i.test(String(e.message || ""));
      if (!byDomain.has(key) && e.domain && (e.kind === "commit" || isFramingEvt || bannedDomains.has(e.domain))) {
        byDomain.set(key, {
          proposal_id: e.proposal_id || key,
          domain: e.domain,
          proposer: e.observer || e.source || "fednode-0",
          reason: e.reason || 4,
          epoch: 1,
          sequence: 1,
          threat_score: e.score || 0.85,
          latency_ms: 0,
          quorum: bft.q,
          created_at: e.timestamp || 0,
          committed: false,
          framingRejected: false,
          approvals: new Set(),
          rejections: new Set(),
          framingRejectors: new Set(),
          equivocators: new Set(),
          invalid: new Set(),
          quarantined: new Set()
        });
      }
      const entry = byDomain.get(key);
      if (!entry) return;
      if (e.kind === "proposal" && e.source && /^fednode-\d+$/.test(e.source)) {
        entry.proposer = e.source;
      } else if (e.kind === "threat" && e.target && /^fednode-\d+$/.test(e.target) && !entry.proposer) {
        entry.proposer = e.target;
      }
      if (e.score) entry.threat_score = e.score;
      if (e.kind === "commit" && entry.created_at && e.timestamp >= entry.created_at && !entry.latency_ms) {
        entry.latency_ms = Math.max(12, Math.min(280, e.timestamp - entry.created_at));
      }
      if (!entry.created_at && e.timestamp) entry.created_at = e.timestamp;
      if (e.kind === "commit") entry.committed = true;
      if (e.decision === "APPROVE") entry.approvals.add(e.source);
      else if (e.decision === "REJECT") entry.rejections.add(e.source);
      else if (e.decision === "INVALID") entry.invalid.add(e.source);
      else if (e.decision === "QUARANTINED") entry.quarantined.add(e.source);

      if (e.kind === "invalid" && /framing attack|origin http signature/i.test(String(e.message || ""))) {
        entry.framingRejected = true;
        const rejector = /^fednode-\d+$/.test(String(e.target || "")) ? e.target :
          /^fednode-\d+$/.test(String(e.observer || "")) ? e.observer : "";
        if (rejector) {
          entry.framingRejectors.add(rejector);
          entry.rejections.add(rejector);
          entry.approvals.delete(rejector);
        }
      } else if (e.kind === "invalid" && /equivocat|conflicting.*ballot/i.test(String(e.message || ""))) {
        if (/^fednode-\d+$/.test(String(e.source || ""))) {
          entry.equivocators.add(e.source);
          entry.approvals.delete(e.source);
        }
      }
    });

    byDomain.forEach(function (entry) {
      if (!entry.proposer) entry.proposer = "fednode-0";
      entry.quorum = bft.q;
      if (bannedDomains.has(entry.domain)) entry.committed = true;
      if (!entry.latency_ms || entry.latency_ms > 280) {
        entry.latency_ms = entry.committed ? 24 : 0;
      }
      entry.rejections.forEach(function (v) { entry.approvals.delete(v); });
      entry.invalid.forEach(function (v) {
        entry.approvals.delete(v);
        entry.rejections.delete(v);
      });
      entry.quarantined.forEach(function (v) {
        entry.approvals.delete(v);
        entry.rejections.delete(v);
        entry.invalid.delete(v);
        if (entry.equivocators) entry.equivocators.delete(v);
      });
      if (entry.equivocators) {
        entry.equivocators.forEach(function (v) {
          entry.approvals.delete(v);
          entry.rejections.delete(v);
        });
      }
      if (!entry.committed) {
        (data.nodes || []).forEach(function (n) {
          const nid = n.node_id;
          const hasExplicitFault = entry.rejections.has(nid) || entry.invalid.has(nid) ||
            (entry.equivocators && entry.equivocators.has(nid)) || entry.quarantined.has(nid);
          if (hasExplicitFault) return;
          if (n.quarantined) {
            entry.approvals.delete(nid);
            entry.quarantined.add(nid);
          } else if (n.state === "BYZANTINE_LIAR") {
            entry.approvals.delete(nid);
            entry.rejections.add(nid);
          } else if (n.state === "BYZANTINE_FORGER") {
            entry.approvals.delete(nid);
            entry.invalid.add(nid);
          } else if (n.state === "BYZANTINE_EQUIVOCATOR") {
            entry.approvals.delete(nid);
            entry.equivocators.add(nid);
          } else if (n.state === "BYZANTINE_SILENT" || n.state === "BYZANTINE_CENSOR" || !n.online) {
            entry.approvals.delete(nid);
          }
        });
      }
    });

    return Array.from(byDomain.values()).sort(function (a, b) {
      return b.created_at - a.created_at;
    });
  }

  function activeLeaderId() {
    const nodes = data.nodes || [];
    const online = nodes.filter(function (n) { return n.online; });
    if (!online.length) return "";
    const maxEpoch = online.reduce(function (m, n) { return Math.max(m, n.epoch || 1); }, 1);
    const realLeaders = online.filter(function (n) {
      return n.is_leader === true || (n.is_leader === undefined && n.state === "LEADER");
    });
    if (realLeaders.length) {
      realLeaders.sort(function (a, b) { return (b.epoch || 1) - (a.epoch || 1); });
      return realLeaders[0].node_id;
    }
    const baseCount = Math.min(nodes.length, 5);
    const byzLeader = online.find(function (n) {
      return n.is_leader === undefined && String(n.state || "").startsWith("BYZANTINE_") &&
        n.node_id === "fednode-" + ((maxEpoch - 1) % Math.max(baseCount, 1));
    });
    return byzLeader ? byzLeader.node_id : "";
  }

  function activeCoordinator() {
    const all = proposals();
    if (selectedDomain) {
      const sel = all.find(function (p) { return p.domain === selectedDomain; });
      if (sel && sel.proposer) {
        const selNode = (data.nodes || []).find(function (n) { return n.node_id === sel.proposer && n.online; });
        if (selNode) return selNode.node_id;
      }
    }
    if (all.length && all[0].proposer) {
      const latestNode = (data.nodes || []).find(function (n) { return n.node_id === all[0].proposer && n.online; });
      if (latestNode) return latestNode.node_id;
    }
    return activeLeaderId();
  }

  function selectTrafficNode(nodeId) {
    const select = $("control-node");
    if (select && Array.from(select.options).some(function (o) { return o.value === nodeId; })) {
      select.value = nodeId;
    }
    topologyKey = "";
    nodesKey = "";
    renderControls();
    renderTopology();
    renderNodesTable();
  }

  function isSlowMo() {
    return Boolean($("slow-mo-toggle") && $("slow-mo-toggle").checked);
  }

  function clearAnimationTimers() {
    if (anim && Array.isArray(anim.timerIds)) {
      anim.timerIds.forEach(function (id) { clearTimeout(id); });
    }
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
  }

  function trimSegment(p1, p2, curveSign) {
    const dx = p2.sx - p1.sx;
    const dy = p2.sy - p1.sy;
    const dist = Math.hypot(dx, dy) || 1;
    const ux = dx / dist;
    const uy = dy / dist;
    function borderPush(pt, dirX, dirY) {
      const tx = Math.abs(dirX) > 0.001 ? pt.hw / Math.abs(dirX) : 9999;
      const ty = Math.abs(dirY) > 0.001 ? pt.hh / Math.abs(dirY) : 9999;
      const t = Math.min(tx, ty) + 4;
      return {x: pt.sx + dirX * t, y: pt.sy + dirY * t};
    }
    const a = borderPush(p1, ux, uy);
    const b = borderPush(p2, -ux, -uy);
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const nx = -(b.y - a.y);
    const ny = b.x - a.x;
    const nlen = Math.hypot(nx, ny) || 1;
    const curve = Math.min(24, dist * 0.08) * (curveSign === undefined ? 1 : curveSign);
    return {
      x1: a.x, y1: a.y,
      cx: mx + (nx / nlen) * curve,
      cy: my + (ny / nlen) * curve,
      x2: b.x, y2: b.y
    };
  }

  function ensureMarkers(svg) {
    const defs = svgEl("defs");
    [
      ["green", "#198754"],
      ["red", "#dc3545"],
      ["amber", "#fd7e14"],
      ["blue", "#0d6efd"],
      ["gray", "#6c757d"]
    ].forEach(function (pair) {
      const marker = svgEl("marker", {
        id: "pkt-arrow-" + pair[0], viewBox: "0 0 10 10",
        refX: 7, refY: 5, markerWidth: 7, markerHeight: 7,
        orient: "auto", markerUnits: "userSpaceOnUse"
      });
      marker.append(svgEl("path", {d: "M 0 1 L 8 5 L 0 9 z", fill: pair[1]}));
      defs.append(marker);
    });
    svg.append(defs);
  }

  function drawPacketAlong(svg, seg, progress, color, markerKey, labelText, reverseProgress) {
    const path = svgEl("path", {
      d: "M " + seg.x1.toFixed(1) + " " + seg.y1.toFixed(1) +
         " Q " + seg.cx.toFixed(1) + " " + seg.cy.toFixed(1) +
         " " + seg.x2.toFixed(1) + " " + seg.y2.toFixed(1),
      class: "edge-flow",
      stroke: color,
      "marker-end": reverseProgress ? "" : "url(#pkt-arrow-" + markerKey + ")"
    });
    svg.append(path);
    let pt;
    try {
      const totalLen = path.getTotalLength() || 1;
      const p = Math.max(0, Math.min(1, progress));
      pt = path.getPointAtLength(totalLen * p);
    } catch (_) {
      pt = {x: seg.x1 + (seg.x2 - seg.x1) * progress, y: seg.y1 + (seg.y2 - seg.y1) * progress};
    }
    svg.append(svgEl("circle", {cx: pt.x.toFixed(1), cy: pt.y.toFixed(1), r: 8, fill: color, "fill-opacity": "0.22"}));
    svg.append(svgEl("circle", {cx: pt.x.toFixed(1), cy: pt.y.toFixed(1), r: 4.5, fill: color, stroke: "#ffffff", "stroke-width": "1.5"}));
    if (labelText) {
      const lbl = svgEl("text", {
        x: pt.x.toFixed(1), y: (pt.y - 10).toFixed(1),
        "text-anchor": "middle", fill: color, class: "packet-label"
      });
      lbl.textContent = labelText;
      svg.append(lbl);
    }
  }

  function nodeBoxSpec(nodeId, pts) {
    if (nodeId === "external" || nodeId === "sender") {
      return {sx: 84, sy: 182.5, hw: 72, hh: 40};
    }
    const found = pts.find(function (p) { return p.node.node_id === nodeId; });
    if (!found) return {sx: 84, sy: 182.5, hw: 72, hh: 40};
    const compact = pts.length > 5;
    return {sx: found.sx, sy: found.sy, hw: compact ? 63 : 76, hh: compact ? 42 : 48};
  }

  function renderPacketFrame() {
    const svg = $("network-packets");
    if (!svg) return;
    svg.replaceChildren();
    if (!anim || anim.finished) {
      rafId = null;
      return;
    }

    ensureMarkers(svg);
    const pts = nodePositions(data.nodes);
    const now = performance.now();
    const elapsed = Math.max(0, now - anim.stageStartedAt);
    const prog = Math.min(1, elapsed / Math.max(1, anim.stageDuration));
    const leaderId = anim.leaderId || activeLeaderId();
    const pData = proposals().find(function (p) { return p.domain === anim.domain; }) || anim.proposal;

    if (anim.kind === "censor") {
      if (anim.stage === 1) {
        const src = nodeBoxSpec(anim.sourceKind === "internal" ? anim.sourceId : "external", pts);
        const dst = nodeBoxSpec(anim.targetId, pts);
        drawPacketAlong(svg, trimSegment(src, dst), prog, "#dc3545", "red", "THREAT 403");
      } else if (anim.censorPhase === "escalate") {
        const segEsc = trimSegment(nodeBoxSpec(anim.targetId, pts), nodeBoxSpec(leaderId, pts));
        drawPacketAlong(svg, segEsc, prog, "#fd7e14", "amber", "ESCALATE");
      } else if (anim.censorPhase === "blocked_at_leader") {
        const segDrop = trimSegment(nodeBoxSpec(anim.targetId, pts), nodeBoxSpec(leaderId, pts));
        svg.append(svgEl("path", {
          d: "M " + segDrop.x1.toFixed(1) + " " + segDrop.y1.toFixed(1) +
             " Q " + segDrop.cx.toFixed(1) + " " + segDrop.cy.toFixed(1) +
             " " + segDrop.x2.toFixed(1) + " " + segDrop.y2.toFixed(1),
          class: "edge-flow", stroke: "#dc3545"
        }));
        svg.append(svgEl("circle", {cx: segDrop.x2.toFixed(1), cy: segDrop.y2.toFixed(1), r: 10, fill: "#dc3545", stroke: "#ffffff", "stroke-width": "2"}));
        const xLbl = svgEl("text", {
          x: segDrop.x2.toFixed(1), y: (segDrop.y2 - 14).toFixed(1),
          "text-anchor": "middle", fill: "#dc3545", class: "packet-label"
        });
        xLbl.textContent = "✕ CENSORED (3s WATCH)";
        svg.append(xLbl);
      } else if (anim.censorPhase === "impeach") {
        const oldSpec = nodeBoxSpec(anim.oldLeaderId || "fednode-0", pts);
        pts.forEach(function (pt) {
          const nid = pt.node.node_id;
          if (nid === (anim.oldLeaderId || "fednode-0") || !pt.node.online || pt.node.state === "BYZANTINE_SILENT") return;
          const seg = trimSegment(nodeBoxSpec(nid, pts), oldSpec, 1);
          drawPacketAlong(svg, seg, prog, "#fd7e14", "amber", "IMPEACH (-30)");
        });
      } else if (anim.censorPhase === "repropose") {
        const lSpec = nodeBoxSpec(leaderId, pts);
        pts.forEach(function (pt) {
          if (pt.node.node_id === leaderId || !pt.node.online) return;
          const seg = trimSegment(lSpec, nodeBoxSpec(pt.node.node_id, pts));
          drawPacketAlong(svg, seg, prog, "#0d6efd", "blue", "PROPOSE (E" + (anim.newEpoch || 2) + ")");
        });
      } else if (anim.censorPhase === "ballot") {
        const lSpec = nodeBoxSpec(leaderId, pts);
        pts.forEach(function (pt) {
          const nid = pt.node.node_id;
          if (nid === leaderId || !pt.node.online || pt.node.quarantined ||
              pt.node.state === "BYZANTINE_SILENT" || pt.node.state === "BYZANTINE_CENSOR") return;
          const seg = trimSegment(nodeBoxSpec(nid, pts), lSpec);
          drawPacketAlong(svg, seg, prog, "#198754", "green", "APPROVE");
        });
      } else if (anim.stage === 4) {
        const lSpec = nodeBoxSpec(leaderId, pts);
        pts.forEach(function (pt) {
          if (!pt.node.online || pt.node.node_id === leaderId || pt.node.state === "BYZANTINE_SILENT") return;
          const seg = trimSegment(lSpec, nodeBoxSpec(pt.node.node_id, pts));
          drawPacketAlong(svg, seg, prog, "#198754", "green", "COMMIT");
        });
      }
      rafId = requestAnimationFrame(renderPacketFrame);
      return;
    }

    if (anim.stage === 1) {
      const src = nodeBoxSpec(anim.sourceKind === "internal" ? anim.sourceId : "external", pts);
      const dst = nodeBoxSpec(anim.targetId, pts);
      const seg = trimSegment(src, dst);
      if (anim.kind === "benign") {
        drawPacketAlong(svg, seg, prog, "#198754", "green", "HTTP 202");
      } else if (anim.kind === "blocked") {
        const bounce = prog < 0.55 ? (prog / 0.55) : (1 - ((prog - 0.55) / 0.45) * 0.72);
        if (prog >= 0.52 && shieldFlashNode !== anim.targetId) {
          shieldFlashNode = anim.targetId;
          shieldFlashUntil = now + 750;
          topologyKey = "";
          renderTopology();
        }
        drawPacketAlong(svg, seg, bounce, "#dc3545", "red", prog < 0.55 ? "POST" : "BLOCKED <1µs", prog >= 0.55);
      } else {
        drawPacketAlong(svg, seg, prog, "#dc3545", "red", "THREAT 403");
      }
    } else if (anim.stage === 2) {
      const needEscalation = Boolean(anim.targetId && anim.targetId !== leaderId);
      if (needEscalation && prog < 0.45) {
        const segEsc = trimSegment(nodeBoxSpec(anim.targetId, pts), nodeBoxSpec(leaderId, pts));
        drawPacketAlong(svg, segEsc, prog / 0.45, "#fd7e14", "amber", "ESCALATE");
      } else {
        const fanProg = needEscalation ? (prog - 0.45) / 0.55 : prog;
        const lSpec = nodeBoxSpec(leaderId, pts);
        pts.forEach(function (pt) {
          if (pt.node.node_id === leaderId || !pt.node.online) return;
          const seg = trimSegment(lSpec, nodeBoxSpec(pt.node.node_id, pts));
          drawPacketAlong(svg, seg, fanProg, "#0d6efd", "blue", "PROPOSE");
        });
      }
    } else if (anim.stage === 3) {
      const lSpec = nodeBoxSpec(leaderId, pts);
      const isFalseFlag = Boolean(anim.isFalseFlag || (pData && pData.framingRejected));
      pts.forEach(function (pt) {
        const nid = pt.node.node_id;
        if (nid === leaderId || !pt.node.online || pt.node.quarantined ||
            pt.node.state === "BYZANTINE_SILENT" || pt.node.state === "BYZANTINE_CENSOR") return;
        const isEquivocator = pt.node.state === "BYZANTINE_EQUIVOCATOR" ||
          Boolean(pData && pData.equivocators && pData.equivocators.has(nid));
        if (isEquivocator) {
          drawPacketAlong(svg, trimSegment(nodeBoxSpec(nid, pts), lSpec, 1.3), prog, "#198754", "green", "APPROVE");
          drawPacketAlong(svg, trimSegment(nodeBoxSpec(nid, pts), lSpec, -1.3), prog, "#dc3545", "red", "REJECT (⚡ -50)");
          return;
        }
        let color = "#198754";
        let mKey = "green";
        let lbl = "APPROVE";
        if (isFalseFlag || pt.node.state === "BYZANTINE_LIAR" || (pData && pData.rejections.has(nid))) {
          color = "#dc3545";
          mKey = "red";
          lbl = "REJECT";
        } else if (pt.node.state === "BYZANTINE_FORGER" || (pData && pData.invalid.has(nid))) {
          color = "#dc3545";
          mKey = "red";
          lbl = "FORGED";
        }
        const seg = trimSegment(nodeBoxSpec(nid, pts), lSpec);
        drawPacketAlong(svg, seg, prog, color, mKey, lbl);
      });
    } else if (anim.stage === 4) {
      const lSpec = nodeBoxSpec(leaderId, pts);
      pts.forEach(function (pt) {
        if (!pt.node.online || pt.node.node_id === leaderId || pt.node.state === "BYZANTINE_SILENT") return;
        const seg = trimSegment(lSpec, nodeBoxSpec(pt.node.node_id, pts));
        drawPacketAlong(svg, seg, prog, "#198754", "green", "COMMIT");
      });
    }

    rafId = requestAnimationFrame(renderPacketFrame);
  }

  function computeRoundReachability(targetProposal, isFalseFlag) {
    const bft = bftParams();
    const health = data.quorum_health;
    if (isFalseFlag) return {ok: false, reason: "framing"};
    if (targetProposal) {
      if (targetProposal.framingRejected) return {ok: false, reason: "framing"};
      if (targetProposal.committed || targetProposal.approvals.size >= bft.q) return {ok: true};
    }
    if (health && health.quorum_reachable === false) return {ok: false, reason: "quorum"};
    const onlineHonest = (data.nodes || []).filter(function (n) {
      return n.online && !n.quarantined && n.state !== "BYZANTINE_LIAR" &&
        n.state !== "BYZANTINE_FORGER" && n.state !== "BYZANTINE_SILENT" && n.state !== "BYZANTINE_EQUIVOCATOR";
    }).length;
    return {ok: onlineHonest >= bft.q, reason: onlineHonest >= bft.q ? "" : "quorum"};
  }

  function advanceCensorImpeachIfReady() {
    if (!anim || anim.finished || anim.kind !== "censor" || anim.impeachStarted) return;
    if (anim.censorPhase !== "blocked_at_leader" && anim.censorPhase !== "escalate") return;
    const nodes = onlineNodes();
    const currentEpoch = nodes.reduce(function (m, n) { return Math.max(m, n.epoch || 1); }, 1);
    const latestProp = proposals().find(function (p) { return p.domain === anim.domain; });
    if (currentEpoch <= (anim.startEpoch || 1) && !(latestProp && latestProp.committed)) return;

    anim.impeachStarted = true;
    const roundId = anim.id;
    const mult = isSlowMo() ? 1.9 : 1.0;
    const isAlive = function () { return anim && anim.id === roundId && !anim.finished; };
    const refreshVisuals = function () {
      topologyKey = "";
      incidentKey = "";
      renderTopology();
      renderIncident();
    };

    anim.oldLeaderId = anim.leaderId;
    anim.leaderId = activeLeaderId();
    anim.newEpoch = currentEpoch;
    anim.stage = 3;
    anim.censorPhase = "impeach";
    anim.stageStartedAt = performance.now();
    anim.stageDuration = Math.round(620 * mult);
    refreshVisuals();

    anim.timerIds.push(setTimeout(function () {
      if (!isAlive()) return;
      anim.censorPhase = "repropose";
      anim.leaderId = activeLeaderId();
      anim.stageStartedAt = performance.now();
      anim.stageDuration = Math.round(450 * mult);
      refreshVisuals();
    }, Math.round(620 * mult)));

    anim.timerIds.push(setTimeout(function () {
      if (!isAlive()) return;
      anim.censorPhase = "ballot";
      anim.stageStartedAt = performance.now();
      anim.stageDuration = Math.round(450 * mult);
      refreshVisuals();
    }, Math.round(1080 * mult)));

    anim.timerIds.push(setTimeout(function () {
      if (!isAlive()) return;
      anim.stage = 4;
      anim.censorPhase = "commit";
      anim.stageStartedAt = performance.now();
      anim.stageDuration = Math.round(480 * mult);
      committedFlashUntil = performance.now() + 1800;
      refreshVisuals();
    }, Math.round(1540 * mult)));

    anim.timerIds.push(setTimeout(function () {
      if (!isAlive()) return;
      anim.finished = true;
      refreshVisuals();
    }, Math.round(2120 * mult)));

    anim.timerIds.push(setTimeout(function () {
      topologyKey = "";
      renderTopology();
    }, Math.round(2120 * mult) + 1800));
  }

  function startAnimationRound(opts) {
    clearAnimationTimers();
    const mult = isSlowMo() ? 1.9 : 1.0;
    const roundId = ++roundCounter;
    const leaderId = activeLeaderId();
    const currentEpoch = onlineNodes().reduce(function (m, n) { return Math.max(m, n.epoch || 1); }, 1);

    anim = {
      id: roundId,
      domain: opts.domain || "",
      sourceKind: opts.sourceKind || "external",
      sourceId: opts.sourceId || "external",
      targetId: opts.targetId || leaderId,
      leaderId: leaderId,
      oldLeaderId: leaderId,
      startEpoch: opts.startEpoch || currentEpoch,
      newEpoch: currentEpoch,
      kind: opts.kind || "consensus",
      censorPhase: opts.kind === "censor" ? "ingress" : "",
      impeachStarted: false,
      isFalseFlag: Boolean(opts.isFalseFlag),
      stage: opts.startStage || 1,
      stageStartedAt: performance.now(),
      stageDuration: Math.round((opts.kind === "blocked" ? 650 : 400) * mult),
      finished: false,
      proposal: opts.proposal || null,
      timerIds: []
    };

    function isAlive() {
      return anim && anim.id === roundId;
    }

    function refreshVisuals() {
      topologyKey = "";
      incidentKey = "";
      renderTopology();
      renderIncident();
    }

    refreshVisuals();
    rafId = requestAnimationFrame(renderPacketFrame);

    if (anim.kind === "censor") {
      anim.timerIds.push(setTimeout(function () {
        if (!isAlive()) return;
        anim.stage = 2;
        anim.censorPhase = "escalate";
        anim.stageStartedAt = performance.now();
        anim.stageDuration = Math.round(380 * mult);
        refreshVisuals();
      }, Math.round(420 * mult)));

      anim.timerIds.push(setTimeout(function () {
        if (!isAlive()) return;
        anim.censorPhase = "blocked_at_leader";
        anim.stageStartedAt = performance.now();
        anim.stageDuration = Math.round(8000 * mult);
        shieldFlashNode = anim.leaderId;
        shieldFlashUntil = performance.now() + 1200;
        refreshVisuals();
        advanceCensorImpeachIfReady();
        const pollWait = setInterval(function () {
          if (!isAlive() || anim.impeachStarted || anim.finished) {
            clearInterval(pollWait);
            return;
          }
          refresh();
        }, 700);
        anim.timerIds.push(setTimeout(function () { clearInterval(pollWait); }, 10500));
      }, Math.round(800 * mult)));

      anim.timerIds.push(setTimeout(function () {
        if (!isAlive() || anim.impeachStarted) return;
        anim.finished = true;
        refreshVisuals();
      }, Math.round(10500 * mult)));
      return;
    }

    if (anim.kind === "benign" || anim.kind === "blocked") {
      anim.timerIds.push(setTimeout(function () {
        if (!isAlive()) return;
        anim.finished = true;
        refreshVisuals();
      }, anim.stageDuration + 80));
      return;
    }

    const t2 = Math.round(420 * mult);
    const t3 = Math.round(920 * mult);
    const t4 = Math.round(1450 * mult);
    const dStage = Math.round(480 * mult);

    if (anim.stage < 2) {
      anim.timerIds.push(setTimeout(function () {
        if (!isAlive()) return;
        anim.stage = 2;
        anim.stageStartedAt = performance.now();
        anim.stageDuration = dStage;
        refreshVisuals();
      }, t2));
    }

    if (anim.stage < 3) {
      anim.timerIds.push(setTimeout(function () {
        if (!isAlive()) return;
        anim.stage = 3;
        anim.stageStartedAt = performance.now();
        anim.stageDuration = dStage;
        refreshVisuals();
      }, anim.stage === 2 ? Math.round(500 * mult) : t3));
    }

    anim.timerIds.push(setTimeout(function () {
      if (!isAlive()) return;
      const latestProp = proposals().find(function (p) { return p.domain === anim.domain; }) || anim.proposal;
      const verdict = computeRoundReachability(latestProp, anim.isFalseFlag);
      if (!verdict.ok) {
        anim.finished = true;
        refreshVisuals();
        return;
      }
      anim.stage = 4;
      anim.stageStartedAt = performance.now();
      anim.stageDuration = Math.round(450 * mult);
      committedFlashUntil = performance.now() + 1800;
      refreshVisuals();

      anim.timerIds.push(setTimeout(function () {
        if (!isAlive()) return;
        anim.finished = true;
        refreshVisuals();
      }, anim.stageDuration + 100));

      anim.timerIds.push(setTimeout(function () {
        topologyKey = "";
        renderTopology();
      }, 1850));
    }, anim.stage === 3 ? Math.round(500 * mult) : anim.stage === 2 ? Math.round(1000 * mult) : t4));
  }

  function visibleProposals() {
    const all = proposals();
    if (!resetBaselineAt) return all;
    return all.filter(function (p) {
      return p.domain === userPinnedDomain || p.domain === selectedDomain || (p.created_at || 0) > resetBaselineAt;
    });
  }

  function synthesizeInFlightProposal(domain) {
    const bft = bftParams();
    const curEpoch = onlineNodes().reduce(function (m, n) { return Math.max(m, n.epoch || 1); }, 1);
    const maxSeq = (data.nodes || []).reduce(function (m, n) { return Math.max(m, n.last_sequence || 0); }, 0);
    return {
      proposal_id: "inflight-" + domain,
      domain: domain,
      proposer: (anim && anim.leaderId) || activeLeaderId(),
      reason: 4,
      epoch: curEpoch,
      sequence: maxSeq + 1,
      threat_score: 0.85,
      latency_ms: 0,
      quorum: bft.q,
      created_at: Date.now(),
      committed: false,
      framingRejected: Boolean(anim && anim.isFalseFlag),
      approvals: new Set(),
      rejections: new Set(),
      framingRejectors: new Set(),
      equivocators: new Set(),
      invalid: new Set(),
      quarantined: new Set()
    };
  }

  function nodeBallotState(node, proposal) {
    const id = node.node_id;
    const isAnimVoteHidden = Boolean(anim && !anim.finished && (anim.kind === "consensus" || anim.kind === "censor") && anim.stage < 3 && anim.domain === (proposal && proposal.domain));
    if (!node.online) return {key: "OFFLINE", text: "OFFLINE", sig: "Unreachable", badge: "text-bg-secondary"};
    if (String(node.state) === "BYZANTINE_SILENT") return {key: "SILENT", text: "⏳ SILENT", sig: "Dropped gRPC", badge: "text-bg-warning text-dark"};
    if (String(node.state) === "BYZANTINE_CENSOR") return {key: "CENSOR", text: "✕ CENSOR", sig: "Leader dropping reports (-30 on impeach)", badge: "text-bg-danger"};
    if (!proposal) {
      if (node.quarantined) return {key: "QUARANTINED", text: "QUARANTINED", sig: "Excluded (<30)", badge: "text-bg-danger"};
      return null;
    }
    if (isAnimVoteHidden) return {key: "WAITING", text: "AUDITING…", sig: "Pending ballot", badge: "text-bg-info text-dark"};
    if (proposal.quarantined && proposal.quarantined.has(id)) {
      return {key: "QUARANTINED", text: "QUARANTINED", sig: "Excluded (<30)", badge: "text-bg-danger"};
    }
    if (proposal.equivocators && proposal.equivocators.has(id)) {
      return {key: "EQUIVOCATED", text: "⚡ DOUBLE-VOTE", sig: "Sent APPROVE + REJECT (-50)", badge: "text-bg-danger"};
    }
    if (proposal.framingRejectors && proposal.framingRejectors.has(id)) {
      return {key: "REJECT", text: "✗ REJECT", sig: "Origin sig invalid", badge: "text-bg-danger"};
    }
    if (proposal.invalid && proposal.invalid.has(id)) {
      return {key: "FORGED", text: "⚠ FORGED", sig: "Invalid Ed25519 (-40)", badge: "text-bg-danger"};
    }
    if (proposal.rejections && proposal.rejections.has(id)) {
      return {key: "REJECT", text: "✗ REJECT", sig: "Dissenting vote (Liar -15)", badge: "text-bg-danger"};
    }
    if (proposal.approvals && proposal.approvals.has(id)) {
      return {key: "APPROVE", text: "✓ APPROVE", sig: "Valid Ed25519", badge: "text-bg-success"};
    }
    if (node.quarantined) {
      return {key: "QUARANTINED", text: "QUARANTINED", sig: "Excluded (<30)", badge: "text-bg-danger"};
    }
    return {key: "WAITING", text: "… WAITING", sig: "Awaiting ballot", badge: "text-bg-secondary"};
  }

  function renderTopology() {
    const svgLines = $("network-lines");
    const layer = $("network-nodes");
    if (!svgLines || !layer) return;

    const nodes = data.nodes || [];
    const stage = $("network-stage");
    if (stage) stage.classList.toggle("topo-stage-scaled", nodes.length > 5);
    const pts = nodePositions(nodes);
    const latest = (data.events || []).length ? data.events[data.events.length - 1] : null;
    const visibleEvents = resetBaselineAt
      ? (data.events || []).filter(function (e) { return (e.timestamp || 0) > resetBaselineAt; })
      : (data.events || []);
    lastSender = rememberSender(visibleEvents, pts, lastSender);
    const activeTarget = $("control-node") ? $("control-node").value : "";
    const coordId = activeCoordinator();
    const leaderId = activeLeaderId();
    const allProps = visibleProposals();
    const isAnimRound = Boolean(anim && !anim.finished && anim.domain && (anim.kind === "consensus" || anim.kind === "censor"));
    const activeProp = allProps.find(function (p) { return p.domain === selectedDomain; }) ||
      (isAnimRound ? synthesizeInFlightProposal(anim.domain) : (allProps[0] || null));
    const now = performance.now();
    const inCommitFlash = now < committedFlashUntil;
    const inShieldFlash = now < shieldFlashUntil ? shieldFlashNode : "";
    const stageTag = anim && !anim.finished ? anim.stage + ":" + (anim.censorPhase || "") + ":" + anim.domain : "settled";
    const health = data.quorum_health;

    const trustMap = {};
    nodes.forEach(function (n) { trustMap[n.node_id] = nodeTrustSummary(n.node_id); });

    const nextKey = JSON.stringify([
      nodes.map(function (n) {
        return [n.node_id, n.online, n.state, n.quarantined, n.org, trustMap[n.node_id]];
      }),
      activeTarget, coordId, leaderId, stageTag, inCommitFlash, inShieldFlash,
      activeProp ? [activeProp.domain, activeProp.committed, Array.from(activeProp.approvals).sort(),
                    Array.from(activeProp.rejections).sort(),
                    activeProp.equivocators ? Array.from(activeProp.equivocators).sort() : [],
                    Array.from(activeProp.invalid).sort(),
                    activeProp.framingRejected] : null,
      lastSender, latest ? latest.id : "", health && health.quorum_reachable
    ]);
    if (nextKey === topologyKey) return;
    topologyKey = nextKey;

    svgLines.replaceChildren();
    layer.replaceChildren();

    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const offlineLink = !pts[i].node.online || !pts[j].node.online;
        svgLines.append(svgEl("line", {
          x1: pts[i].sx.toFixed(1), y1: pts[i].sy.toFixed(1),
          x2: pts[j].sx.toFixed(1), y2: pts[j].sy.toFixed(1),
          class: "mesh-line" + (offlineLink ? " offline" : "")
        }));
      }
    }

    const activeVotingView = Boolean((anim && !anim.finished) || (activeProp && !activeProp.committed));

    pts.forEach(function (pt) {
      const node = pt.node;
      const trust = trustMap[node.node_id];
      const isFault = node.online && (node.quarantined || String(node.state).startsWith("BYZANTINE"));
      const isSelected = node.node_id === activeTarget;
      const isLeader = Boolean(node.online && leaderId && node.node_id === leaderId);
      const isCompact = pts.length > 5;
      const slotClass = !isCompact ? " topo-n5-" + pt.idx : " topo-compact";

      let cardClasses = "card shadow-sm topo-node-card" + slotClass;
      if (isSelected) cardClasses += " topo-selected";
      else if (inCommitFlash && node.online && !isFault && (!activeProp || activeProp.committed)) cardClasses += " topo-committed";
      else if (isFault) cardClasses += " topo-fault";
      if (!node.online) cardClasses += " topo-offline";
      if (inShieldFlash === node.node_id) cardClasses += " topo-shield-flash";

      const card = el("div", cardClasses);
      card.setAttribute("role", "button");
      card.setAttribute("tabindex", "0");
      card.setAttribute("aria-label", "Select " + node.node_id + " as active Target Node");
      if (isCompact) {
        card.style.left = pt.x.toFixed(2) + "%";
        card.style.top = pt.y.toFixed(2) + "%";
      }
      card.addEventListener("click", function () { selectTrafficNode(node.node_id); });
      card.addEventListener("keydown", function (evt) {
        if (evt.key === "Enter" || evt.key === " ") {
          evt.preventDefault();
          selectTrafficNode(node.node_id);
        }
      });

      const body = el("div", "card-body p-2");
      const topRow = el("div", "d-flex justify-content-between align-items-center gap-1");
      topRow.append(
        el("span", "fw-bold topo-meta log-mono text-nowrap", node.node_id),
        el("span", "badge px-1 " + (isLeader ? "text-bg-primary" : "text-bg-light text-dark border"),
          !node.online ? "OFFLINE" : isLeader ? "LEADER ★" : "FOLLOWER")
      );

      const domRow = el("div", "topo-meta text-muted text-truncate mt-1", node.org || DEFAULT_ORGS[node.node_id] || (node.node_id + ".social"));

      const modeName = !node.online ? "OFFLINE" :
        String(node.state).startsWith("BYZANTINE_") ? String(node.state).slice(10) : "NONE";
      const modeClass = modeName === "NONE" ? "text-bg-light text-dark border" :
        modeName === "OFFLINE" ? "text-bg-secondary" : "text-bg-warning text-dark";
      const trustClass = trust.score < 30 ? "text-danger" : trust.score < 70 ? "text-warning-emphasis" : "text-success";

      const metaRow = el("div", "d-flex justify-content-between align-items-center mt-1 gap-1");
      metaRow.append(
        el("span", "badge " + modeClass, modeName),
        el("span", "topo-meta fw-semibold " + trustClass, trust.score + "/100")
      );

      const footRow = el("div", "d-flex justify-content-between align-items-center mt-1 gap-1");
      const ballot = nodeBallotState(node, activeProp);
      if (ballot && (activeProp || ballot.key !== "APPROVE")) {
        const badgeText = inCommitFlash && ballot.key === "APPROVE" ? "✓ WAL+RAM" : ballot.text;
        const bPill = el("span", "badge " + ballot.badge, badgeText);
        bPill.title = ballot.sig;
        footRow.append(bPill);
      } else {
        footRow.append(el("span", "badge text-bg-light text-muted border", "READY"));
      }
      const inspectBtn = el("button", "btn btn-link btn-sm p-0 topo-meta text-decoration-none", "Inspect");
      inspectBtn.type = "button";
      inspectBtn.addEventListener("click", function (evt) {
        evt.stopPropagation();
        openNode(node.node_id);
      });
      footRow.append(inspectBtn);

      body.append(topRow, domRow, metaRow, footRow);
      card.append(body);
      layer.append(card);
    });

    const senderBox = $("external-sender");
    if (senderBox) {
      const showAnimSender = anim && !anim.finished;
      const senderLabel = showAnimSender
        ? (anim.sourceKind === "internal" ? anim.sourceId + " (INTERNAL)" : (anim.domain || "attacker.lab.example"))
        : (lastSender ? lastSender.source.label : "Awaiting sender");
      const isBad = showAnimSender ? (anim.kind !== "benign") : Boolean(lastSender && lastSender.attack);
      senderBox.className = "card shadow-sm external-sender " +
        (isBad ? "border-danger bg-danger-subtle" : lastSender ? "border-success bg-success-subtle" : "");
      $("sender-type").className = "badge mb-1 " + (isBad ? "text-bg-danger" : lastSender ? "text-bg-success" : "text-bg-secondary");
      $("sender-type").textContent = (showAnimSender && anim.sourceKind === "internal") ||
        (lastSender && lastSender.source.kind === "node") ? "INTERNAL SENDER" : "EXTERNAL SENDER";
      $("sender-domain").textContent = senderLabel;
      $("sender-domain").title = senderLabel;
      $("sender-status").textContent = showAnimSender
        ? (anim.kind === "benign" ? "Sending benign post" : anim.kind === "blocked" ? "Testing RAM drop" : "Sending attack payload")
        : (!lastSender ? "Waiting for traffic" : lastSender.attack ? "Last post flagged" : "Last post accepted");
    }

    if ($("mesh-caption")) {
      $("mesh-caption").textContent = onlineNodes().length + " / " + nodes.length + " reachable";
    }
    if ($("message-label")) {
      const label = $("message-label");
      label.classList.toggle("text-danger", Boolean(latest && isAttack(latest)));
      let cleanTarget = latest ? latest.target : "";
      if (cleanTarget === "firewall") cleanTarget = "Local O(1) RAM Firewall";
      if (cleanTarget === "consortium") cleanTarget = "P2P gRPC Consortium";
      label.textContent = latest ? "Latest: " + latest.source + " → " + cleanTarget + " · " + latest.kind :
        "No observed transmissions yet";
      label.title = latest ? label.textContent + " · " + formatTime(latest.timestamp) : label.textContent;
    }
  }

  function openNode(nodeId) {
    selectedNode = nodeId;
    renderNodeDetails();
    if ($("node-dialog") && !$("node-dialog").open) {
      $("node-dialog").showModal();
    }
  }

  function renderNodeDetails() {
    const node = (data.nodes || []).find(function (n) { return n.node_id === selectedNode; });
    if (!node || !$("node-details")) return;
    $("node-dialog-title").textContent = node.node_id;
    const details = $("node-details");
    details.replaceChildren();

    const localDomains = Array.isArray(node.blocked_domains) ? node.blocked_domains : [];
    const localSet = new Set(localDomains);
    const clusterDomains = (data.bans || []).map(function (b) { return b.domain; });
    const allDomains = Array.from(new Set(clusterDomains.concat(localDomains)));
    const missingCount = clusterDomains.filter(function (d) { return !localSet.has(d); }).length;

    const tabs = el("ul", "nav nav-tabs mb-3");
    const statusLi = el("li", "nav-item");
    const statusBtn = el("button", "nav-link" + (selectedNodeTab === "status" ? " active" : ""), "Status & Reputation");
    statusBtn.type = "button";
    statusBtn.addEventListener("click", function () { selectedNodeTab = "status"; renderNodeDetails(); });
    statusLi.append(statusBtn);

    const ramLi = el("li", "nav-item");
    const ramLabel = "Banned Domains · RAM (" + localDomains.length + "/" + allDomains.length + ")" + (missingCount > 0 ? " ⚠" : "");
    const ramBtn = el("button", "nav-link" + (selectedNodeTab === "ram" ? " active" : "") + (missingCount > 0 ? " text-danger" : ""), ramLabel);
    ramBtn.type = "button";
    ramBtn.addEventListener("click", function () { selectedNodeTab = "ram"; renderNodeDetails(); });
    ramLi.append(ramBtn);

    tabs.append(statusLi, ramLi);
    details.append(tabs);

    if (selectedNodeTab === "ram") {
      const syncBanner = el("div", "alert " + (missingCount === 0 && node.online ? "alert-success" : "alert-warning"));
      const bannerTitle = el("div", "fw-semibold mb-1", missingCount === 0 && node.online
        ? "✓ " + node.node_id + "'s Local RAM Firewall: In Sync (Seq #" + (node.last_sequence || 0) + ")"
        : !node.online
        ? "⚠ " + node.node_id + " Offline · " + missingCount + " Ban(s) Missing in Local RAM"
        : "↻ " + node.node_id + " Syncing " + missingCount + " Missed Ban(s) via gRPC CatchupSync…");
      const bannerDesc = el("div", "small mb-0", node.node_id + " stores its persistent ledger in its own isolated SQLite database (/data/wal.db). Its RAM firewall is an in-memory hash set (< 1 µs lookup) that drops requests from banned domains at /inbox.");
      syncBanner.append(bannerTitle, bannerDesc);
      details.append(syncBanner);

      if (!allDomains.length) {
        details.append(el("p", "text-muted small mb-0", "No domains are currently blocked in this node's RAM Firewall or the consortium."));
        return;
      }

      const scrollBox = el("div", "table-responsive log-scroll-box");
      const ramTable = el("table", "table table-sm table-bordered align-middle mb-0");
      const ramHead = el("thead", "table-light");
      const ramHeader = el("tr");
      ["Domain", "Local O(1) RAM State", "Verification Source"].forEach(function (t) { ramHeader.append(el("th", "", t)); });
      ramHead.append(ramHeader);
      const ramBody = el("tbody");
      allDomains.forEach(function (domain) {
        const inRam = localSet.has(domain);
        const tr = el("tr", inRam ? "" : "table-danger");
        const stateCell = el("td");
        stateCell.append(el("span", "badge " + (inRam ? "text-bg-success" : "text-bg-danger"),
          inRam ? "✓ Active in RAM" : "× Missing (Offline)"));
        tr.append(
          el("td", "log-mono", domain),
          stateCell,
          el("td", "small", inRam ? "SQLite WAL + Ed25519 QC" : "Awaiting CatchupSync")
        );
        ramBody.append(tr);
      });
      ramTable.append(ramHead, ramBody);
      scrollBox.append(ramTable);
      details.append(scrollBox);
      return;
    }

    const grid = el("div", "row g-2 mb-3");
    const orgLabel = node.org ? node.org + " (" + node.address + ")" : node.address;
    [
      ["Connection", node.online ? "Active / reachable" : "Inactive / unreachable"],
      ["Reported role", !node.online ? (node.last_known_state || "Offline") :
        String(node.state).startsWith("BYZANTINE") ? node.state :
        node.state === "LEADER" ? "LEADER ★" :
        node.node_id === activeCoordinator() ? "PROPOSER ★" : "PEER VALIDATOR"],
      ["Organisation / Endpoint", orgLabel],
      ["Architecture", "Shared-Nothing · Zero central DB"],
      ["Local Database", "Isolated SQLite WAL (/data/wal.db)"],
      ["Perimeter Defense", "Local RAM cache (< 1 µs O(1))"],
      ["Last sequence", node.last_sequence === undefined ? "Unknown" : "Seq #" + node.last_sequence],
      ["Epoch", node.epoch === undefined ? "Unknown" : "Epoch " + node.epoch]
    ].forEach(function (item) {
      const col = el("div", "col-sm-6");
      const field = el("div", "border rounded p-2 bg-light h-100");
      field.append(el("div", "small text-muted", item[0]), el("div", "fw-semibold small", item[1]));
      col.append(field);
      grid.append(col);
    });
    details.append(
      grid,
      el("h3", "h6 mb-1", node.node_id + "'s peer reputation ledger"),
      el("p", "small text-muted mb-2", "Observations recorded on this node." + (node.online ? "" : " Showing last-known data."))
    );
    if ((node.quarantined_by || []).length) {
      details.append(el("div", "alert alert-danger py-2 px-3 small", "Quarantine reported by: " + node.quarantined_by.join(", ")));
    }
    if (!(node.reputations || []).length) {
      details.append(el("p", "small text-muted mb-0", "No peer reputation records reported."));
      return;
    }

    const repScrollBox = el("div", "table-responsive log-scroll-box");
    const table = el("table", "table table-sm table-bordered align-middle mb-0");
    const head = el("thead", "table-light");
    const header = el("tr");
    ["Peer", "Score", "Voting eligibility"].forEach(function (text) { header.append(el("th", "", text)); });
    head.append(header);
    const body = el("tbody");
    node.reputations.forEach(function (rep) {
      const row = el("tr");
      const eligible = rep.trust_score >= 30 && Boolean(rep.is_active);
      const statusCell = el("td");
      statusCell.append(el("span", "badge " + (eligible ? "text-bg-success" : "text-bg-danger"), eligible ? "Eligible" : "Quarantined"));
      row.append(el("td", "log-mono", rep.peer_id), el("td", "", rep.trust_score + " / 100"), statusCell);
      body.append(row);
    });
    table.append(head, body);
    repScrollBox.append(table);
    details.append(repScrollBox);
  }

  function renderNodesTable() {
    const tbody = $("network-nodes-rows");
    if (!tbody) return;

    const nodes = data.nodes || [];
    const activeCount = onlineNodes().length;
    if ($("nodes-tab-count")) {
      $("nodes-tab-count").textContent = activeCount + "/" + nodes.length;
    }

    const activeTarget = $("control-node") ? $("control-node").value : "";
    const coordId = activeCoordinator();
    const leaderId = activeLeaderId();
    const trustMap = {};
    nodes.forEach(function (n) {
      trustMap[n.node_id] = nodeTrustSummary(n.node_id);
    });

    const allPropsForSeq = proposals();
    const maxActiveSeq = allPropsForSeq.reduce(function (m, p) { return Math.max(m, p.sequence || 0); }, 0);

    const nextKey = JSON.stringify([
      nodes.map(function (n) {
        return [n.node_id, n.online, n.telemetry_available, n.state, n.is_leader, n.last_known_state,
                n.quarantined, n.org, n.epoch, n.last_sequence, trustMap[n.node_id]];
      }),
      activeTarget, coordId, leaderId, maxActiveSeq
    ]);
    if (nextKey === nodesKey) return;
    nodesKey = nextKey;

    tbody.replaceChildren();
    nodes.forEach(function (node) {
      const isSelected = node.node_id === activeTarget;
      const tr = el("tr", "node-row" + (isSelected ? " table-primary" : !node.online ? " table-secondary text-muted" : node.quarantined ? " table-danger" : ""));
      tr.addEventListener("click", function () { selectTrafficNode(node.node_id); });

      const idTd = el("td", "fw-semibold font-monospace small");
      idTd.textContent = node.node_id + (isSelected ? " ●" : "");

      const domainTd = el("td", "small", node.org || DEFAULT_ORGS[node.node_id] || "—");

      const isFault = Boolean(node.online && String(node.state || "").startsWith("BYZANTINE_"));
      const roleTd = el("td");
      if (!node.online) {
        roleTd.append(el("span", "badge text-bg-secondary", node.last_known_state === "LEADER" ? "Leader (last)" : "Follower"));
      } else if (leaderId && node.node_id === leaderId) {
        roleTd.append(el("span", "badge text-bg-primary", "LEADER ★"));
      } else if (!isFault && !node.quarantined && node.node_id === coordId) {
        roleTd.append(el("span", "badge text-bg-info text-dark", "FOLLOWER · Proposer ★"));
      } else {
        roleTd.append(el("span", "badge text-bg-light text-dark border", "FOLLOWER"));
      }

      const displaySeq = node.online && maxActiveSeq > (node.last_sequence || 0) ? maxActiveSeq : node.last_sequence;
      const epochTd = el("td", "small",
        (node.epoch !== undefined ? "Epoch " + node.epoch : "—") +
        (displaySeq !== undefined ? " (Seq #" + displaySeq + ")" : ""));

      const modeTd = el("td");
      const modeName = !node.online ? "—" :
        !node.telemetry_available ? "UNKNOWN" :
        isFault ? String(node.state).slice(10) : "NONE";
      if (isFault) {
        modeTd.append(el("span", "badge text-bg-warning text-dark", modeName));
      } else if (modeName === "NONE") {
        modeTd.append(el("span", "badge text-bg-light text-dark border", "NONE"));
      } else {
        modeTd.append(el("span", "small text-muted", modeName));
      }

      const trust = trustMap[node.node_id];
      const trustClass = trust.score < 30 ? "text-danger" : trust.score < 70 ? "text-warning-emphasis" : "text-success";
      const trustTd = el("td", "fw-semibold small " + trustClass, trust.score + " / 100");

      const statusTd = el("td");
      if (!node.online) {
        statusTd.append(el("span", "badge text-bg-secondary", "OFFLINE"));
      } else if (!node.telemetry_available) {
        statusTd.append(el("span", "badge text-bg-warning text-dark", "NO TELEMETRY"));
      } else if (node.quarantined || !trust.eligible) {
        statusTd.append(el("span", "badge text-bg-danger", "QUARANTINED (< 30)"));
      } else if (isFault) {
        statusTd.append(el("span", "badge text-bg-warning text-dark", "FAULT MODE"));
      } else {
        statusTd.append(el("span", "badge text-bg-success", "ONLINE"));
      }

      const inspectTd = el("td");
      const inspectBtn = el("button", "btn btn-outline-secondary btn-sm py-0 px-2", "Inspect");
      inspectBtn.type = "button";
      inspectBtn.addEventListener("click", function (evt) {
        evt.stopPropagation();
        openNode(node.node_id);
      });
      inspectTd.append(inspectBtn);

      tr.append(idTd, domainTd, roleTd, epochTd, modeTd, trustTd, statusTd, inspectTd);
      tbody.append(tr);
    });

    if (!nodes.length) {
      const emptyRow = el("tr");
      const emptyCell = el("td", "text-center text-muted py-3", "No nodes configured.");
      emptyCell.colSpan = 8;
      emptyRow.append(emptyCell);
      tbody.append(emptyRow);
    }
  }

  function renderPhaseStepperInto(container, activeStage, isFailed, isCommitted, bft, customLabels) {
    if (!container) return;
    container.replaceChildren();
    const steps = [
      [1, (customLabels && customLabels[1]) || "1. Ingress & Classify"],
      [2, (customLabels && customLabels[2]) || "2. Leader Proposal"],
      [3, (customLabels && customLabels[3]) || ("3. BFT Ballot Audit (Q=" + bft.q + "/" + bft.n + ")")],
      [4, (customLabels && customLabels[4]) || "4. Quorum Commit"]
    ];
    steps.forEach(function (step) {
      const num = step[0];
      let cls = "border rounded py-1 px-2 text-center small fw-semibold bg-light text-muted";
      if (isFailed && num === (customLabels && customLabels.failStep ? customLabels.failStep : 3)) {
        cls = "border border-danger rounded py-1 px-2 text-center small fw-semibold bg-danger-subtle text-danger-emphasis";
      } else if (isCommitted && num <= 4) {
        cls = "border border-success rounded py-1 px-2 text-center small fw-semibold bg-success-subtle text-success-emphasis";
      } else if (activeStage === num) {
        cls = "border border-primary rounded py-1 px-2 text-center small fw-semibold bg-primary text-white";
      } else if (activeStage > num) {
        cls = "border border-success rounded py-1 px-2 text-center small fw-semibold bg-success-subtle text-success-emphasis";
      }
      const col = el("div", "col-6 col-md-3");
      col.append(el("div", cls, step[1]));
      container.append(col);
    });
  }

  function renderIncident() {
    const rawAll = proposals();
    if (!initialLoadDone) {
      rawAll.forEach(function (p) {
        seenDomains.add(p.domain);
        if (p.committed) seenCommitted.add(p.domain);
      });
      initialLoadDone = true;
    } else {
      const newestUnseen = rawAll.find(function (p) { return !seenDomains.has(p.domain); });
      if (newestUnseen) {
        resetBaselineAt = 0;
        rawAll.forEach(function (p) { seenDomains.add(p.domain); });
        selectedDomain = newestUnseen.domain;
        userPinnedDomain = "";
        if (newestUnseen.domain === lastStartedRoundDomain) {
          lastStartedRoundDomain = "";
          if (anim && !anim.finished && anim.domain === newestUnseen.domain) {
            anim.proposal = newestUnseen;
            if (newestUnseen.framingRejected) anim.isFalseFlag = true;
          }
        } else if (!anim || anim.finished || anim.domain !== newestUnseen.domain) {
          startAnimationRound({
            domain: newestUnseen.domain,
            sourceKind: "external",
            targetId: newestUnseen.proposer || activeLeaderId(),
            kind: "consensus",
            isFalseFlag: newestUnseen.framingRejected,
            proposal: newestUnseen
          });
        } else {
          anim.proposal = newestUnseen;
          if (newestUnseen.framingRejected) anim.isFalseFlag = true;
        }
      } else {
        const newlyCommitted = rawAll.find(function (p) { return p.committed && !seenCommitted.has(p.domain); });
        if (newlyCommitted) {
          resetBaselineAt = 0;
          seenCommitted.add(newlyCommitted.domain);
          selectedDomain = newlyCommitted.domain;
          if (!anim || anim.finished || anim.domain !== newlyCommitted.domain) {
            startAnimationRound({
              domain: newlyCommitted.domain,
              sourceKind: "external",
              targetId: newlyCommitted.proposer || activeLeaderId(),
              kind: "consensus",
              startStage: 3,
              proposal: newlyCommitted
            });
          }
        }
      }
      rawAll.forEach(function (p) {
        if (p.committed) seenCommitted.add(p.domain);
      });
    }

    const all = visibleProposals();
    const isAnimRound = Boolean(anim && !anim.finished && anim.domain && (anim.kind === "consensus" || anim.kind === "censor"));
    if (userPinnedDomain && all.some(function (p) { return p.domain === userPinnedDomain; })) {
      selectedDomain = userPinnedDomain;
    } else if (isAnimRound) {
      selectedDomain = anim.domain;
    } else if (!selectedDomain || !all.some(function (p) { return p.domain === selectedDomain; })) {
      selectedDomain = all.length ? all[0].domain : "";
    }
    const proposal = all.find(function (p) { return p.domain === selectedDomain; }) ||
      (isAnimRound ? synthesizeInFlightProposal(anim.domain) : (all[0] || null));
    const health = data.quorum_health || null;
    const quorumBlocked = Boolean(health && health.quorum_reachable === false);
    const isAnimActive = Boolean(anim && !anim.finished && (anim.kind === "consensus" || anim.kind === "censor"));
    const activeAnimStage = isAnimActive ? anim.stage : 0;
    const censorPhaseTag = anim && !anim.finished ? (anim.censorPhase || "") : "";
    const curEpoch = onlineNodes().reduce(function (m, n) { return Math.max(m, n.epoch || 1); }, 1);

    const nextKey = JSON.stringify([
      proposal ? [proposal.domain, proposal.committed, proposal.framingRejected, proposal.epoch, proposal.sequence,
                  Array.from(proposal.approvals).sort(),
                  Array.from(proposal.rejections).sort(),
                  proposal.equivocators ? Array.from(proposal.equivocators).sort() : [],
                  Array.from(proposal.invalid).sort(),
                  Array.from(proposal.quarantined).sort()] : null,
      (data.nodes || []).map(function (n) { return [n.node_id, n.online, n.quarantined, n.state, n.epoch]; }),
      health, activeAnimStage, censorPhaseTag, curEpoch, anim && anim.finished, anim && anim.domain
    ]);
    if (nextKey === incidentKey) return;
    incidentKey = nextKey;

    const stepper = $("phase-stepper");
    const verdictBar = $("verdict-bar");
    const verdictFooter = $("verdict-footer");
    const state = $("incident-state");
    const panel = $("topology-panel");
    const phaseBadge = $("topology-phase-badge");
    if (!stepper || !verdictBar || !state || !panel) return;

    verdictBar.replaceChildren();
    const bft = bftParams();
    const isCensorAnim = Boolean(anim && !anim.finished && anim.kind === "censor" && (!proposal || anim.domain === proposal.domain));
    const censorStepperLabels = isCensorAnim ? {
      2: (anim.censorPhase === "escalate" || anim.censorPhase === "blocked_at_leader") ? "2. Censored (3s Watch)" : "2. Leader Impeached",
      3: anim.censorPhase === "impeach" ? ("3. Impeach → Epoch " + (anim.newEpoch || curEpoch)) :
         anim.censorPhase === "repropose" ? ("3. Epoch " + (anim.newEpoch || curEpoch) + " Proposal") : "3. BFT Ballot Audit",
      failStep: (anim.censorPhase === "blocked_at_leader") ? 2 : 0
    } : null;

    if (!proposal) {
      panel.classList.remove("border-danger");
      if (verdictFooter) verdictFooter.className = "card-footer d-flex flex-column gap-1 py-2 px-3 small";
      if ($("verdict-evidence")) $("verdict-evidence").textContent = "";
      const latestThreat = (data.events || []).slice().reverse().find(function (e) {
        return e.kind === "threat" && (!resetBaselineAt || (e.timestamp || 0) > resetBaselineAt);
      });
      if (isCensorAnim) {
        state.className = anim.censorPhase === "blocked_at_leader" ? "badge text-bg-danger" : "badge text-bg-primary";
        state.textContent = anim.stage === 1 ? "STAGE 1 · INGRESS" :
          anim.censorPhase === "impeach" ? "STAGE 3 · IMPEACHMENT (-30)" :
          "STAGE 2 · LEADER CENSORED (3s)";
      } else {
        state.className = "badge " + (latestThreat ? "text-bg-danger" : "text-bg-secondary");
        state.textContent = latestThreat ? "THREAT DETECTED" : "FLEET IDLE";
      }
      if (phaseBadge) {
        phaseBadge.className = state.className + " d-none";
        phaseBadge.textContent = state.textContent;
      }
      renderPhaseStepperInto(stepper, anim && !anim.finished ? anim.stage : 0, isCensorAnim && anim.censorPhase === "blocked_at_leader", false, bft, censorStepperLabels);
      verdictBar.append(el("span", "text-muted",
        isCensorAnim ? ((anim.domain || "threat") + " — Censored by Leader; waiting 3s follower impeachment…")
          : latestThreat ? (latestThreat.domain || latestThreat.source) + " — " + latestThreat.message
          : "Trigger an attack on the left to watch 4-phase BFT consensus live."));
      return;
    }

    const visibleApprovals = proposal.approvals.size;
    const quorumNeeded = bft.q;
    const isFramingRejected = Boolean(proposal.framingRejected);
    const isFinalCommitted = !isFramingRejected && Boolean(proposal.committed || visibleApprovals >= quorumNeeded);
    const unreachable = !isFramingRejected && !isFinalCommitted && quorumBlocked;
    const isAnimPlaying = Boolean(anim && !anim.finished && anim.domain === proposal.domain);
    const stepperStage = isAnimPlaying ? anim.stage : (isFinalCommitted ? 4 : 3);
    const stepperFailed = isCensorAnim
      ? (anim.censorPhase === "blocked_at_leader")
      : ((!isAnimPlaying || anim.stage >= 3) && (unreachable || isFramingRejected || (!isFinalCommitted && !isAnimPlaying)));

    panel.classList.toggle("border-danger", !isFinalCommitted || (isCensorAnim && anim.censorPhase === "blocked_at_leader"));

    if (isCensorAnim && activeAnimStage < 4) {
      if (anim.censorPhase === "blocked_at_leader") {
        state.className = "badge text-bg-danger";
        state.textContent = "STAGE 2 · CENSORED BY LEADER";
      } else if (anim.censorPhase === "impeach") {
        state.className = "badge text-bg-warning text-dark";
        state.textContent = "STAGE 3 · IMPEACHMENT (-30 TRUST)";
      } else if (anim.censorPhase === "repropose") {
        state.className = "badge text-bg-primary";
        state.textContent = "EPOCH " + (anim.newEpoch || curEpoch) + " · NEW LEADER PROPOSE";
      } else {
        state.className = "badge text-bg-primary";
        state.textContent = activeAnimStage === 1 ? "STAGE 1 · INGRESS" : "STAGE 3 · BALLOT AUDIT";
      }
    } else if (isAnimPlaying && activeAnimStage < 4) {
      state.className = "badge text-bg-primary";
      state.textContent = activeAnimStage === 1 ? "STAGE 1 · INGRESS" :
        activeAnimStage === 2 ? "STAGE 2 · PROPOSE" : "STAGE 3 · BALLOT AUDIT";
    } else if (isFramingRejected) {
      state.className = "badge text-bg-danger";
      state.textContent = "FRAMING REJECTED (-25)";
    } else if (unreachable) {
      state.className = "badge text-bg-danger";
      state.textContent = "QUORUM UNREACHABLE (" + health.eligible_voters + "/" + health.quorum + " eligible)";
    } else if (isFinalCommitted) {
      state.className = "badge text-bg-success";
      state.textContent = "PHASE 3 · QUORUM REACHED & BANNED";
    } else {
      state.className = "badge text-bg-warning text-dark";
      state.textContent = "QUORUM PENDING (" + visibleApprovals + "/" + quorumNeeded + ")";
    }
    if (phaseBadge) {
      phaseBadge.className = state.className + " d-none";
      phaseBadge.textContent = state.textContent;
    }

    renderPhaseStepperInto(stepper, stepperStage, stepperFailed, isFinalCommitted && !isAnimPlaying, bft, censorStepperLabels);

    if (verdictFooter) {
      verdictFooter.className = "card-footer d-flex flex-column gap-1 py-2 px-3 small " +
        (isFramingRejected || unreachable ? "bg-danger-subtle text-danger-emphasis" :
         isFinalCommitted ? "bg-success-subtle" : "");
    }

    const latencyMs = proposal.latency_ms || 18;
    const scoreVal = Number(proposal.threat_score || 0.85).toFixed(2);
    const threatEvent = (data.events || []).slice().reverse().find(function (e) {
      return e.domain === proposal.domain && e.kind === "threat";
    });
    const defaultReason = reasonNames[proposal.reason] ? (reasonNames[proposal.reason] + " detected") : "Malicious activity";
    const evidenceText = isFramingRejected
      ? "Invalid Origin Sig (-25 trust)"
      : unreachable
      ? quorumUnreachableText(health)
      : (threatEvent ? threatEvent.message : defaultReason);

    const domBadge = el("span", "fw-bold log-mono text-dark", proposal.domain);
    const metaSpan = el("span", "text-muted",
      "· " + (isFinalCommitted ? latencyMs + " ms" : isFramingRejected ? "Rejected" : "Stalled") +
      " · Score " + scoreVal + " · Seq #" + (proposal.sequence || 1) +
      " · Quorum " + visibleApprovals + "/" + quorumNeeded);
    metaSpan.title = evidenceText;

    const pct = Math.min(100, Math.round((Math.min(visibleApprovals, quorumNeeded) / quorumNeeded) * 100));
    const progress = el("div", "progress progress-thin");
    progress.setAttribute("role", "progressbar");
    progress.setAttribute("aria-label", "Recorded approvals");
    progress.setAttribute("aria-valuemin", "0");
    progress.setAttribute("aria-valuemax", String(quorumNeeded));
    progress.setAttribute("aria-valuenow", String(Math.min(visibleApprovals, quorumNeeded)));
    const fill = el("div", "progress-bar " + (isFinalCommitted ? "bg-success" : "bg-danger"));
    fill.style.width = pct + "%";
    progress.append(fill);

    const summaryPill = el("span", "verdict-evidence text-muted", evidenceText);
    summaryPill.title = evidenceText;

    verdictBar.append(domBadge, metaSpan, progress);

    if (isFinalCommitted) {
      const fwTestBtn = el("button", "btn btn-outline-danger btn-sm py-0 px-2 ms-auto flex-shrink-0", "Test Firewall Drop");
      fwTestBtn.type = "button";
      fwTestBtn.addEventListener("click", function () {
        runAction({
          action: "inject",
          node: $("control-node").value || "fednode-0",
          scenario: "malware",
          source: "external",
          domain: proposal.domain
        });
      });
      verdictBar.append(fwTestBtn);
    }

    verdictBar.append(summaryPill);
  }

  function renderEvents() {
    const rows = $("event-rows");
    if (!rows) return;
    rows.replaceChildren();
    const filterValue = $("event-filter") ? $("event-filter").value : "all";
    const events = (data.events || []).filter(function (event) {
      return filterValue === "all" || securityKinds.includes(event.kind);
    }).slice(-40).reverse();

    events.forEach(function (event) {
      const row = el("tr", isAttack(event) ? "table-danger" : "");
      const route = el("td", "text-nowrap");
      route.append(el("span", "", event.source), el("span", "text-muted", " → "), el("span", "", event.target));

      const kindClass = isAttack(event) ? "text-bg-danger" :
        event.kind === "commit" ? "text-bg-success" :
        event.kind === "proposal" || event.kind === "vote" ? "text-bg-primary" : "text-bg-secondary";
      const kindTd = el("td");
      kindTd.append(el("span", "badge " + kindClass, String(event.kind || "").toUpperCase()));

      const detail = el("td", "", event.message);
      detail.title = "Observed by " + event.observer;
      row.append(el("td", "text-nowrap", formatTime(event.timestamp)), route, kindTd, detail);
      rows.append(row);
    });

    if (!events.length) {
      const row = el("tr");
      const cell = el("td", "text-center text-muted py-3", "No activity observed yet. Incoming posts and consensus messages will appear here.");
      cell.colSpan = 4;
      row.append(cell);
      rows.append(row);
    }
  }

  function renderBans() {
    const list = $("banned-list");
    if (!list) return;
    list.replaceChildren();
    const query = $("ban-search") ? $("ban-search").value.trim().toLowerCase() : "";
    const bans = (data.bans || []).filter(function (ban) { return ban.domain.toLowerCase().includes(query); });
    const propMap = new Map(proposals().map(function (p) { return [p.domain, p]; }));

    if ($("banned-badge")) {
      $("banned-badge").textContent = (data.bans || []).length;
    }

    bans.forEach(function (ban) {
      const row = el("tr", "node-row");
      const complete = ban.applied_on.length === (data.nodes || []).length;
      const pInfo = propMap.get(ban.domain);
      const ms = (pInfo && pInfo.latency_ms) ? pInfo.latency_ms : 18;

      const domainTd = el("td", "fw-semibold log-mono", ban.domain);
      const coverageTd = el("td");
      coverageTd.append(el("span", "badge " + (complete ? "text-bg-success" : "text-bg-warning text-dark"),
        ban.applied_on.length + " / " + (data.nodes || []).length + " servers"));

      const nodesText = (ban.applied_on.join(", ") || "None") +
        (ban.last_known_on.length ? " (last known: " + ban.last_known_on.join(", ") + ")" : "");
      const nodesTd = el("td", "small text-muted", nodesText);
      const proofTd = el("td", "small log-mono text-nowrap", ms + " ms · Ed25519 QC");

      row.append(domainTd, coverageTd, nodesTd, proofTd);
      row.addEventListener("click", function () {
        userPinnedDomain = ban.domain;
        selectedDomain = ban.domain;
        if ($("traffic-domain")) $("traffic-domain").value = ban.domain;
        incidentKey = "";
        renderIncident();
      });
      list.append(row);
    });

    if (!bans.length) {
      const row = el("tr");
      const cell = el("td", "text-center text-muted py-3", query ? "No domains match your search." : "No reported domain blocks.");
      cell.colSpan = 4;
      row.append(cell);
      list.append(row);
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

  function renderControls() {
    const nodes = data.nodes || [];
    const options = nodes.map(function (node) {
      const label = node.node_id + (node.org ? " (" + node.org + ")" : "") + (node.online ? "" : " · offline");
      return [label, node.node_id];
    });
    const fallbackOpts = options.length ? options : [["No configured nodes", ""]];

    const select = $("control-node");
    if (select) {
      const previous = select.value;
      updateOptions(select, fallbackOpts);
      if (options.some(function (o) { return o[1] === previous; })) select.value = previous;
    }
    const selected = select ? select.value : "";

    const chaosSelect = $("chaos-node");
    if (chaosSelect) {
      const prevChaos = chaosSelect.value;
      updateOptions(chaosSelect, fallbackOpts);
      if (options.some(function (o) { return o[1] === prevChaos; })) {
        chaosSelect.value = prevChaos;
      } else if (options.some(function (o) { return o[1] === selected; })) {
        chaosSelect.value = selected;
      }
    }
    const chaosSelected = chaosSelect ? chaosSelect.value : selected;

    const trafficSource = $("traffic-source");
    if (trafficSource) {
      const prevOrigin = trafficSource.value;
      const originOptions = [["External Server (Internet)", "external"]];
      nodes.forEach(function (n) {
        if (n.node_id !== selected) {
          originOptions.push(["Internal Node: " + n.node_id + " (sends to " + (selected || "target") + ")", n.node_id]);
        }
      });
      updateOptions(trafficSource, originOptions);
      if (originOptions.some(function (o) { return o[1] === prevOrigin; })) trafficSource.value = prevOrigin;
    }

    const node = nodes.find(function (item) { return item.node_id === selected; });
    if (controlledNode !== selected && node) controlledNode = selected;

    const chaosNodeObj = nodes.find(function (item) { return item.node_id === chaosSelected; });
    if (controlledChaosNode !== chaosSelected && chaosNodeObj) {
      controlledChaosNode = chaosSelected;
      if ($("fault-mode")) {
        $("fault-mode").value = String(chaosNodeObj.state).startsWith("BYZANTINE_")
          ? chaosNodeObj.state.slice(10) : "NONE";
      }
    }

    if ($("trust-peer")) $("trust-peer").value = chaosSelected || "fednode-0";
    if ($("operator-target-badge")) $("operator-target-badge").textContent = "Target: " + (selected || "—");
    if ($("traffic-target-badge")) $("traffic-target-badge").textContent = "Targeting: " + (selected || "—");
    if ($("chaos-target-badge")) {
      const leaderNow = activeLeaderId();
      const isLeaderChaos = Boolean(chaosNodeObj && leaderNow && chaosSelected === leaderNow);
      $("chaos-target-badge").className = "badge " + (isLeaderChaos ? "text-bg-danger" : "text-bg-warning text-dark");
      $("chaos-target-badge").textContent = "Targeting: " + (chaosSelected || "—") + (isLeaderChaos ? " (LEADER!)" : "");
    }
    if ($("controlled-node-status")) {
      $("controlled-node-status").textContent = node ? (node.online ? "Online" : "Offline") +
        " · " + (node.quarantined ? "Quarantined (<30)" : node.state) : "";
    }
    if ($("chaos-node-status")) {
      const chaosTrust = chaosSelected ? nodeTrustSummary(chaosSelected).score : 100;
      $("chaos-node-status").textContent = chaosNodeObj ? (chaosNodeObj.online ? "Online" : "Offline") +
        " · " + chaosNodeObj.state + " · Trust: " + chaosTrust + "/100" : "";
    }
    if ($("controls-state")) {
      $("controls-state").textContent = controls.connected ? "Connected · Actions use real node identities" : controls.message || "Connecting…";
    }
    document.querySelectorAll(".control-action-btn").forEach(function (button) {
      button.disabled = actionBusy || !controls.enabled || !controls.connected;
    });
    if ($("stop-node")) $("stop-node").disabled = actionBusy || !chaosNodeObj || !chaosNodeObj.online;
    if ($("revive-node")) $("revive-node").disabled = actionBusy || !chaosNodeObj || chaosNodeObj.online;
    if ($("apply-settings")) $("apply-settings").disabled = actionBusy || !controls.connected || !chaosNodeObj;
    if ($("restore-peer")) $("restore-peer").disabled = actionBusy || !controls.connected || !chaosNodeObj;
  }

  function render() {
    const nodes = data.nodes || [];
    const active = onlineNodes().length;
    const allProposals = proposals();
    const visibleList = visibleProposals();
    const committed = new Set(allProposals.filter(function (p) { return p.committed; }).map(function (p) { return p.domain; }));
    const pending = new Set(visibleList.filter(function (p) { return !p.committed && !committed.has(p.domain) && !p.framingRejected; }).map(function (p) { return p.domain; }));
    const bft = bftParams();
    const health = data.quorum_health;
    const quorumBlocked = Boolean(health && health.quorum_reachable === false);
    const quorumUnreachable = Boolean(quorumBlocked && pending.size > 0);
    const coordId = activeCoordinator();
    const maxEpoch = nodes.reduce(function (m, n) { return Math.max(m, n.epoch || 1); }, 1);

    $("active-count").textContent = active;
    $("inactive-count").textContent = nodes.length - active;
    $("total-label").textContent = "/ " + nodes.length;
    $("threat-count").textContent = pending.size;
    $("ban-count").textContent = (data.bans || []).length;

    const banner = $("quorum-banner");
    const bannerTitle = $("quorum-banner-title");
    const bannerDetail = $("quorum-banner-detail");
    const bannerBadge = $("quorum-banner-badge");
    if (banner && bannerBadge) {
      if (!nodes.length || !active) {
        banner.className = "alert alert-danger d-flex flex-wrap justify-content-between align-items-center gap-2 py-2 px-3 mb-2 shadow-sm small";
        if (bannerTitle) bannerTitle.textContent = "Cluster Offline";
        bannerBadge.className = "badge text-bg-danger";
        bannerBadge.textContent = "CLUSTER OFFLINE (0/" + nodes.length + ")";
      } else if (quorumBlocked) {
        banner.className = "alert alert-danger d-flex flex-wrap justify-content-between align-items-center gap-2 py-2 px-3 mb-2 shadow-sm small";
        if (bannerTitle) bannerTitle.textContent = "QUORUM UNREACHABLE";
        if (bannerDetail) bannerDetail.textContent = quorumUnreachableText(health);
        bannerBadge.className = "badge text-bg-danger";
        bannerBadge.textContent = "QUORUM UNREACHABLE (" + health.eligible_voters + "/" + health.quorum + ")";
      } else {
        banner.className = "alert alert-success d-flex flex-wrap justify-content-between align-items-center gap-2 py-2 px-3 mb-2 shadow-sm small";
        if (bannerTitle) bannerTitle.textContent = "Consortium Quorum Healthy";
        if (bannerDetail) bannerDetail.textContent = "";
        bannerBadge.className = "badge text-bg-success";
        bannerBadge.textContent = "QUORUM READY (" + (health ? health.eligible_voters : active) + "/" + bft.n + ")";
      }
    }

    if ($("threat-label")) $("threat-label").textContent = quorumUnreachable ? "quorum unreachable" : "awaiting";
    if ($("threat-subtext")) {
      $("threat-subtext").textContent = quorumUnreachable ? quorumUnreachableText(health) :
        "Rule: Q = " + bft.q + "/" + bft.n + " (N=" + bft.n + ", f=" + bft.f + ")";
    }
    if ($("bft-tolerance-hint")) {
      $("bft-tolerance-hint").textContent = "With N=" + bft.n + ", consortium tolerates f=" + bft.f + " rogue/offline node(s) and requires Q=" + bft.q + " votes.";
    }
    const leaderId = activeLeaderId();
    if ($("active-subtext")) {
      $("active-subtext").textContent = !active
        ? "Epoch " + maxEpoch + " (No leader online)"
        : leaderId
          ? "Epoch " + maxEpoch + " (Leader: " + leaderId + " ★)" +
            (coordId && coordId !== leaderId ? " · Proposer: " + coordId : "")
          : "Epoch " + maxEpoch + " (Leader offline — electing…)";
    }
    if ($("ban-subtext")) {
      const committedList = allProposals.filter(function (p) { return p.committed; });
      if (committedList.length) {
        const avgMs = Math.round(committedList.reduce(function (s, p) { return s + (p.latency_ms || 18); }, 0) / committedList.length);
        $("ban-subtext").textContent = "(Avg: " + avgMs + " ms)";
      } else {
        $("ban-subtext").textContent = "(WAL + O(1) RAM)";
      }
    }

    $("updated").textContent = "Updated " + formatTime(data.updated_at);
    const conn = $("connection");
    conn.className = "badge text-bg-light text-dark";
    conn.replaceChildren(
      el("span", "status-dot " + (active ? "dot-green" : "dot-red") + " me-1"),
      document.createTextNode(active ? "Live observations" : "No nodes reachable")
    );

    const notice = $("live-notice");
    const oldNodes = nodes.filter(function (n) { return n.online && !n.telemetry_available; }).length;
    notice.hidden = active > 0 && !oldNodes;
    notice.textContent = !active
      ? "No servers are reachable. Start the cluster with start-cluster.bat."
      : oldNodes + " server(s) are online without telemetry. Rebuild or restart updated nodes to see votes and activity.";

    advanceCensorImpeachIfReady();
    renderIncident();
    renderTopology();
    renderNodesTable();
    renderEvents();
    renderBans();
    renderControls();
    if ($("node-dialog") && $("node-dialog").open) renderNodeDetails();
  }

  async function refresh() {
    if (fetching) return;
    fetching = true;
    if ($("refresh")) $("refresh").disabled = true;
    try {
      const responses = await Promise.all([
        fetch("/api/cluster", {cache: "no-store", signal: AbortSignal.timeout(5000)}),
        fetch("/api/controls", {cache: "no-store", signal: AbortSignal.timeout(5000)})
      ]);
      const response = responses[0];
      if (!response.ok) throw new Error("Dashboard API unavailable");
      const next = await response.json();
      controls = responses[1].ok ? await responses[1].json()
        : {enabled: false, connected: false, runtime: {}, message: "Restart the updated dashboard to enable live controls."};
      data = next;
    } catch (_) {
      const conn = $("connection");
      conn.className = "badge text-bg-light text-dark";
      conn.replaceChildren(el("span", "status-dot dot-red me-1"), document.createTextNode("Connection lost"));
      $("live-notice").hidden = false;
      $("live-notice").textContent = "Dashboard connection lost. Displayed observations are stale; retrying automatically.";
      return;
    } finally {
      fetching = false;
      if ($("refresh")) $("refresh").disabled = false;
    }

    try {
      render();
    } catch (renderError) {
      console.error("Dashboard render error:", renderError);
    }
  }

  async function runAction(body) {
    if (actionBusy) return false;
    actionBusy = true;
    let ok = false;
    const result = $("action-result");
    result.className = "alert alert-info py-2 px-2 small mb-0";
    result.textContent = "Working: " + body.action + "…";
    renderControls();
    try {
      const response = await fetch("/api/actions", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": controls.csrf},
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(120000)
      });
      const value = await response.json();
      if (!response.ok) throw new Error(value.error || "Action failed");
      result.className = "alert py-2 px-2 small mb-0 " + (value.accepted === false ? "alert-danger" : "alert-success");
      result.textContent = value.message || "Action completed";
      if (value.inbox_results) {
        result.textContent += " · " + value.inbox_results.map(function (r) {
          return "HTTP " + r.http_status + " / " + (r.status || "unknown");
        }).filter(function (item, index, all) { return all.indexOf(item) === index; }).join(", ");
      }
      if (value.outcomes && body.action === "trust") result.textContent += " in " + value.outcomes.length + " ledger(s)";
      if (body.action === "inject" && value.domain) {
        const firstRes = (value.inbox_results && value.inbox_results[0]) || {};
        const ingressStatus = String(firstRes.status || "");
        const leaderIdNow = activeLeaderId();
        const leaderObj = (data.nodes || []).find(function (n) { return n.node_id === leaderIdNow; });
        const targetIdNow = body.node || leaderIdNow;
        let animKind = ingressStatus === "ACCEPTED" ? "benign" :
          ingressStatus === "BLOCKED" ? "blocked" : "consensus";
        if (animKind === "consensus" && leaderObj && leaderObj.state === "BYZANTINE_CENSOR" && targetIdNow !== leaderIdNow) {
          animKind = "censor";
        }
        lastSender = {
          source: {
            kind: body.source === "internal" ? "node" : "external",
            label: body.source === "internal" ? body.source_node : value.domain
          },
          attack: animKind !== "benign"
        };
        if (animKind !== "benign") {
          resetBaselineAt = 0;
          userPinnedDomain = "";
          seenDomains.delete(value.domain);
          selectedDomain = value.domain;
        }
        lastStartedRoundDomain = (animKind === "consensus" || animKind === "censor") ? value.domain : "";
        startAnimationRound({
          domain: value.domain,
          sourceKind: body.source || "external",
          sourceId: body.source === "internal" ? body.source_node : "external",
          targetId: targetIdNow,
          kind: animKind,
          isFalseFlag: body.scenario === "false_flag"
        });
      }
      if (body.action === "add_org" && $("org-domain")) $("org-domain").value = "";
      if (body.action === "revive" || body.action === "reset_all") {
        controlledChaosNode = "";
        if (body.action === "reset_all") {
          resetBaselineAt = Date.now();
          selectedDomain = "";
          userPinnedDomain = "";
          lastStartedRoundDomain = "";
          lastSender = null;
          clearAnimationTimers();
          anim = null;
          proposals().forEach(function (p) {
            seenDomains.add(p.domain);
            if (p.committed) seenCommitted.add(p.domain);
          });
          if ($("traffic-domain")) $("traffic-domain").value = "";
          if ($("fault-mode")) $("fault-mode").value = "NONE";
          if ($("chaos-role-guide")) $("chaos-role-guide").hidden = true;
        }
      }
      ok = true;
    } catch (error) {
      result.className = "alert alert-danger py-2 px-2 small mb-0";
      result.textContent = error.name === "TimeoutError"
        ? "Action timed out. Refresh and inspect actual node state before retrying."
        : error.message;
    } finally {
      actionBusy = false;
      await refresh();
      renderControls();
    }
    return ok;
  }

  function actor() {
    return $("control-node") ? $("control-node").value : "fednode-0";
  }

  function chaosActor() {
    return $("chaos-node") && $("chaos-node").value ? $("chaos-node").value : actor();
  }

  function traffic(scenario) {
    const rawOrigin = $("traffic-source") ? $("traffic-source").value : "external";
    const isInternal = rawOrigin !== "external";
    const sourceType = isInternal ? "internal" : "external";
    const sourceNode = isInternal ? (rawOrigin === "internal" ? ($("source-node") ? $("source-node").value : "fednode-1") : rawOrigin) : "";
    const customDomain = $("traffic-domain") ? $("traffic-domain").value.trim().toLowerCase() : "";
    return runAction({
      action: "inject",
      node: actor(),
      scenario: scenario,
      source: sourceType,
      source_node: sourceNode,
      domain: customDomain,
      content: $("traffic-content") ? $("traffic-content").value : ""
    });
  }

  function setControlTab(name) {
    [
      ["traffic", "tab-btn-traffic", "pane-traffic"],
      ["chaos", "tab-btn-chaos", "pane-chaos"],
      ["scale", "tab-btn-scale", "pane-scale"]
    ].forEach(function (spec) {
      const active = spec[0] === name;
      const btn = $(spec[1]);
      const pane = $(spec[2]);
      if (btn) {
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-selected", active ? "true" : "false");
      }
      if (pane) pane.hidden = !active;
    });
  }

  function setDataTab(name) {
    [
      ["activity", "tab-btn-activity", "activity-view-container"],
      ["bans", "toggle-bans-btn", "bans-view-container"],
      ["reps", "toggle-reps-btn", "reps-view-container"]
    ].forEach(function (spec) {
      const active = spec[0] === name;
      const btn = $(spec[1]);
      const pane = $(spec[2]);
      if (btn) {
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-selected", active ? "true" : "false");
      }
      if (pane) pane.hidden = !active;
    });
    if ($("activity-filter-wrap")) $("activity-filter-wrap").hidden = name !== "activity";
    if (name === "bans") renderBans();
    if (name === "reps") renderNodesTable();
  }

  if ($("tab-btn-traffic")) $("tab-btn-traffic").addEventListener("click", function () { setControlTab("traffic"); });
  if ($("tab-btn-chaos")) $("tab-btn-chaos").addEventListener("click", function () { setControlTab("chaos"); });
  if ($("tab-btn-scale")) $("tab-btn-scale").addEventListener("click", function () { setControlTab("scale"); });

  if ($("toggle-custom-payload") && $("custom-payload-box")) {
    $("toggle-custom-payload").addEventListener("click", function () {
      const nextHidden = !$("custom-payload-box").hidden;
      $("custom-payload-box").hidden = nextHidden;
      $("toggle-custom-payload").textContent = nextHidden ? "+ Custom payload" : "− Custom payload";
      $("toggle-custom-payload").setAttribute("aria-expanded", nextHidden ? "false" : "true");
    });
  }

  if ($("control-node")) {
    $("control-node").addEventListener("change", function () {
      topologyKey = "";
      nodesKey = "";
      renderControls();
      renderTopology();
      renderNodesTable();
    });
  }
  if ($("chaos-node")) {
    $("chaos-node").addEventListener("change", function () {
      controlledChaosNode = "";
      renderControls();
      updateChaosRoleGuide($("fault-mode") ? $("fault-mode").value : "NONE", "selected");
    });
  }
  if ($("sync-chaos-node")) {
    $("sync-chaos-node").addEventListener("click", function () {
      if ($("chaos-node")) {
        $("chaos-node").value = actor();
        controlledChaosNode = "";
        renderControls();
        updateChaosRoleGuide($("fault-mode") ? $("fault-mode").value : "NONE", "selected");
      }
    });
  }
  if ($("traffic-source")) $("traffic-source").addEventListener("change", renderControls);

  document.querySelectorAll("[data-scenario]").forEach(function (button) {
    button.addEventListener("click", function () { traffic(button.dataset.scenario); });
  });
  if ($("send-custom")) $("send-custom").addEventListener("click", function () { traffic("custom"); });

  function healthyFollowerId(excludeId) {
    const nodes = data.nodes || [];
    const clean = nodes.find(function (n) {
      return n.online && n.node_id !== excludeId && !n.quarantined && !String(n.state).startsWith("BYZANTINE_");
    });
    if (clean) return clean.node_id;
    const anyOnline = nodes.find(function (n) { return n.online && n.node_id !== excludeId; });
    return anyOnline ? anyOnline.node_id : (excludeId === "fednode-0" ? "fednode-1" : "fednode-0");
  }

  function updateChaosRoleGuide(mode, phase) {
    const guide = $("chaos-role-guide");
    if (!guide) return;
    const leaderId = activeLeaderId();
    const followerId = healthyFollowerId(leaderId);
    const chaosId = chaosActor();

    if (mode === "CENSOR") {
      guide.hidden = false;
      if (phase === "applied") {
        guide.className = "alert alert-success py-1 px-2 small mb-0";
        guide.textContent = "Leader " + leaderId + " set to CENSOR. Inject an attack to Follower " +
          followerId + " to trigger 3s Censorship Impeachment.";
      } else {
        guide.className = "alert alert-warning py-1 px-2 small mb-0";
        guide.textContent = "CENSOR targets Leader " + leaderId + ". Simulator set to Follower " +
          followerId + ". Click Apply, then send an attack.";
      }
    } else if (mode === "EQUIVOCATOR") {
      guide.hidden = false;
      if (chaosId === leaderId) {
        guide.className = "alert alert-warning py-1 px-2 small mb-0";
        guide.textContent = "Tip: EQUIVOCATOR works on Followers during voting (target e.g. " + followerId + ").";
      } else {
        guide.className = "alert alert-info py-1 px-2 small mb-0";
        guide.textContent = "Follower " + chaosId + " will cast split APPROVE + REJECT ballots (-50 trust).";
      }
    } else if ((mode === "LIAR" || mode === "FORGER") && chaosId === leaderId) {
      guide.hidden = false;
      guide.className = "alert alert-warning py-1 px-2 small mb-0";
      guide.textContent = "Tip: " + mode + " is best demonstrated on a Follower (e.g. " + followerId + ").";
    } else {
      guide.hidden = true;
      guide.textContent = "";
    }
  }

  if ($("fault-mode")) {
    $("fault-mode").addEventListener("change", function () {
      const mode = $("fault-mode").value;
      const leaderId = activeLeaderId() || chaosActor();
      const followerId = healthyFollowerId(leaderId);
      if (mode === "CENSOR") {
        if ($("chaos-node")) {
          $("chaos-node").value = leaderId;
          controlledChaosNode = leaderId;
        }
        if ($("control-node")) {
          $("control-node").value = followerId;
          controlledNode = followerId;
        }
        topologyKey = "";
        nodesKey = "";
        renderControls();
        renderTopology();
        renderNodesTable();
      }
      updateChaosRoleGuide(mode, "selected");
    });
  }

  if ($("apply-settings")) {
    $("apply-settings").addEventListener("click", async function () {
      const fault = $("fault-mode") ? $("fault-mode").value : "NONE";
      const targetNode = fault === "CENSOR" ? (activeLeaderId() || chaosActor()) : chaosActor();
      if (fault === "CENSOR" && $("chaos-node")) {
        $("chaos-node").value = targetNode;
        controlledChaosNode = targetNode;
      }
      const ok = await runAction({action: "settings", node: targetNode, fault: fault});
      if (!ok) return;
      if (fault === "CENSOR") {
        const followerId = healthyFollowerId(targetNode);
        if ($("control-node")) {
          $("control-node").value = followerId;
          controlledNode = followerId;
          topologyKey = "";
          nodesKey = "";
          renderControls();
          renderTopology();
          renderNodesTable();
        }
        const msg = "Leader " + targetNode + " set to CENSOR. Inject an attack to Follower " +
          followerId + " to trigger 3s Censorship Impeachment.";
        if ($("action-result")) {
          $("action-result").className = "alert alert-success py-2 px-2 small mb-0";
          $("action-result").textContent = msg;
        }
        updateChaosRoleGuide("CENSOR", "applied");
      } else {
        updateChaosRoleGuide(fault, "applied");
      }
    });
  }
  ["stop", "revive"].forEach(function (action) {
    const btn = $(action + "-node");
    if (btn) btn.addEventListener("click", function () { runAction({action: action, node: chaosActor()}); });
  });
  if ($("reset-lab")) {
    $("reset-lab").addEventListener("click", function () { runAction({action: "reset_all"}); });
  }
  if ($("restore-peer")) {
    $("restore-peer").addEventListener("click", function () {
      if ($("trust-score")) $("trust-score").value = "100";
      runAction({action: "trust", node: "fednode-0", peer: chaosActor(), score: 100, scope: "all"});
    });
  }
  if ($("add-org-node")) {
    $("add-org-node").addEventListener("click", function () {
      const org = $("org-domain") ? $("org-domain").value.trim() : "";
      runAction({action: "add_org", org: org || "bluesky-bridge.social"});
    });
  }
  if ($("autoscale-up")) {
    $("autoscale-up").addEventListener("click", function () { runAction({action: "autoscale", delta: 2}); });
  }
  if ($("reset-scale")) {
    $("reset-scale").addEventListener("click", function () { runAction({action: "reset_scale"}); });
  }

  if ($("tab-btn-activity")) $("tab-btn-activity").addEventListener("click", function () { setDataTab("activity"); });
  if ($("toggle-bans-btn")) $("toggle-bans-btn").addEventListener("click", function () { setDataTab("bans"); });
  if ($("toggle-reps-btn")) $("toggle-reps-btn").addEventListener("click", function () { setDataTab("reps"); });

  if ($("refresh")) $("refresh").addEventListener("click", refresh);
  if ($("event-filter")) $("event-filter").addEventListener("change", renderEvents);
  if ($("ban-search")) $("ban-search").addEventListener("input", renderBans);
  if ($("close-dialog")) $("close-dialog").addEventListener("click", function () { $("node-dialog").close(); });
  if ($("node-dialog")) {
    $("node-dialog").addEventListener("click", function (event) { if (event.target === this) this.close(); });
  }

  refresh();
  setInterval(refresh, 1500);
})();
