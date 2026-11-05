/* Explicit illustrative playback; never submitted to a real node. */
window.demoSnapshot = function (elapsed) {
  const now = Date.now();
  const base = now - elapsed;
  const domain = "malware-relay.example";
  const proposalId = "demo-proposal-001";
  const completed = elapsed >= 12000;
  const ids = Array.from({length: 5}, function (_, i) { return "fednode-" + i; });
  const approvals = elapsed < 3000 ? [] : elapsed < 5500 ? [ids[0]] :
    elapsed < 8000 ? [ids[0], ids[1]] : elapsed < 10500 ? [ids[0], ids[1], ids[2]] :
    [ids[0], ids[1], ids[2], ids[3]];
  const proposal = {
    proposal_id: proposalId, domain: domain, reason: 4, epoch: 3, sequence: 12,
    created_at: base + 3000, committed: completed, approvals: approvals,
    quorum: 4, observer: ids[0]
  };
  const nodes = ids.map(function (id, i) {
    return {
      node_id: id, address: "http://" + id + ":8080", online: i !== 4,
      telemetry_available: i !== 4, state: i === 0 ? "LEADER" : i === 4 ? "OFFLINE" : "FOLLOWER",
      epoch: 3, quorum: 4, last_sequence: completed && i !== 4 ? 12 : 11,
      operational_mode: "AUTOMATIC", last_seen: i === 4 ? base - 60000 : now,
      blocked_domains: i === 4 ? ["spam-hub.example"] :
        completed ? ["spam-hub.example", domain] : ["spam-hub.example"],
      reputations: [{peer_id: ids[4], trust_score: 60, is_active: true, violations_count: 1}],
      proposals: i === 0 && elapsed >= 3000 ? [proposal] : [], events: []
    };
  });
  function event(ms, kind, source, target, message, fields) {
    return Object.assign({
      id: "demo-" + ms, timestamp: base + ms, kind: kind, source: source,
      target: target, message: message, observer: ids[0]
    }, fields);
  }
  const related = {proposal_id: proposalId, domain: domain};
  const events = [
    event(500, "message", "community.example", ids[2], "Hello from the community. Post accepted."),
    event(2200, "threat", domain, ids[0], "Suspicious attachment: security-update.exe. Threat score 0.85.",
      {domain: domain, score: 0.85}),
    event(3000, "proposal", ids[0], ids[1], "Proposed blocking malware-relay.example", related),
    event(5500, "vote", ids[1], ids[0], "Signed approval received", Object.assign({decision: "APPROVE"}, related)),
    event(8000, "vote", ids[2], ids[0], "Signed approval received", Object.assign({decision: "APPROVE"}, related)),
    event(10500, "vote", ids[3], ids[0], "Fourth approval received; threshold reached", Object.assign({decision: "APPROVE"}, related)),
    event(12000, "commit", ids[0], "firewall", "Block reported applied on all four active nodes", related),
    event(14000, "blocked", domain, ids[1], "Repeat post rejected by the domain blocklist", {domain: domain}),
  ].filter(function (item) { return item.timestamp <= now; });
  return {
    nodes: nodes, events: events, updated_at: now,
    bans: [
      {domain: "spam-hub.example", applied_on: ids.slice(0, 4), last_known_on: [ids[4]]}
    ].concat(completed ? [{domain: domain, applied_on: ids.slice(0, 4), last_known_on: []}] : [])
  };
};
