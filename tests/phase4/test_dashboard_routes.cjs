const assert = require("node:assert/strict");
const {networkRoute, rememberSender} = require("../../dashboard/static/app.js");
const positions = [
  {node: {node_id: "fednode-0", address: "http://localhost:8080"}, x: 65, y: 11},
  {node: {node_id: "fednode-1", address: "http://localhost:8081"}, x: 88, y: 37}
];
assert.equal(networkRoute(null, positions), null);
for (const kind of ["message", "threat", "blocked"]) {
  const route = networkRoute({source: "test-attacker.example", target: "fednode-0", kind}, positions);
  assert.equal(route.source.kind, "external");
  assert.equal(route.source.label, "test-attacker.example");
  assert.equal(route.source.x, 26); // The visible sender card's right edge.
  assert.equal(route.target.label, "fednode-0");
  assert.equal(route.target.x, 65);
  assert.equal(route.attack, kind !== "message");
}
const vote = networkRoute({source: "fednode-1", target: "fednode-0", kind: "vote"}, positions);
assert.equal(vote.source.kind, "node");
assert.equal(vote.source.x, 88);
assert.equal(vote.target.x, 65);
const local = networkRoute({source: "http://localhost:8081", target: "localhost:8080", kind: "proposal"}, positions);
assert.equal(local.source.label, "fednode-1");
assert.equal(local.target.label, "fednode-0");
const peer = networkRoute({source: "fednode-0", target: "fednode-1:50051", kind: "proposal"}, positions);
assert.equal(peer.target.label, "fednode-1");
const unknown = networkRoute({source: "unmapped-peer:50051", target: "localhost:50051", kind: "invalid"}, positions);
assert.equal(unknown.source.kind, "endpoint");
assert.equal(unknown.source.label, "unmapped-peer:50051");
assert.equal(unknown.target.label, "localhost:50051");
assert.equal(unknown.target.kind, "service"); // Not incorrectly assigned to the first localhost node.
const commit = networkRoute({source: "fednode-0", target: "firewall", kind: "commit"}, positions);
assert.equal(commit.target.label, "firewall");
assert.equal(commit.target.kind, "service");
console.log("Dashboard routes: labelled external senders, node identities, endpoint matching, and destinations passed.");
const externalEvent = {source: "community.example", target: "fednode-0", kind: "message"};
const attackEvent = {source: "malware.example", target: "fednode-0", kind: "threat"};
const voteEvent = {source: "fednode-1", target: "fednode-0", kind: "vote"};
const commitEvent = {source: "fednode-0", target: "firewall", kind: "commit"};
assert.equal(rememberSender([], positions), null);
let sender = rememberSender([externalEvent], positions);
assert.equal(sender.source.label, "community.example");
assert.equal(sender.attack, false);
sender = rememberSender([externalEvent, attackEvent, voteEvent], positions, sender);
assert.equal(sender.source.label, "malware.example");
assert.equal(sender.attack, true);
sender = rememberSender([voteEvent, commitEvent], positions, sender);
assert.equal(sender.source.label, "malware.example");
assert.equal(rememberSender([], positions, sender), sender);
assert.equal(rememberSender([], positions, null), null);
console.log("Persistent sender: idle, incoming traffic, voting, commit, and expired-history checks passed.");
