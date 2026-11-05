const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const context = {window: {}, Date};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../../dashboard/static/demo.js"), "utf8"), context);
const snapshot = context.window.demoSnapshot;
for (const elapsed of [0, 4000, 6000, 9000, 11000, 15000]) {
  const data = snapshot(elapsed);
  assert.equal(data.nodes.length, 5);
  assert.equal(data.nodes.filter(n => n.online).length, 4);
  assert.equal(new Set(data.events.map(e => e.id)).size, data.events.length);
  assert.ok(data.events.every(e => e.timestamp <= data.updated_at));
  const proposals = data.nodes.flatMap(n => n.proposals);
  if (elapsed < 3000) assert.equal(proposals.length, 0);
  else {
    assert.equal(new Set(proposals[0].approvals).size, proposals[0].approvals.length);
    assert.ok(!proposals[0].approvals.includes("fednode-4"));
    assert.equal(proposals[0].committed, elapsed >= 12000);
  }
  assert.equal(data.bans.length, elapsed >= 12000 ? 2 : 1);
}
console.log("Dashboard demo: timing, distinct votes, inactive node, and commit checks passed.");
