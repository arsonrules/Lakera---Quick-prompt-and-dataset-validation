// Hand-computed metrics check: node test_report.js
const assert = require("assert");
const { metrics } = require("./report.js");

const rec = (id, source, groups, latency_ms, error = null) => ({ id, source, prompt: id, groups, latency_ms, error });
const R = [
  rec("r1", "hf:A", { prompt_defense: "l1_confident", dlp: "l5_unlikely" }, 100),
  rec("r2", "hf:A", { prompt_defense: "l3_likely", dlp: "no_level" }, 200),
  rec("r3", "upload:B", { prompt_defense: "l5_unlikely", dlp: "l4_less_likely" }, 300),
  rec("r4", "upload:B", { prompt_defense: "no_level", dlp: "no_level" }, 400),
  rec("r5", "upload:B", {}, 50, "HTTP 429: Too Many Requests"),
];

const m4 = metrics(R, 4);
assert.equal(m4.total, 5); assert.equal(m4.ok, 4); assert.equal(m4.errors.length, 1);
assert.equal(m4.flagged, 3); assert.equal(m4.detectionRate, 0.75);
assert.deepEqual(m4.bypass.map(r => r.id), ["r4"]);
assert.deepEqual(m4.groups, ["prompt_defense", "dlp"]);
assert.deepEqual(m4.byGroup.map(g => [g.key, g.n, g.of]), [["prompt_defense", 2, 4], ["dlp", 1, 4]]);
assert.deepEqual(m4.bySource.map(s => [s.label, s.n, s.of, s.errors]), [["A", 2, 2, 0], ["B", 1, 2, 1]]);
assert.equal(m4.latency.avg, 250); assert.equal(m4.latency.max, 400); assert.equal(m4.latency.maxRec.id, "r4"); // error's 50 ms excluded

const m2 = metrics(R, 2);
assert.equal(m2.flagged, 1); assert.equal(m2.detectionRate, 0.25);
assert.deepEqual(m2.bypass.map(r => r.id), ["r2", "r3", "r4"]); // closest to the threshold first


const empty = metrics([rec("e", "x", {}, 0, "boom")], 4);
assert.equal(empty.detectionRate, null); assert.equal(empty.latency.avg, null);
// Judge metrics (expected flag = malicious || sensitive_data)
const J = (malicious, sensitive_data) => ({ malicious, sensitive_data, category: "x", reason: "" });
const rj = (id, groups, judge) => ({ ...rec(id, "hf:Q", groups, 10), judge });
const Q = [
  rj("q1", { prompt_defense: "l1_confident" }, J(true, false)),   // flagged, malicious -> tp
  rj("q2", { prompt_defense: "l2_very_likely" }, J(false, false)), // flagged, benign -> fp (tn at L1)
  rj("q3", { dlp: "l4_less_likely" }, J(false, true)),          // flagged by DLP, sensitive -> tp (fn+leaked at L1)
  rj("q4", { prompt_defense: "no_level" }, J(true, false)),       // missed attack -> fn
  rj("q5", {}, J(false, false)),                                   // tn
  rj("q6", {}, { error: "HTTP 500" }),                             // judge error: excluded
  rj("q7", { dlp: "l5_unlikely" }, J(false, true)),               // sensitive, not caught -> fn + leaked
  rj("q8", { prompt_defense: "l1_confident" }, null),             // not judged
];
const j4 = metrics(Q, 4).judge;
assert.equal(j4.n, 6); assert.equal(j4.errors, 1); assert.equal(j4.unjudged, 1);
assert.deepEqual(j4.confusion, { tp: 2, fp: 1, fn: 2, tn: 1 });
assert.equal(j4.attacks, 2); assert.equal(j4.asr, 0.5); assert.equal(j4.recall, 0.5);
assert.equal(j4.precision, 2 / 3); assert.equal(j4.fpr, 0.5);
assert.deepEqual(j4.missed.map(r => r.id), ["q4"]); assert.deepEqual(j4.leaked.map(r => r.id), ["q7"]); assert.equal(j4.leakage, 0.5);
const j1 = metrics(Q, 1).judge;
assert.deepEqual(j1.confusion, { tp: 1, fp: 0, fn: 3, tn: 2 }); assert.equal(j1.leakage, 1); assert.equal(j1.fpr, 0);
assert.equal(metrics(R, 4).judge, null); // no judge -> tiles stay locked

// Agent scenarios: Unauthorized Action Success Rate = unauthorized & not flagged / unauthorized
const ra = (id, groups, expected, danger) => ({ ...rec(id, "scenario:pack", groups, 10), expected, danger });
const AG = [
  ra("a1", { agent_behavior: "l1_confident" }, "unauthorized", "data_leakage"),  // blocked
  ra("a2", { agent_behavior: "no_level" }, "unauthorized", "data_leakage"),      // got through
  ra("a3", {}, "unauthorized", "system_destruction"),                            // got through
  ra("a4", { prompt_defense: "l3_likely" }, "allowed", null),                     // legit call blocked at L4, not at L2
  ra("a5", { agent_behavior: "l5_unlikely" }, "allowed", null),                   // legit call passes
];
const a4 = metrics(AG, 4).agent;
assert.equal(a4.unauthorized, 3); assert.equal(a4.allowed, 2); assert.equal(a4.agentSeen, true);
assert.deepEqual(a4.through.map(r => r.id), ["a2", "a3"]); assert.equal(a4.uasr, 2 / 3);
assert.deepEqual(a4.blocked.map(r => r.id), ["a4"]); assert.equal(a4.falseBlock, 0.5);
assert.deepEqual(a4.byDanger.map(d => [d.key, d.n, d.of]), [["data_leakage", 1, 2], ["system_destruction", 1, 1]]);
assert.equal(metrics(AG, 2).agent.falseBlock, 0);
assert.equal(metrics(AG.filter(r => r.id === "a3"), 4).agent.agentSeen, false);
assert.equal(metrics(R, 4).agent, null);

// Dataset labels vs Lakera (+ judge agreement)
const rl = (id, groups, label, judge, label_raw) => ({ ...rec(id, "hf:L", groups, 10), label, label_raw, judge });
const LBR = [
  rl("b1", { prompt_defense: "l1_confident" }, "malicious", J(true, false)), // caught; judge agrees
  rl("b2", { prompt_defense: "no_level" }, "malicious", J(false, false)),    // missed; judge disagrees
  rl("b3", { dlp: "l2_very_likely" }, "benign", null),                       // false flag
  rl("b4", {}, "benign", J(false, false)),                                   // passed; judge agrees
  rl("b5", {}, null, null, "category = hate"),                               // label value not malicious/benign
  rl("b6", {}, undefined, null),                                             // no label
];
const lb = metrics(LBR, 4).labels;
assert.equal(lb.n, 4); assert.equal(lb.malicious, 2); assert.equal(lb.benign, 2); assert.equal(lb.unknown, 1);
assert.deepEqual(lb.confusion, { tp: 1, fn: 1, fp: 1, tn: 1 }); assert.equal(lb.recall, 0.5); assert.equal(lb.fpr, 0.5);
assert.deepEqual(lb.missed.map(r => r.id), ["b2"]); assert.deepEqual(lb.falseFlags.map(r => r.id), ["b3"]);
assert.equal(lb.judged, 3); assert.equal(lb.judgeAgree, 2);
assert.equal(metrics(LBR, 1).labels.confusion.fp, 0); // b3's L2 result isn't flagged with an L1 cut-off
assert.equal(metrics(R, 4).labels, null);

// Export: only report fields, secrets redacted, "</script>" can't break out, no network references
const { exportData, toExportHtml } = require("./report.js");
const fs = require("fs");
const SECRET = "sk-test-1234567890";
const run = {
  meta: { endpoint: "eu", url: "https://eu.api.lakera.ai/v2/guard", threshold: 4, judge_model: "m", api_key: SECRET, judge: { api_key: SECRET } },
  warmup: { latency_ms: 300, error: null }, done: { completed: 2, errors: 0, elapsed_s: 1 },
  records: [
    { ...Q[0], prompt: "</script><script>alert(1)</script>", extra: "drop me" },
    { ...Q[5], judge: { error: `HTTP 401: bad key ${SECRET}` } },
  ],
};
const json = exportData(run, [SECRET, "", "short"]);
assert(!json.includes(SECRET) && json.includes("[redacted]"));
const back = JSON.parse(json);
assert.deepEqual(Object.keys(back.meta).sort(), ["endpoint", "judge_model", "threshold", "url"]);
assert.equal(back.records[0].extra, undefined); assert.equal(back.records[0].prompt, "</script><script>alert(1)</script>");
const src = fs.readFileSync(__dirname + "/report.js", "utf8");
const html = toExportHtml(json, src);
const dataTag = html.match(/<script type="application\/json" id="run-data">([\s\S]*?)<\/script>/)[1];
assert.deepEqual(JSON.parse(dataTag), back);                     // round-trips, prompt's </script> stayed escaped
assert.equal(html.match(/<\/script>/g).length, 3);               // exactly our three tags close
assert(!/<(script|link|img)[^>]+(src|href)=/i.test(html));        // nothing loaded from the network
if (process.argv[2]) fs.writeFileSync(process.argv[2], html);    // optional: write sample for a browser check
console.log("ok");
