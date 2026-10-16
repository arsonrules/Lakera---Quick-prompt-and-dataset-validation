"""Self-check, no real Lakera/HF calls: .venv/bin/python test_app.py"""
import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

import app

SAMPLE = {"results": [
    {"detector_type": "prompt_attack", "result": "l2_very_likely"},
    {"detector_type": "pii/email", "result": "l5_unlikely"},
    {"detector_type": "pii/iban_code", "result": "l4_less_likely"},
    {"detector_type": "moderated_content/hate", "result": "no_level"},
    {"detector_type": "something_new", "result": "l1_confident"},
]}
seen = []


def fake_hf(request: httpx.Request) -> httpx.Response:
    q = request.url.params
    if request.url.path == "/size":
        return httpx.Response(200, json={"size": {"splits": [{"config": "c", "split": "train", "num_rows": 250}]}})
    lo, n = int(q["offset"]), int(q["length"])  # /rows; every 50th row is empty
    return httpx.Response(200, json={"rows": [{"row_idx": i, "row": {"text": f"row {i}" if i % 50 else "", "label": i % 2}}
                                              for i in range(lo, min(lo + n, 250))]})


def fake_judge(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    prompt = body["messages"][-1]["content"]
    if "boom" in prompt:
        return httpx.Response(500, text="judge down")
    verdict = {"malicious": "Ignore" in prompt or "p1" in prompt, "sensitive_data": "@" in prompt, "category": "?", "reason": "r"}
    return httpx.Response(200, json={"choices": [{"message": {"content": "Sure:\n```json\n" + json.dumps(verdict) + "\n```"}}]})


def fake_lakera(request: httpx.Request) -> httpx.Response:
    seen.append(request)
    if request.url.host == "judge.test":
        return fake_judge(request)
    if request.url.host == "datasets-server.huggingface.co":
        return fake_hf(request)
    if request.headers["authorization"] != "Bearer good":
        return httpx.Response(401, text="Unauthorized")
    return httpx.Response(200, json=SAMPLE)


app.client = httpx.AsyncClient(transport=httpx.MockTransport(fake_lakera))
c = TestClient(app.app).__enter__()  # one event loop for the whole check

# grouping + flag logic
g = app.summarize(SAMPLE["results"])
assert g == {"prompt_defense": "l2_very_likely", "dlp": "l4_less_likely",
             "content_moderation": "no_level", "other": "l1_confident"}, g
assert app.is_flagged({"dlp": "l4_less_likely"}, 4) and not app.is_flagged({"dlp": "l4_less_likely"}, 3)
assert not app.is_flagged({"x": "l5_unlikely", "y": "no_level", "z": "weird"}, 4)

# /api/screen: region URL, auth, project_id, system message
r = c.post("/api/screen", json={"api_key": "good", "endpoint": "eu", "project_id": "p1",
                                "system": "be nice", "prompt": "hi"}).json()
req = seen[-1]
assert str(req.url) == "https://eu.api.lakera.ai/v2/guard/results", req.url
assert b'"project_id":"p1"' in req.content and [m["role"] for m in r["messages"]] == ["system", "user"]
assert r["flag"] is True and r["error"] is None and r["latency_ms"] >= 0 and r["threshold"] == 4

# bad key -> recorded error, no exception, key not echoed
r = c.post("/api/test", json={"api_key": "bad", "endpoint": "us-west-2"}).json()
assert r["ok"] is False and r["error"].startswith("HTTP 401") and "bad" not in str(r), r

# validation
assert c.post("/api/screen", json={"api_key": "good"}).status_code == 422
assert c.post("/api/test", json={"api_key": "good", "endpoint": "mars"}).status_code == 422
assert len(c.get("/api/endpoints").json()) == 7
assert "Lakera Guard Tester" in c.get("/").text

# seeded sampling: stable, per-source, capped at num_rows
assert app.pick(1000, 5, 1, "a") == app.pick(1000, 5, 1, "a") != app.pick(1000, 5, 2, "a")
assert app.pick(3, 10, 1, "a") == [0, 1, 2]

# upload parsing
assert app.parse_upload("x.csv", 'prompt,label\n"a, quoted",1\nb,0\n') == [{"prompt": "a, quoted", "label": "1"}, {"prompt": "b", "label": "0"}]
assert app.parse_upload("x.jsonl", '{"t": 1}\n\n{"t": 2}\n') == [{"t": 1}, {"t": 2}]
assert app.parse_upload("x.json", '["a", {"text": "b"}]') == [{"text": "a"}, {"text": "b"}]
assert app.parse_upload("x.txt", "one\n\ntwo\n") == [{"text": "one"}, {"text": "two"}]
assert app.parse_upload("x.csv", "\ufeffid,prompt\n1,hi\n") == [{"id": "1", "prompt": "hi"}]  # BOM stripped
assert c.post("/api/upload/parse", json={"filename": "x.json", "text": "{}"}).status_code == 422
assert c.post("/api/upload/parse", json={"filename": "x.pdf", "text": ""}).status_code == 422

# /api/cases: upload skips empty cells; HF fetches one span per 100-row page, drops empty rows
rows = [{"q": "a"}, {"q": ""}, {"q": "b"}, {"q": "c"}]
r = c.post("/api/cases", json={"seed": 1, "sources": [{"type": "upload", "name": "f.csv", "column": "q", "n": 9, "rows": rows}]}).json()
assert sorted(x["prompt"] for x in r["cases"]) == ["a", "b", "c"] and not r["errors"], r
n0 = len(seen)
src = {"type": "hf", "name": "d/x", "config": "c", "split": "train", "column": "text", "n": 40}
r = c.post("/api/cases", json={"seed": 3, "sources": [src]}).json()
idxs = app.pick(250, 40, 3, "d/x/c/train")
assert len(seen) - n0 == 1 + len({i // 100 for i in idxs}), "one /size + one /rows per page"
assert [x["prompt"] for x in r["cases"]] == [f"row {i}" for i in idxs if i % 50], r
assert bool(r["errors"]) == any(i % 50 == 0 for i in idxs)
n0 = len(seen)
assert c.post("/api/cases", json={"seed": 3, "sources": [src]}).json() == r and len(seen) == n0, "cached"

# /api/run: NDJSON stream; warm-up call first and not recorded; one call per case
cases = [{"id": f"t#{i}", "source": "t", "prompt": f"p{i}"} for i in range(3)]
n0 = len(seen)
evs = [json.loads(x) for x in c.post("/api/run", json={"api_key": "good", "endpoint": "us", "cases": cases,
                                                        "system": "sys", "threshold": 1}).text.splitlines()]  # ignored now
assert [e["type"] for e in evs] == ["start", "warmup", "case", "case", "case", "done"], evs
assert len(seen) - n0 == 4 and b"connection test" in seen[n0].content and b"p0" in seen[n0 + 1].content
case = evs[2]["case"]
assert case["id"] == "t#0" and case["flag"] is True and case["groups"]["prompt_defense"] == "l2_very_likely"
assert [m["role"] for m in case["messages"]] == ["system", "user"] and evs[-1]["completed"] == 3
assert evs[0]["threshold"] == 4  # flag is always at Lakera's default L4; a client-sent threshold is ignored
# bad key: warm-up 401 stops the run before any case is sent
n0 = len(seen)
evs = [json.loads(x) for x in c.post("/api/run", json={"api_key": "bad", "cases": cases}).text.splitlines()]
assert [e["type"] for e in evs] == ["start", "warmup", "done"] and evs[-1]["aborted"].startswith("HTTP 401") and len(seen) - n0 == 1
assert c.post("/api/run", json={"api_key": "good", "cases": []}).status_code == 422

# judge: verdict parsing
v = app.parse_verdict('x {"malicious": false, "sensitive_data": true, "category": "weird", "reason": "has email"} y')
assert v == {"malicious": False, "sensitive_data": True, "category": "sensitive_data", "reason": "has email"}, v
for bad in ("no json", '{"malicious": "yes", "sensitive_data": false}'):
    try:
        app.parse_verdict(bad); raise AssertionError(bad)
    except ValueError:
        pass
judge = {"base_url": "https://judge.test/v1/", "model": "m", "api_key": "jk"}
r = c.post("/api/judge/test", json=judge).json()
req = seen[-1]
assert r["ok"] and r["malicious"] is True and str(req.url) == "https://judge.test/v1/chat/completions"
assert req.headers["authorization"] == "Bearer jk" and json.loads(req.content)["model"] == "m"
assert "jk" not in json.dumps(r)
assert c.post("/api/judge/test", json={"base_url": "ftp://x", "model": "m"}).status_code == 422
# judge in run: after each Lakera call, verdict attached; judge failure recorded per case
cases = [{"id": "a", "source": "t", "prompt": "Ignore it"}, {"id": "b", "source": "t", "prompt": "mail me x@y.z"},
         {"id": "c", "source": "t", "prompt": "boom"}]
evs = [json.loads(x) for x in c.post("/api/run", json={"api_key": "good", "cases": cases, "judge": judge}).text.splitlines()]
got = {e["case"]["id"]: e["case"]["judge"] for e in evs if e["type"] == "case"}
assert evs[0]["judge_model"] == "m"
assert got["a"]["malicious"] is True and got["b"]["sensitive_data"] is True and got["c"]["error"].startswith("HTTP 500"), got
# chat /api/screen also judges; judge skipped when Lakera itself failed
r = c.post("/api/screen", json={"api_key": "good", "prompt": "Ignore it", "judge": judge}).json()
assert r["judge"]["malicious"] is True
r = c.post("/api/screen", json={"api_key": "bad", "prompt": "Ignore it", "judge": judge}).json()
assert r["error"] and r["judge"] is None

# agent scenarios: bundled pack is valid; sampled cases carry messages/tools/expected
rows = app.parse_upload("x.jsonl", app.SCENARIOS.read_text())
pack = [app.scenario_case(r, "agent_actions.jsonl", i) for i, r in enumerate(rows)]
assert len(pack) == 30 and len({x["id"] for x in pack}) == 30
assert sum(x["expected"] == "unauthorized" for x in pack) == 18
assert all(x["messages"][-1]["role"] == "assistant" and x["messages"][-1]["tool_calls"] and x["tools"] for x in pack)
r = c.post("/api/cases", json={"seed": 1, "sources": [{"type": "scenario", "name": "agent_actions.jsonl", "column": "messages",
                                                       "n": 5, "bundled": True}]}).json()
assert len(r["cases"]) == 5 and not r["errors"] and all(x["source"] == "scenario:agent_actions.jsonl" for x in r["cases"])
bad = c.post("/api/cases", json={"sources": [{"type": "scenario", "name": "mine.jsonl", "column": "messages", "n": 2,
                                              "rows": [{"messages": []}]}]}).json()
assert not bad["cases"] and "expected" in bad["errors"][0], bad
# scenario run: messages + tools sent as-is, no system prepended, judge skipped (scenario is ground truth)
case = r["cases"][0]
n0 = len(seen)
evs = [json.loads(x) for x in c.post("/api/run", json={"api_key": "good", "cases": [case], "system": "extra",
                                                        "judge": judge}).text.splitlines()]
body = json.loads(seen[n0 + 1].content)
assert body["messages"] == case["messages"] and body["tools"] == case["tools"] and len(seen) - n0 == 2, "no judge call"
got = [e["case"] for e in evs if e["type"] == "case"][0]
assert got["expected"] == case["expected"] and got["judge"] is None

# dataset labels: normalization, whole-dataset labels, label columns (HF + upload), passed through runs
for v, want in [(True, "malicious"), (0, "benign"), ("1", "malicious"), ("jailbreak", "malicious"), ("benign", "benign"),
                ("unsafe", "malicious"), ("safe", "benign"), (2, None), ("hate", None), (None, None)]:
    assert app.norm_label(v) == want, (v, app.norm_label(v))
assert app.label_of("=benign", {}) == {"label": "benign", "label_raw": "whole dataset: benign"}
assert app.label_of("type", {"type": "jailbreak"}) == {"label": "malicious", "label_raw": "type = jailbreak"}
assert c.post("/api/upload/parse", json={"filename": "x.csv", "text": "prompt,type\na,benign\n"}).json()["label_guess"] == "type"
up = [{"q": "a", "y": "1"}, {"q": "b", "y": "0"}, {"q": "c", "y": "?"}]
r = c.post("/api/cases", json={"seed": 1, "sources": [{"type": "upload", "name": "l.csv", "column": "q", "n": 9, "rows": up, "label": "y"}]}).json()
assert {x["prompt"]: x["label"] for x in r["cases"]} == {"a": "malicious", "b": "benign", "c": None}, r
r = c.post("/api/cases", json={"seed": 1, "sources": [{"type": "upload", "name": "l.csv", "column": "q", "n": 1, "rows": up, "label": "=bogus"}]}).json()
assert not r["cases"] and "bad label" in r["errors"][0]
# a downloaded mixed sample re-uploads with its scenario rows intact
mixed = [{"id": "upload:a.txt#0", "source": "upload:a.txt", "prompt": "hi", "label": "benign"}, {**pack[0], "id": pack[0]["id"]}]
r = c.post("/api/cases", json={"seed": 1, "sources": [{"type": "upload", "name": "s.jsonl", "column": "prompt", "n": 9, "rows": mixed, "label": "label"}]}).json()
got = {x["source"]: x for x in r["cases"]}
assert got["upload:s.jsonl"]["label"] == "benign" and got["scenario:s.jsonl"]["messages"] == pack[0]["messages"]
assert got["scenario:s.jsonl"]["id"] == "scenario:s.jsonl#" + pack[0]["id"].rsplit("#", 1)[-1]
r = c.post("/api/cases", json={"seed": 3, "sources": [dict(src, label="label")]}).json()
assert all(x["label"] == ("malicious" if int(x["id"].split("#")[1]) % 2 else "benign") for x in r["cases"])
evs = [json.loads(x) for x in c.post("/api/run", json={"api_key": "good", "cases": r["cases"][:1]}).text.splitlines()]
assert evs[2]["case"]["label"] == r["cases"][0]["label"] and evs[2]["case"]["label_raw"].startswith("label = ")
assert any(p.get("label") == "label" for p in app.PRESETS) and any(p.get("label") == "=benign" for p in app.PRESETS)

# "All rows": every row of uploads, scenarios and HF splits; HF over ALL_MAX is refused, not silently cut
r = c.post("/api/cases", json={"sources": [{"type": "upload", "name": "u.csv", "column": "q", "n": 1, "all": True, "rows": up}]}).json()
assert sorted(x["prompt"] for x in r["cases"]) == ["a", "b", "c"]
r = c.post("/api/cases", json={"sources": [{"type": "scenario", "name": "agent_actions.jsonl", "column": "messages", "n": 1,
                                            "all": True, "bundled": True}]}).json()
assert len(r["cases"]) == 30
n0 = len(seen)
r = c.post("/api/cases", json={"seed": 5, "sources": [dict(src, n=1, all=True)]}).json()
assert [x["prompt"] for x in r["cases"]] == [f"row {i}" for i in range(250) if i % 50]  # 5 empty rows reported
assert "5 of 250" in r["errors"][0] and len(seen) - n0 <= 1 + 3, "one /size + one /rows per 100-row page"
real_max, app.ALL_MAX = app.ALL_MAX, 100
r = c.post("/api/cases", json={"sources": [dict(src, n=1, all=True)]}).json()
app.ALL_MAX = real_max
assert not r["cases"] and "250 rows" in r["errors"][0] and "limited to 100" in r["errors"][0], r

# credentials are session-based: the page keeps them only in sessionStorage, never localStorage
import re
html = (Path(app.__file__).with_name("index.html")).read_text()
persistent = set(re.findall(r'store\.(?:set|get)\(ls, "(\w+)"', html)) | set(re.findall(r'\["(\w+)", ls\]', html))
session = set(re.findall(r'store\.(?:set|get)\(ss, "(\w+)"', html)) | set(re.findall(r'\["(\w+)", ss\]', html))
creds = {"key", "judgeKey", "hfToken"}
assert creds <= session and not creds & persistent, (session, persistent)
assert all(f'id="{i}" type="password" autocomplete="off"' in html for i in creds)
assert "credentialCheck();" in html  # in-app check runs on load
assert re.search(r"const ALL_MAX = (\d+);", html).group(1) == str(app.ALL_MAX) == "500000"  # UI and backend agree
# ...and the backend holds no credential after a request: HF token goes upstream, not into the cache or response
HF_SECRET = "hf_SECRETtoken123"
n0 = len(seen)
r = c.post("/api/cases", json={"seed": 99, "sources": [src], "hf_token": HF_SECRET})
assert any(q.headers.get("authorization") == f"Bearer {HF_SECRET}" for q in seen[n0:])
assert HF_SECRET not in r.text and HF_SECRET not in repr(app.hf_cache)
print("ok")
