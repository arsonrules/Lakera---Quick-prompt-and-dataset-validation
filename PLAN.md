# Lakera Guard Testing Web UI — Build Plan

_Researched 2026-10-15 against docs.lakera.ai (now branded "Check Point AI Guardrails"). Revision 2: includes your decisions on the 10 gap points (section 2)._

## 1. What Lakera Guard can do

| Detector group | What it detects | `detector_type` prefix |
|---|---|---|
| Prompt Defense | Direct and indirect prompt injection and jailbreaks, in 100+ languages | `prompt_attack` |
| Content Moderation | Crime, Hate, Profanity, Sexual, Violence, Weapons, Self Harm | `moderated_content/*` |
| Data Leakage Prevention (DLP) | 8 built-in PII types: name, US address, US phone, email, IP, credit card, IBAN, US SSN. Custom regex, custom guardrails and system-prompt leak detection are set in the policy. | `pii/*`, custom |
| Malicious Links | Unknown or untrusted domains | `unknown_links` |
| Agent Behavior Defense | Dangerous Deviation (beta), Tool Allow/Deny List | `dangerous_deviation`, … |

**The only API we call: `POST {base}/v2/guard/results`**
- **Request:** `messages` (OpenAI chat format) plus optional `project_id`. Auth is `Authorization: Bearer <key>`.
- **Response:** `results[]` with `detector_type`, `detector_id`, `policy_id`, `project_id`, `message_id`, `custom_matched`, and `result`.
- **`result` values:** `l1_confident`, `l2_very_likely`, `l3_likely`, `l4_less_likely`, `l5_unlikely`, `no_level`.
- **No flagging decision.** The response has no yes/no; we work it out ourselves (section 3).
- **Not logged** in the Lakera dashboard.
- **Default policy:** without a `project_id`, Lakera runs Prompt, Content Moderation, PII and Links detection at L4.

**Endpoints.** All 7 return `401` on `/v2/guard/results` without a key, so they exist. The base URL is the endpoint URL minus `/v2/guard`.

| Key | Label | URL |
|---|---|---|
| community | Community | `https://api.lakera.ai/v2/guard` |
| us | US (multi-region) | `https://us.api.lakera.ai/v2/guard` |
| us-east-1 | US East (N. Virginia) | `https://us-east-1.api.lakera.ai/v2/guard` |
| us-west-2 | US West (Oregon) | `https://us-west-2.api.lakera.ai/v2/guard` |
| eu-west-1 | EU (Ireland) | `https://eu-west-1.api.lakera.ai/v2/guard` |
| eu | EU | `https://eu.api.lakera.ai/v2/guard` |
| ap-southeast-1 | Asia (Singapore) | `https://ap-southeast-1.api.lakera.ai/v2/guard` |

Three hosts are not in Lakera's region docs: us-east-1, us-west-2 and eu-west-1. A key only works in the regions its organization allows; other regions return 4xx. Settings includes a **Test connection** button.

## 2. Decisions on the gap points

| # | Gap | Decision |
|---|---|---|
| 1 | Browser can't call Lakera directly (no CORS) | A backend service makes every API call. The browser only talks to it. |
| 2 | Endpoint list | All 6 listed endpoints plus `eu.api.lakera.ai` (table above). |
| 3 | Attack Success Rate | Flagged cases (`flag=true`) count as detections. Unflagged cases (`flag=false`) are recorded as bypass candidates. **Without a judge model:** only Detection Rate is shown. **With a judge:** the judge gives a malicious/benign verdict and ASR is computed (section 4). |
| 4 | Recall, Precision, False Positive Rate (FPR) | Shown **only when a judge model is configured**. Otherwise these tiles read "Add a judge model to enable". |
| 5 | Sensitive Data Leakage Rate | Marked as a **⚙ DLP customization item**. Built-in detection covers 8 mostly-US PII types. Other data needs custom regex or custom guardrails in a Lakera project policy, passed in through the optional `project_id`. The report shows a coverage note with a link to the DLP docs. |
| 6 | Unauthorized Action Success Rate | **Optional** module, off by default. It needs a `project_id` whose policy has Dangerous Deviation or a Tool Allow/Deny List, plus the bundled agent scenario pack or the user's own tool-call scenarios. |
| 7 | Latency | The report shows **average round-trip time (RTT)** and **maximum latency** (with a link to the slowest case), plus a latency histogram. The timer runs in the backend around each Lakera call. |
| 8 | Rate limits and quotas | Rate-limit handling is **off**: no throttling, retry or quota warnings. Calls run **one at a time**. A `429` or any other error is recorded on that case and the run continues. Running one at a time also keeps each latency reading clean. |
| 9 | Detector names | Results are **grouped** by prefix into Prompt Defense, Content Moderation, DLP, Malicious Links, Agent Behavior, and Other for unknown prefixes. Charts and tables are split by group, with each detector listed under its group. |
| 10 | Dashboard and `/guard` | **Only `/v2/guard/results`** is called. We read its confidence levels and never call `/guard`. |

## 3. How the backend works out "flag" from confidence levels

`/results` returns a level, not a yes/no, so the backend works out the flag:

```
flag(case, Lk) = any detector result in [l1 .. lk]      (default threshold: L4, same as Lakera's default policy)
```

- The report has a **threshold selector (L1–L4)**. Changing it recomputes every metric from the stored levels, with no new API calls.
- A threshold-sweep chart shows detection rate (and, with a judge, precision, recall and FPR) at L1, L2, L3 and L4.
- `l5_unlikely` and `no_level` never count as flagged.

## 4. Metrics

| Metric | Without judge | With judge |
|---|---|---|
| **Detection Rate** | flagged ÷ total, per dataset and per detector group | same |
| **Attack Success Rate** | not shown (unflagged cases are listed as bypass candidates) | malicious & `flag=false` ÷ all judge-malicious |
| **Attack Recall** | disabled | malicious & `flag=true` ÷ all judge-malicious |
| **Precision** | disabled | malicious & `flag=true` ÷ all `flag=true` |
| **False Positive Rate** | disabled | benign & `flag=true` ÷ all judge-benign |
| **Sensitive Data Leakage Rate** ⚙ | DLP group detection rate only | judge says "contains sensitive data" & no DLP detector flagged ÷ all judge-sensitive |
| **Unauthorized Action Success Rate** (optional) | scenario label is "unauthorized" & no Agent Behavior detector flagged ÷ all unauthorized scenarios | same |
| **Avg RTT / Max latency** | ms, errors excluded | same |

Each tile shows its sample count `n`.

**Judge scope.** You asked the judge to examine `flag=true` prompts. Recall, ASR and FPR also need verdicts on the `flag=false` prompts, because missed attacks only show up there. So when a judge is set, it reviews **every** case.
- `flag=true` verdicts split detections into true and false positives (precision).
- `flag=false` verdicts split unflagged cases into missed attacks and correctly passed benign prompts (recall, ASR, FPR).
- The report keeps the two sets separate, so the `flag=true` review you asked for stands on its own.

**Judge.** Any OpenAI-compatible endpoint (base URL, API key, model name). It makes one call per case and returns JSON:

```json
{ "malicious": true, "sensitive_data": false, "category": "prompt_attack|harmful_content|sensitive_data|benign", "reason": "..." }
```

Judge verdicts are labeled "judge" in the report.

## 5. Architecture

```
browser (index.html)  ──►  backend (FastAPI, app.py)  ──►  {region}.api.lakera.ai/v2/guard/results
                                    ├──►  datasets-server.huggingface.co  (/splits, /size, /rows)
                                    └──►  optional judge (OpenAI-compatible /chat/completions)
```

- **Backend:** one `app.py` using FastAPI and httpx.
  - `POST /api/test`: checks the key against the chosen endpoint.
  - `POST /api/screen`: screens one chat message.
  - `POST /api/run`: starts a dataset run and streams progress (server-sent events).
  - `GET /api/hf/*`: searches Hugging Face (HF) and samples dataset rows.
  - `POST /api/export`: builds the HTML report.
  - Keys are held only for the request. They are never logged, written to disk, or included in exports.
- **Frontend:** one `index.html` using vanilla JS and a pinned Chart.js. No build step.
- **Storage:** none. Runs live in memory and can be downloaded as JSON or HTML.
- **Run:** `uvicorn app:app` (binds to localhost), or a one-line Dockerfile.

**One record per case:**
```json
{ "id": "...", "source": "chat|upload:<file>|hf:<dataset>/<config>/<split>#<row>",
  "messages": [...], "lakera_results": [...], "groups": {"prompt_defense": "l2_very_likely", "dlp": "no_level", ...},
  "latency_ms": 123, "error": null,
  "judge": { "malicious": true, "sensitive_data": false, "category": "...", "reason": "..." } }
```

## 6. UI

1. **Settings bar**
   - Lakera API key (password field)
   - Endpoint dropdown (7 options)
   - Optional `project_id`, with a ⚙ hint about DLP customization and the agent module
   - Test connection button
   - Optional HF token, for gated datasets
   - Judge section, collapsed by default: base URL, key, model
2. **Chat**
   - Free-form messages, plus an optional system prompt sent as a `system` role message
   - Each message is screened through `/results`
   - The reply bubble shows the flag, a badge per detector group with its level, the latency and, when a judge is set, its verdict
3. **Datasets**
   - Preset list (below), HF search, and file upload (CSV/JSON/JSONL)
   - Pick several datasets. For each one, choose the config/split, the text column and **N** (how many random rows to pull)
   - A global seed makes the random sampling reproducible
4. **Run:** a progress bar, a live results table and a Cancel button. Calls run one at a time.
5. **Report**
   - Threshold selector
   - Metric tiles (section 4)
   - Charts:
     - detection rate per detector group
     - detection rate per dataset
     - threshold sweep
     - confusion matrix (judge only)
     - latency histogram with average and maximum marked
   - Filterable case table with the raw JSON, and a "Bypass candidates (`flag=false`)" tab
   - **Export HTML** and Export JSON buttons

**Dataset presets** (all ungated, and the HF rows API works for each, checked 2026-10-15):

| Purpose | Datasets |
|---|---|
| Attacks (from Lakera's evaluation list) | `OpenSafetyLab/Salad-Data`, `rubend18/ChatGPT-Jailbreak-Prompts`, `deadbits/vigil-jailbreak-ada-002`, `Babelscape/ALERT` |
| Mixed attacks and benign | `deepset/prompt-injections`, `jackhhao/jailbreak-classification` |
| Content moderation | `NobodyExistsOnTheInternet/ToxicQAFinal`, `lmsys/toxic-chat` |
| Benign (for FPR) | `rajpurkar/squad_v2`, `tatsu-lab/alpaca` |
| ⚙ DLP | `ai4privacy/pii-masking-200k`, `gretelai/synthetic_pii_finance_multilingual` |
| Agent (optional) | bundled `scenarios/agent_actions.jsonl` with about 30 labeled tool-call cases, or the user's own upload |

**Random sampling.** `/size` gives the row count. The backend draws N distinct offsets from a seeded random generator and fetches each with `/rows?offset=…&length=1`.

## 7. Interactive HTML export

- A single self-contained file: Chart.js and the run JSON are inlined, so it works offline.
- It keeps the threshold selector, filters, the case table and the raw-JSON drill-down.
- Settings (keys, endpoint credentials, judge URL) are stripped from the file.

## 8. Build phases

| Phase | Deliverable | Done when |
|---|---|---|
| 1 | `app.py`: endpoint map, `/api/test`, `/api/screen` calling `/results`, timing, error capture | A real key returns grouped levels and latency for each endpoint |
| 2 | `index.html`: settings and chat | A chat message shows group badges, the flag and latency |
| 3 | Datasets: HF search, splits, size and seeded sampling; upload parser; presets | 3 datasets × N=20 give 60 cases |
| 4 | Run engine: one call at a time, progress stream, cancel, errors recorded per case | A 200-case run finishes; any 429s are recorded, not fatal |
| 5 | Metrics and report: flag logic, grouping, threshold selector, charts, average and maximum latency | `test_metrics.py` matches a small hand-computed example |
| 6 | Judge: OpenAI-compatible verdicts on all cases; recall, precision, FPR, ASR and leakage enabled | Turning the judge on or off shows or hides the right tiles |
| 7 | HTML export | The exported file opens offline and its charts and filters work |
| 8 | Optional agent module and ⚙ DLP notes: scenario pack, docs links, README, Dockerfile | The Unauthorized Action metric computes when a `project_id` with agent detectors is set |
