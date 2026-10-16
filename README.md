# Lakera Guard Tester

A local web UI for testing Lakera Guard (Check Point AI Guardrails) detection. It needs no model endpoint: every prompt is screened with `POST /v2/guard/results`. The report is built from the confidence levels that endpoint returns, and you can export it as an interactive, offline HTML file.

## Quick start

```bash
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/uvicorn app:app --port 8765          # open http://localhost:8765
```

Or with Docker (published on localhost only, because the backend forwards your API keys):

```bash
docker build -t lakera-guard-tester .
docker run --rm -p 127.0.0.1:8765:8765 lakera-guard-tester
```

## Using it

1. **Settings bar:**
   - Lakera API key, endpoint (7 regions) and optional project ID.
   - Optional Hugging Face (HF) token, for rate limits and gated datasets.
   - Optional **judge model**: an OpenAI-compatible base URL, an optional API key, and a model name.

   **Test connection** and **Test judge** check each one.
2. **Chat:** type any prompt, with an optional system prompt. Each message is screened, and you see the flag, the level for each detector group, the latency and, if a judge is set, its verdict.
3. **Datasets:** pick sources from three places:
   - presets (Lakera's evaluation list plus benign and DLP sets);
   - Hugging Face search, then choose the config, split and text column;
   - an uploaded `.csv` / `.json` / `.jsonl` / `.txt` file.

   Set **N** for each dataset and a **seed**. The random sampling is reproducible, and adding a dataset never reshuffles the others.
   To use every row instead, tick **All rows** in the Hugging Face search or upload picker, tick **All** on a selected dataset, or click **Load all rows** to do it for every selected dataset and build in one step. "All" is limited to 500,000 rows per dataset; larger datasets are refused with a message. Hugging Face serves 100 rows per request, so a large split means thousands of requests (451k rows ≈ 4,500): add an HF token, and expect it to take a while. Builds and runs over 10,000 prompts ask for confirmation first, since a run makes one Lakera call per prompt (100k prompts ≈ 8 hours at ~0.3 s each) and uses your quota.

   After **Build sample** you can download it:
   - **.jsonl** keeps every field, including labels and agent scenarios' messages and tools. Uploading it again rebuilds the same sample with no Hugging Face calls; set N ≥ the row count to keep every row.
   - **.csv** has id, source, prompt and label, for spreadsheets. Cells starting with `=`, `+`, `-` or `@` get a leading `'` so spreadsheets don't run them as formulas.
4. **Run:** prompts are screened one at a time.
   - A warm-up call opens the connection first; it isn't recorded or counted in latency. If the warm-up gets a 401 or 403, the run stops before using quota.
   - Progress is live, and you can cancel at any point.
   - Errors, including `429`, are recorded on the prompt and the run continues.
5. **Report:** metrics, charts, bypass candidates and a filterable case table. Then **Export HTML** (an interactive offline file) or **Export JSON**.

## Endpoints

| Key | Label | URL |
|---|---|---|
| community | Community | `https://api.lakera.ai/v2/guard` |
| us | US (multi-region) | `https://us.api.lakera.ai/v2/guard` |
| us-east-1 | US East (N. Virginia) | `https://us-east-1.api.lakera.ai/v2/guard` |
| us-west-2 | US West (Oregon) | `https://us-west-2.api.lakera.ai/v2/guard` |
| eu-west-1 | EU (Ireland) | `https://eu-west-1.api.lakera.ai/v2/guard` |
| eu | EU | `https://eu.api.lakera.ai/v2/guard` |
| ap-southeast-1 | Asia (Singapore) | `https://ap-southeast-1.api.lakera.ai/v2/guard` |

`us-east-1`, `us-west-2` and `eu-west-1` respond to requests but are not in Lakera's Data Regions doc. Your organization's `allowed_processing_regions` setting can reject other regions with a 4xx error.

## How the flag and metrics are calculated

`/v2/guard/results` returns a confidence level for each detector and makes no flagging decision. The levels are `l1_confident` … `l5_unlikely` and `no_level`. This tool works out the flag itself:

- **Flag:** any detector reports a level from l1 to l4, the same cut-off as Lakera's default policy sensitivity. It's fixed, not configurable; set the real sensitivity in your project's policy.
- **Detector groups:** results are grouped by prefix:
  - `prompt_attack` → Prompt Defense
  - `moderated_content/*` → Content Moderation
  - `pii/*` → DLP
  - `unknown_links` → Malicious Links
  - `dangerous_deviation` → Agent Behavior
  - anything else → Other

| Metric | Needs | Definition |
|---|---|---|
| Detection rate | — | flagged ÷ prompts screened successfully |
| Bypass candidates | — | prompts with flag = false (without a judge these are candidates, not confirmed misses) |
| Avg RTT / Max latency | — | backend-measured round trip to Lakera, errors and warm-up excluded |
| Attack Success Rate | judge | judged malicious & not flagged ÷ judged malicious |
| Attack Recall | judge | judged malicious & flagged ÷ judged malicious |
| Precision | judge | flagged & expected ÷ flagged, where expected = judged malicious **or** contains sensitive data |
| False Positive Rate | judge | flagged & not expected ÷ not expected |
| Sensitive Data Leakage ⚙ | judge | contains sensitive data & no DLP detector flagged ÷ contains sensitive data |
| Unauthorized Action Success Rate | agent scenarios | `expected: unauthorized` & not flagged ÷ unauthorized scenarios (a flag from any detector counts as blocked, as Enforce mode would) |
| Allowed actions blocked | agent scenarios | `expected: allowed` & flagged ÷ allowed scenarios |

**The judge** reviews every prompt that Lakera screened successfully (both `flag=true` and `flag=false`), and its time is never counted in Lakera latency. Its verdicts are model labels, not ground truth, and the report says so.

## Dataset labels (for cross-checking)

If a dataset says whether a prompt is malicious or benign, the report shows that next to Lakera's flag and the judge's verdict. It doesn't change any metric.

- **In the picker:** choose **Label (optional)**. Either pick a label column (auto-guessed from names like `label`, `type`, `toxicity`), or say the whole dataset is malicious or benign.
  - Values such as `1`/`true`/`jailbreak`/`injection`/`toxic`/`unsafe` mean malicious.
  - Values such as `0`/`false`/`benign`/`safe` mean benign.
  - Anything else is shown as "unknown" with the raw value.
- **Presets:** these come with labels set:
  - `deepset/prompt-injections`: the `label` column
  - `jackhhao/jailbreak-classification`: the `type` column
  - `lmsys/toxic-chat`: the `toxicity` column
  - The attack and harmful-content sets are marked malicious as a whole, and SQuAD and Alpaca benign as a whole.
- **In the report:** a "Dataset labels vs Lakera" table, the judge's agreement rate with the labels, a **Disagreements** list (labeled malicious but not flagged, then labeled benign but flagged) to review, and a dataset-label filter in All cases.

## Agent scenarios (optional)

[`scenarios/agent_actions.jsonl`](scenarios/agent_actions.jsonl) bundles 30 hand-written tool-call cases in four domains: support, DevOps, drive and email.

- 18 are unauthorized, split evenly across data leakage, privilege escalation and system destruction. 4 of them arrive by prompt injection in a tool response.
- 12 are legitimate tool calls.

Add the pack from **Datasets → Presets → Agent**, or upload your own `.jsonl` file in the same format:

```json
{"id": "…", "expected": "allowed|unauthorized", "danger": "data_leakage|privilege_escalation|system_destruction|null",
 "messages": [{"role": "system", …}, {"role": "user", …}, {"role": "assistant", "tool_calls": [ … ]}],
 "tools": [{"type": "function", "function": {"name": "…", "parameters": { … }}}]}
```

Lakera's default policy does **not** run agent detectors. To measure this properly, set a **project ID** whose policy enables Dangerous Deviation (beta) or a tool allow/deny list. When no Agent Behavior results come back, the report says so.

## ⚙ DLP customization

Lakera's built-in PII detectors cover 8 types: full name, US mailing address, US phone, email, IP, credit card, IBAN and US SSN. Non-US formats such as phone numbers, addresses and national IDs will look like leakage. For other data, add custom regex or custom guardrails to a project policy in the Lakera dashboard, then pass that project ID. Custom matches show up under DLP or Other in the report.

## Known limitations

- **No end-to-end attack success.** No model is called, so "Attack Success Rate" means the guardrail was bypassed, not that the attack worked.
- **Rate limits.** No throttling or retry for Lakera: a `429` is recorded on that prompt. HF's dataset viewer rate-limits anonymous use, so add an HF token for large samples.
- **Not in the dashboard.** `/v2/guard/results` calls are not logged in the Lakera dashboard, and `/v2/guard` is never called.
- **Text only.** Images and audio are out of scope.
- **Unknown detector names.** Detector types that aren't listed above land in "Other". A live run on 2026-10-15 (us-east-1, a project with 17 detectors) returned these, all grouped correctly:
  - `prompt_attack`
  - `unknown_links`
  - `moderated_content/` hate, weapons, crime, sexual, self_harm, profanity, violence
  - `pii/` address, credit_card, email, ip_address, name, phone_number, us_social_security_number, iban_code

  `dangerous_deviation` comes from Lakera's docs. That policy had no agent detectors, so it wasn't confirmed live, and neither was the tool allow/deny list's type name.

## Security notes

- **Keys:** the Lakera key, judge key and HF token stay in the browser tab's session storage and are sent to the local backend only per request. They are never logged, written to disk or exported, and any key that appears in exported text is redacted.
- **Session check:** on load and whenever a key changes, the page checks that keys are session-only. Any copy in localStorage (which outlives the tab) is removed and reported in the header; a copy in a cookie is reported. When all is well the header shows "🔒 Keys: this tab only". `test_app.py` also fails if the page ever stores a key outside sessionStorage, or if the backend keeps a token after a request.
- **Bind address:** the backend binds to localhost by default. In Docker, publish to `127.0.0.1` only.
- **Judge URL:** the judge URL you enter is called as-is.

## Development

```bash
.venv/bin/python test_app.py   # backend self-check (fake Lakera, HF and judge; no network)
node test_report.js            # metrics + export check against hand-computed examples
```

| File | What |
|---|---|
| `app.py` | FastAPI backend: Lakera calls, HF sampling, uploads, run stream, judge |
| `index.html` | the single-page UI (no build step) |
| `report.js` | metrics and report rendering; inlined into HTML exports |
| `scenarios/agent_actions.jsonl` | bundled agent scenario pack |
| `PLAN.md` | design and the Lakera capability and gap review |
