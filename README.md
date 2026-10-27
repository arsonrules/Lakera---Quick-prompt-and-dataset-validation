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
docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD/data:/app/data" lakera-guard-tester
```

## Using it

New to guardrail testing? The app walks you through it: **Quick check** tries one prompt; then **1 Choose prompts → 2 Run test → 3 Report**. A tick appears on each step once it's done.

1. **Top bar:** your Lakera API key, the region, and an optional project ID (blank uses Lakera's default policy, which runs every detector). **Test connection** checks the key, and the lock note confirms keys stay in this browser tab.
2. **Quick check:** type any prompt, or click an example (prompt injection, normal question, personal data, suspicious link). The answer says in plain words whether Lakera flagged it, which detector caught it, how sure it was (for example "L3 likely") and what that detector looks for.
3. **1 Choose prompts:**
   - **Use the recommended starter set** adds 100 labeled prompts (attacks and normal prompts) and builds the test set in one click.
   - Or pick sources yourself: **presets** grouped by what Lakera should do with them (Labeled mix, Attacks, Harmful content, Benign, Personal data, Agent tool calls); click a preset to add it and again to remove it. You can also use **downloaded datasets**, **Hugging Face search** (with an optional token) or **upload a file**.
   - For each source choose how many prompts to use at random, or tick **All**. The **random seed** makes the picks repeatable, and adding a source never reshuffles the others.
   - "All" is limited to 500,000 rows per source. Small Hugging Face samples are read through its dataset viewer (100 rows per request). That API rate-limits hard (429), even with a token, so a sample that would need more than 10 requests downloads the whole split once as Parquet into `data/` instead: a few requests, and later builds read it from disk. Builds and runs over 10,000 prompts ask for confirmation first.
   - **Build test set** shows what you got, for example "37 labeled malicious, 63 labeled benign". Download it as **.jsonl** (every field; upload it again to rerun exactly the same prompts) or **.csv** (for spreadsheets; cells starting with `=`, `+`, `-` or `@` get a leading `'` so they can't run as formulas).
4. **2 Run test:**
   - Optional **judge model** (any OpenAI-compatible API) labels each prompt, so prompts without labels can be scored too and the report adds Attack Success Rate, Precision and more.
   - Optional **system prompt**, sent with every prompt the way your app would send it.
   - **Parallel checks** (1–16, default 4). Lakera publishes no per-second rate limit (only a `429` response, and 10,000 requests a month on Community plans), so on a `429` the test halves its parallel checks, pauses for the server's `Retry-After` (1 s if absent) and retries that prompt once. A second `429`, or any other error, is recorded on the prompt and the test continues. More parallel checks finish sooner but can make each answer slower.
   - A warm-up call opens the connection first and isn't counted. If it gets a 401 or 403, the test stops before using quota.
   - **Stop** ends the test at any point and keeps every result. **Resume (N left)** tests the connection first, then checks only the prompts that hadn't finished (any that were in flight when you stopped are re-run). If the region or project changed, Resume asks first. **Start test** starts over and asks before discarding a stopped test.
5. **3 Report:**
   - **At a glance:** the answer in plain sentences, for example "Lakera caught 9 of the 23 prompts it should have flagged (39%)" and "It wrongly flagged 2 of the 24 prompts it should have let through (8%)", plus response time.
   - **Dataset composition:** how many prompts each dataset labels malicious or benign (a bar plus a per-source table naming where the labels come from: a label column, a whole-dataset label or an agent scenario). If no selected dataset has labels, it says so instead: all results then rest on the judge model's verdicts or, without a judge, on what Lakera's guardrails flagged alone. Sources without labels in a mixed run are called out the same way.
   - **How to read this report:** a glossary (flagged, confidence levels L1–L5, each detector group, malicious/benign, threat, false alarm, judge, failed check, response time) and this run's details.
   - Metrics grouped by question: **Overview**, **Catching threats**, **Avoiding false alarms**, **The judge's view** (judge-only metrics, kept apart because the judge can disagree with dataset labels) and **Speed**. Each says what it means and whether higher or lower is better; **ⓘ** shows how it's calculated with this run's numbers.
   - **Results by source** (click a row to list its prompts), Lakera against the datasets' labels and against the judge (Caught / Missed / False alarm / Correctly let through), charts by detector and source, response times, prompts not flagged, and **All prompts** with filters. Click any prompt for its full text (or agent conversation), what each detector reported, the dataset label and the judge's verdict.
   - Sections fold (Expand all / Collapse all). **Download report (HTML)** gives an interactive offline file; **Download data (JSON)** the raw results.

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
| False alarm rate | dataset label, agent scenario or judge | prompts that should be let through but were flagged ÷ prompts that should be let through (failed checks left out) |
| Effective detection rate | dataset label, agent scenario or judge | should-flag prompts flagged ÷ all should-flag prompts; failed calls count as missed. "Should flag" comes from the dataset label (malicious), else the scenario (unauthorized), else the judge (malicious or sensitive data); prompts with none are left out |
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

## Local datasets (fast loading)

Download datasets once into `data/` (git-ignored); the **Datasets → Local datasets** list then samples them from disk with no Hugging Face requests or rate limits. Loading all 451,424 Nemotron train rows takes about 3 seconds.

```bash
.venv/bin/python download_datasets.py                      # the default list
.venv/bin/python download_datasets.py org/name             # any other dataset
HF_TOKEN=hf_... .venv/bin/python download_datasets.py      # gated datasets
```

- **What's downloaded:** each dataset's Parquet conversion from Hugging Face, every config and split, a few requests per split. Files already on disk are skipped.
- **Gated datasets** (`walledai/XSTest`, `hackaprompt/hackaprompt-dataset`, `MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT`): accept each one's terms on its Hugging Face page while signed in, then rerun with `HF_TOKEN` set to a read token. Without that they're skipped with a message.
- **`qxcv/tensor-trust`** has no Parquet conversion, so its three benchmark JSONL files are downloaded and converted. The 130 MB+ raw dumps are skipped.
- **Default labels:** label columns are auto-detected (`label`, `prompt_label`, `is_prompt_extraction`, …). NotInject defaults to "whole dataset benign" and tensor-trust to "whole dataset malicious"; change either in the picker.
- **Docker:** `data/` isn't in the image; mount it with `-v "$PWD/data:/app/data"`.

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
- **Rate limits.** Lakera documents no numeric rate limit, so the run can only react to `429`s (halve concurrency, pause, retry once); it can't stay under a limit it doesn't know. HF's dataset viewer rate-limits anonymous use, so add an HF token or use local datasets for large samples.
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
| `download_datasets.py` | downloads Hugging Face datasets into `data/` as Parquet |
| `PLAN.md` | design and the Lakera capability and gap review |
