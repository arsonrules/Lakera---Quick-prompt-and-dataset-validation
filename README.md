# Lakera Guard Tester

A local web UI for testing Lakera Guard (Check Point AI Guardrails) detection on single prompts, datasets and agent tool calls, with a report you can export as an offline HTML file. No model endpoint needed.

The **API** picker in the header chooses the endpoint:

- **Screening (logged)**, the default: `POST /v2/guard`. Shows in the Lakera portal's logs.
- **Raw results (L1–L5)**: `POST /v2/guard/results`. Returns confidence levels, not logged.

## Quick start

Needs Python 3.11+ (Node.js only for `test_report.js`).

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app:app --port 8765          # open http://localhost:8765
```

On Windows, use `.venv\Scripts\` in place of `.venv/bin/`.

### Docker

```bash
docker build -t lakera-guard-tester .
docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD/data:/app/data" lakera-guard-tester
```

- Publish on `127.0.0.1` only: the backend forwards your API keys.
- The `-v` mount keeps downloaded datasets between runs. On Linux, make `data/` writable first: `mkdir -p data && chmod a+rwx data`.

### `CERTIFICATE_VERIFY_FAILED` behind a corporate proxy

Your network re-signs HTTPS with its own root CA. Get that CA file from IT (PEM or DER, here `corp-ca.cer`), add it to the standard CAs, and point `SSL_CERT_FILE` at the bundle:

```bash
docker run --rm -v "$PWD/corp-ca.cer:/tmp/corp:ro" lakera-guard-tester python -c "import ssl,certifi;b=open('/tmp/corp','rb').read();print(open(certifi.where()).read()+(b.decode() if b'BEGIN' in b else ssl.DER_cert_to_PEM_cert(b)))" > ca-bundle.pem
```

```bash
docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD/data:/app/data" -v "$PWD/ca-bundle.pem:/certs/ca-bundle.pem:ro" -e SSL_CERT_FILE=/certs/ca-bundle.pem lakera-guard-tester
```

Without Docker: `SSL_CERT_FILE=ca-bundle.pem .venv/bin/uvicorn app:app --port 8765`.

If it still fails, run `certcheck.py`. It shows whether `SSL_CERT_FILE` arrived, how many certificates the bundle holds, and who signs huggingface.co and api.lakera.ai. If that signer isn't your IT's CA, you have the wrong file.

```bash
docker run --rm -i -v "$PWD/ca-bundle.pem:/certs/ca-bundle.pem:ro" -e SSL_CERT_FILE=/certs/ca-bundle.pem lakera-guard-tester python - < certcheck.py
```

## Using it

1. **Top bar:** Lakera API key, region, optional project ID (blank = Lakera's default policy). **Test connection** checks the key.
2. **Quick check:** test one prompt. **Add it as: Attack / Normal prompt** saves it into every later batch run.
3. **1 Choose prompts:** the recommended starter set, presets, downloaded datasets, Hugging Face search, an uploaded file or pasted prompts. Pick N at random per source (or **All**, up to 500,000); the **random seed** makes picks repeatable. **Build test set** can be downloaded as .jsonl (re-uploadable) or .csv.
4. **2 Run test:** optional judge model (any OpenAI-compatible API) and system prompt; 1–16 parallel checks. On a `429` the run halves concurrency, waits for `Retry-After` and retries once. **Stop**, **Resume** and **Retry failed checks** keep every result.
5. **3 Report:** headline answer with **Show missed** / **Show false alarms**, dataset composition with a detection overlay, metrics, results by source, clickable confusion tables, and every prompt's detail. Download as HTML (interactive, offline) or JSON, reopen either with **Open saved report…**, and **Compare** two runs prompt by prompt (build both from the same sources and seed).

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

`us-east-1`, `us-west-2` and `eu-west-1` work but aren't in Lakera's Data Regions doc. Your organization's `allowed_processing_regions` can reject a region with a 4xx.

## How the flag and metrics are calculated

- **Screening:** the flag is Lakera's `flagged` under your project policy. The breakdown shows which detectors fired, and the Lakera request ID is kept to find the call in the portal.
- **Raw results:** each detector returns `l1_confident` … `l5_unlikely` or `no_level`. A prompt is flagged when any detector reports L1–L4, matching Lakera's default sensitivity.
- **Detector groups:** `prompt_attack` → Prompt Defense, `moderated_content/*` → Content Moderation, `pii/*` → DLP, `unknown_links` → Malicious Links, `dangerous_deviation` → Agent Behavior, anything else → Other.

| Metric | Needs | Definition |
|---|---|---|
| Detection rate | — | flagged ÷ prompts screened successfully |
| False positive rate | label, scenario or judge | should-pass prompts flagged ÷ should-pass prompts (failed checks left out) |
| Effective detection rate | label, scenario or judge | should-flag prompts flagged ÷ should-flag prompts; failed checks count as missed. "Should flag" comes from the dataset label, else the scenario, else the judge |
| Bypass candidates | — | prompts not flagged |
| Avg RTT / Max latency | — | backend-measured round trip to Lakera, errors and warm-up excluded |
| Attack Success Rate | judge | judged malicious & not flagged ÷ judged malicious |
| Attack Recall | judge | judged malicious & flagged ÷ judged malicious |
| Precision | judge | flagged & expected ÷ flagged (expected = judged malicious or sensitive data) |
| False Positive Rate (judge) | judge | flagged & not expected ÷ not expected |
| Sensitive Data Leakage | judge | sensitive data & no DLP flag ÷ sensitive data |
| Unauthorized Action Success Rate | agent scenarios | unauthorized & not flagged ÷ unauthorized scenarios |
| Allowed actions blocked | agent scenarios | allowed & flagged ÷ allowed scenarios |

The judge reviews every successfully screened prompt. Its time isn't counted in Lakera latency, and its verdicts are model labels, not ground truth.

## Local datasets

Download datasets once into `data/` (git-ignored) to sample them from disk with no Hugging Face rate limits:

```bash
.venv/bin/python download_datasets.py                      # the default list
.venv/bin/python download_datasets.py org/name             # any other dataset
HF_TOKEN=hf_... .venv/bin/python download_datasets.py      # gated datasets
```

Gated datasets (`walledai/XSTest`, `hackaprompt/hackaprompt-dataset`, `MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT`) need their terms accepted on Hugging Face first, then `HF_TOKEN` set to a read token.

## Dataset labels

Choose **Label (optional)** in the picker: a label column, or the whole dataset as malicious or benign. Values like `1`/`true`/`jailbreak`/`toxic`/`unsafe` mean malicious; `0`/`false`/`benign`/`safe` mean benign; anything else shows as "unknown". Presets come with labels set.

## Agent scenarios

[`scenarios/agent_actions.jsonl`](scenarios/agent_actions.jsonl) has 30 tool-call cases (18 unauthorized, 12 allowed). Add it from **Presets → Agent**, or upload your own in this format:

```json
{"id": "…", "expected": "allowed|unauthorized", "danger": "data_leakage|privilege_escalation|system_destruction|null",
 "messages": [{"role": "system", …}, {"role": "user", …}, {"role": "assistant", "tool_calls": [ … ]}],
 "tools": [{"type": "function", "function": {"name": "…", "parameters": { … }}}]}
```

Lakera's default policy runs no agent detectors: use a project ID whose policy enables Dangerous Deviation or a tool allow/deny list.

## Known limitations

- **No end-to-end attack success:** no model is called, so "Attack Success Rate" means the guardrail was bypassed.
- **DLP:** built-in PII covers 8 mostly US formats. Add custom regex or guardrails to your project policy for others.
- **Rate limits:** Lakera documents none, so runs only react to `429`s. Use an HF token or local datasets for large Hugging Face samples.
- **Screening calls are real traffic:** they're logged and can trigger alerts. Raw results calls aren't logged.
- **Text only:** no images or audio.

## Security

- API keys and the HF token stay in the tab's session storage, are sent to the local backend per request, and are never logged, stored or exported.
- The backend binds to localhost; in Docker publish to `127.0.0.1` only.
- The judge URL you enter is called as-is.

## Development

```bash
.venv/bin/python test_app.py   # backend self-check (no network)
node test_report.js            # metrics and export check
```

| File | What |
|---|---|
| `app.py` | FastAPI backend |
| `index.html` | single-page UI (no build step) |
| `report.js` | metrics and report; inlined into HTML exports |
| `download_datasets.py` | downloads Hugging Face datasets into `data/` |
| `certcheck.py` | diagnoses certificate errors |
| `scenarios/agent_actions.jsonl` | bundled agent scenarios |
| `PLAN.md` | design notes |
