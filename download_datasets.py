"""Download Hugging Face datasets into data/ for quick local loading.

    .venv/bin/python download_datasets.py                 # the default list below
    .venv/bin/python download_datasets.py org/name ...    # specific datasets
    HF_TOKEN=hf_... .venv/bin/python download_datasets.py # gated datasets (accept their terms on huggingface.co first)

Layout: data/<org>__<name>/<config>/<split>/<n>.parquet. Files already on disk are skipped.
Uses Hugging Face's Parquet conversion (a few requests per split, not one per 100 rows);
datasets without one fall back to RAW_FILES (JSONL in the repo), converted to Parquet.
"""
import json
import os
import sys
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

DATA = Path(__file__).with_name("data")
DEFAULT = [
    "leolee99/NotInject",
    "walledai/XSTest",
    "qxcv/tensor-trust",
    "hackaprompt/hackaprompt-dataset",
    "MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT",
    "walledai/CyberSecEval",
    "neuralchemy/Prompt-injection-dataset",
    "nvidia/Nemotron-Safety-Guard-Dataset-v3",
]
# No Parquet conversion on HF (dataset viewer off): repo JSONL files -> (config, split).
# ponytail: tensor-trust's raw dumps (130 MB+ .bz2) are skipped; add them here if needed.
RAW_FILES = {
    "qxcv/tensor-trust": {
        "benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl": ("benchmarks", "hijacking_robustness"),
        "benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl": ("benchmarks", "extraction_robustness"),
        "detecting-extractions/v1/prompt_extraction_detection.jsonl": ("detection", "prompt_extraction_detection"),
    },
}


def folder(dataset: str) -> Path:
    return DATA / dataset.replace("/", "__")


def fetch(client: httpx.Client, url: str, dest: Path) -> None:
    """Stream url to dest via a .part file, so an interrupted download is never mistaken for a finished one."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    try:
        with client.stream("GET", url) as r:
            r.raise_for_status()
            with part.open("wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    f.write(chunk)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    part.rename(dest)


def download(client: httpx.Client, dataset: str) -> str:
    if dataset in RAW_FILES:
        for path, (config, split) in RAW_FILES[dataset].items():
            dest = folder(dataset) / config / split / "0.parquet"
            if dest.exists():
                continue
            raw = dest.with_suffix(".jsonl")
            fetch(client, f"https://huggingface.co/datasets/{dataset}/resolve/main/{path}", raw)
            rows = [json.loads(line) for line in raw.read_text().splitlines() if line.strip()]
            pq.write_table(pa.Table.from_pylist(rows), dest)
            raw.unlink()
        return "ok (repo JSONL -> Parquet)"
    r = client.get(f"https://huggingface.co/api/datasets/{dataset}/parquet")
    if r.status_code in (401, 403) or (r.status_code == 200 and not r.json()):
        return "skipped: gated or no Parquet files. Accept its terms on huggingface.co, then rerun with HF_TOKEN set"
    r.raise_for_status()
    n = 0
    for config, splits in r.json().items():
        for split, urls in splits.items():
            for i, url in enumerate(urls):
                dest = folder(dataset) / config / split / f"{i}.parquet"
                if not dest.exists():
                    fetch(client, url, dest)
                n += 1
    return f"ok ({n} Parquet files)"


def main(names: list[str]) -> int:
    token = os.environ.get("HF_TOKEN", "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    failed = 0
    # httpx drops the Authorization header when HF redirects downloads to its CDN host.
    with httpx.Client(headers=headers, follow_redirects=True, timeout=120) as client:
        for d in names:
            try:
                status = download(client, d)
            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                status = ("skipped: gated. Accept its terms on huggingface.co, then rerun with HF_TOKEN set"
                          if code in (401, 403) else f"failed: HTTP {code}")
            except (httpx.HTTPError, OSError, ValueError) as e:
                status = f"failed: {type(e).__name__}: {e}"
            if not status.startswith("ok"):
                failed += 1
                for p in sorted(folder(d).glob("**/"), reverse=True):  # drop folders a failed download left empty
                    if p.is_dir() and not any(p.iterdir()):
                        p.rmdir()
            print(f"{d}: {status}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or DEFAULT))
