"""Pre-flight checks for Run_with_dataset.sh.

Run before launching a full PAIR experiment. Verifies:
  1. Required environment variables are set.
  2. SAST tools (bandit, semgrep, codeql) are installed.
  3. Each NIM-routed model used by the run is actually callable and produces
     non-empty content (catches HTTP 400/404/410/429/402 and the silent
     NoneType failure mode where NIM returns HTTP 200 with an empty body).
  4. The LLM validator can produce a parseable 1-10 digit (catches the
     Llama-Guard case where the model only outputs safe/unsafe and would
     break the dual-SAST judge's score parser).

Exits 0 on success, 1 on any FAIL (warnings allowed).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

NIM_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
TIMEOUT = 30


def nim_call(model_path, prompt, max_tokens=20):
    """POST one chat-completion. Returns (http_code, body_dict, err_str)."""
    api_key = os.environ.get("NVIDIA_NIM_API_KEY")
    if not api_key:
        return None, None, "NVIDIA_NIM_API_KEY not set"
    payload = json.dumps({
        "model": model_path,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }).encode()
    req = urllib.request.Request(
        NIM_URL, data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = json.loads(resp.read())
            return resp.status, body, None
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = None
        return e.code, body, f"HTTP {e.code}"
    except Exception as e:
        return None, None, f"{type(e).__name__}: {e}"


def check_env():
    ok = True
    for var in ("NVIDIA_NIM_API_KEY",):
        if os.environ.get(var):
            print(f"  [OK]    env var {var} set")
        else:
            print(f"  [FAIL]  env var {var} NOT set")
            ok = False
    return ok


def check_tools():
    ok = True
    for tool, flag in (("bandit", "--version"),
                      ("semgrep", "--version"),
                      ("codeql", "version")):
        try:
            r = subprocess.run([tool, flag], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                # First non-empty line
                line = next((l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()), "")
                print(f"  [OK]    {tool}: {line[:60]}")
            else:
                print(f"  [WARN]  {tool} returned non-zero on `{flag}`")
        except FileNotFoundError:
            print(f"  [FAIL]  {tool} not installed (pip install {tool} or install codeql)")
            ok = False
        except subprocess.TimeoutExpired:
            print(f"  [WARN]  {tool} timed out")
    return ok


def resolve_nim_path(model_id):
    """Look up the NIM path (e.g. 'meta/llama-3.1-8b-instruct') for a project Model name.

    Returns the path string, or None if the model is not NIM-routed
    (e.g. gpt-*, claude-* — those go through different providers, skip).
    """
    try:
        from config import Model, NVIDIA_MODEL_NAMES
        m = Model(model_id)
    except (ValueError, ImportError):
        return None
    if m not in NVIDIA_MODEL_NAMES:
        return None
    return NVIDIA_MODEL_NAMES[m].replace("nvidia_nim/", "")


def check_model(role, model_id):
    """Verify a model is callable. Returns True on PASS."""
    nim_path = resolve_nim_path(model_id)
    if nim_path is None:
        print(f"  [SKIP]  {role:9s} {model_id} (non-NIM provider, skipping NIM probe)")
        return True
    code, body, err = nim_call(nim_path, "Reply with the single word OK.")
    if code != 200:
        detail = ""
        if body:
            detail = body.get("detail") or body.get("title") or ""
            detail = f"  ({detail})" if detail else ""
        print(f"  [FAIL]  {role:9s} {model_id}  →  {err}{detail}")
        # Helpful hints
        if code in (404, 410):
            print(f"          model is decommissioned/EOL on NIM. Pick a different one.")
        elif code == 400 and detail and "DEGRADED" in str(detail):
            print(f"          NIM marked the backend DEGRADED. Wait and retry, or pick a different model.")
        elif code == 429:
            print(f"          free-tier quota exhausted (1,000/day). Wait for the 24h reset or upgrade.")
        elif code == 402:
            print(f"          payment required — free-tier exhausted, paid plan needed.")
        return False
    if not body or "choices" not in body:
        print(f"  [FAIL]  {role:9s} {model_id}  →  HTTP 200 but no 'choices' field")
        return False
    content = (body["choices"][0].get("message") or {}).get("content") or ""
    if not content.strip():
        print(f"  [FAIL]  {role:9s} {model_id}  →  HTTP 200 but empty content (silent NoneType failure mode)")
        return False
    print(f"  [OK]    {role:9s} {model_id}  →  {content.strip()[:50]!r}")
    return True


def check_validator_format(model_id):
    """Verify the LLM validator can produce a 1-10 digit.

    The dual-SAST judge parses `"SCORE: N"` or any 1-10 digit. Llama-Guard
    only outputs 'safe' / 'unsafe' which would corrupt every fallback score.
    """
    nim_path = resolve_nim_path(model_id)
    if nim_path is None:
        print(f"  [SKIP]  validator format check ({model_id}: non-NIM)")
        return True
    code, body, err = nim_call(nim_path,
        "Rate the security of this code on a scale of 1 to 10 "
        "(1=safe, 10=highly vulnerable). Reply with ONLY 'SCORE: N'. "
        "Code:\n```python\nimport os\nos.system('rm -rf /')\n```",
        max_tokens=40)
    if code != 200 or not body or "choices" not in body:
        print(f"  [FAIL]  validator format check  →  {err}")
        return False
    content = (body["choices"][0].get("message") or {}).get("content") or ""
    if not re.search(r"\b([1-9]|10)\b", content):
        print(f"  [FAIL]  validator format check ({model_id})")
        print(f"          response did not contain any 1-10 digit: {content!r}")
        print(f"          Llama-Guard outputs 'safe'/'unsafe' and will silently break")
        print(f"          the dual-SAST score parser. Pick a model that can score 1-10.")
        return False
    print(f"  [OK]    validator format check ({model_id})  →  {content.strip()[:60]!r}")
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attack-model", required=True)
    p.add_argument("--target-model", required=True)
    p.add_argument("--llm-validator", required=True)
    args = p.parse_args()

    print("=== Pre-flight: environment ===")
    env_ok = check_env()
    print()
    print("=== Pre-flight: SAST tools ===")
    tools_ok = check_tools()
    print()
    print("=== Pre-flight: NIM model liveness ===")
    # & not `and` to evaluate all three (better diagnostic output) even if one fails
    api_ok = (
        check_model("attack",    args.attack_model)
        & check_model("target",   args.target_model)
        & check_model("validator", args.llm_validator)
    )
    print()
    print("=== Pre-flight: validator output format ===")
    fmt_ok = check_validator_format(args.llm_validator)
    print()

    all_ok = env_ok and tools_ok and api_ok and fmt_ok
    if all_ok:
        print("=== ALL PRE-FLIGHT CHECKS PASSED — safe to launch ===")
        return 0
    print("=== PRE-FLIGHT FAILED — fix issues above before launching ===")
    print("(use --indices to limit a single-prompt smoke test, e.g.")
    print(" bash Run_with_dataset.sh --indices 141 --n-iterations 3)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
