import hashlib
import hmac
import os
import threading
import traceback

import requests
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, request

load_dotenv()  # before graph is imported: it reads REVIEW_MODEL at import time

from graph import MODEL, run_review  # noqa: E402

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
REVIEWED_ACTIONS = {"opened", "synchronize", "reopened"}
# GitHub rejects comments over 65,536 characters; a long review should lose its
# tail, not the whole post.
MAX_COMMENT_CHARS = 65_000

app = Flask(__name__)


def signature_valid(body: bytes, header: str | None) -> bool:
    # Unsigned requests could make the bot spend minutes of compute and comment on
    # any pull request the token can reach. With no secret configured, fail closed.
    if not WEBHOOK_SECRET or not header:
        return False
    expected = "sha256=" + hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def build_comment(files: list[dict], metadata: dict) -> str:
    sections = []
    for f in files:
        patch = f.get("patch")
        if not patch:  # binary, too large for GitHub to diff, or a pure rename
            continue
        try:
            report = run_review(raw_diff=patch, pr_metadata=metadata)
        except Exception as e:
            # One file failing - a repetition loop, say - must not cost the reviews
            # of every other file in the pull request.
            report = f"_Review failed for this file ({type(e).__name__})._"
        sections.append(f"### `{f['filename']}`\n\n{report}")

    header = f"## AI Code Review — `{metadata['commit_hash'][:7]}`"
    if not sections:
        return f"{header}\n\nNo reviewable text changes in this pull request."

    body = header + "\n\n" + "\n\n---\n\n".join(sections)
    footer = f"\n\n<sub>Reviewed locally with {MODEL} via Ollama; no code left the machine.</sub>"
    if len(body) + len(footer) > MAX_COMMENT_CHARS:
        body = body[: MAX_COMMENT_CHARS - len(footer) - 60] + "\n\n_Truncated to fit GitHub's comment limit._"
    return body + footer


def review_pull_request(payload: dict) -> None:
    repo = payload["repository"]["full_name"]
    pr = payload["pull_request"]
    number = pr["number"]
    try:
        github = requests.Session()
        github.headers.update({
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        # ponytail: first 100 files only; paginate if pull requests get that big.
        files = github.get(f"{GITHUB_API}/repos/{repo}/pulls/{number}/files",
                           params={"per_page": 100}, timeout=30)
        files.raise_for_status()

        metadata = {"repository": repo, "pr_number": number,
                    "author": pr["user"]["login"], "commit_hash": pr["head"]["sha"]}
        body = build_comment(files.json(), metadata)

        github.post(f"{GITHUB_API}/repos/{repo}/issues/{number}/comments",
                    json={"body": body}, timeout=30).raise_for_status()
        print(f"Posted review on {repo}#{number}")
    except Exception:
        print(f"Review of {repo}#{number} failed:")
        traceback.print_exc()


@app.get("/")
def health():
    return "Webhook endpoint is up; GitHub events are accepted on POST.", 200


@app.post("/")
def github_webhook():
    if not signature_valid(request.get_data(), request.headers.get("X-Hub-Signature-256")):
        abort(401)

    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return jsonify(status="pong"), 200

    payload = request.get_json(silent=True) or {}
    if event != "pull_request" or payload.get("action") not in REVIEWED_ACTIONS:
        return jsonify(status="ignored"), 200

    # GitHub gives up on a delivery after 10 s and logs it as failed; a review
    # takes minutes. Answering first keeps that log truthful about real failures.
    threading.Thread(target=review_pull_request, args=(payload,), daemon=True).start()
    return jsonify(status="accepted"), 202


if __name__ == "__main__":
    if not WEBHOOK_SECRET or not GITHUB_TOKEN:
        raise SystemExit("Set GITHUB_TOKEN and GITHUB_WEBHOOK_SECRET - see .env.example.")
    app.run(port=3000)
