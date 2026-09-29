"""Webhook, comment and report checks - no LLM, no network.

    python test_app.py
"""
import hashlib
import hmac
import json
import os
from unittest import mock

os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
os.environ["GITHUB_TOKEN"] = "test-token"

import app  # noqa: E402  - the secret must be in the environment before import
from graph import generate_final_review  # noqa: E402

PR = {
    "action": "opened",
    "repository": {"full_name": "owner/repo"},
    "pull_request": {"number": 7, "head": {"sha": "abc1234def"}, "user": {"login": "dev"}},
}


def _post(event: str, payload: dict, signature: str | None = None):
    body = json.dumps(payload).encode()
    good = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    return app.app.test_client().post("/", data=body, headers={
        "X-GitHub-Event": event,
        "X-Hub-Signature-256": good if signature is None else signature,
        "Content-Type": "application/json",
    })


def test_rejects_unsigned_and_forged_requests():
    assert _post("pull_request", PR, signature="").status_code == 401
    assert _post("pull_request", PR, signature="sha256=" + "0" * 64).status_code == 401


def test_ping_and_irrelevant_events_do_not_start_a_review():
    with mock.patch.object(app.threading, "Thread") as thread:
        assert _post("ping", {}).status_code == 200
        assert _post("push", {}).status_code == 200
        assert _post("pull_request", dict(PR, action="closed")).status_code == 200
    thread.assert_not_called()


def test_pull_request_is_accepted_and_reviewed_in_the_background():
    with mock.patch.object(app.threading, "Thread") as thread:
        assert _post("pull_request", PR).status_code == 202
    assert thread.call_args.kwargs["target"] is app.review_pull_request
    thread.return_value.start.assert_called_once()


def test_one_failing_file_does_not_cost_the_others():
    files = [
        {"filename": "ok.py", "patch": "+x = 1"},
        {"filename": "loop.py", "patch": "+y = 2"},
        {"filename": "logo.png"},  # binary: GitHub sends no patch
    ]

    def fake_review(raw_diff, pr_metadata):
        if "y = 2" in raw_diff:
            raise ValueError("repetition loop")
        return "**Verdict:** APPROVED"

    with mock.patch.object(app, "run_review", side_effect=fake_review):
        body = app.build_comment(files, {"commit_hash": "abc1234def"})
    assert "`abc1234`" in body
    assert "### `ok.py`" in body and "**Verdict:** APPROVED" in body
    assert "### `loop.py`" in body and "Review failed" in body
    assert "logo.png" not in body


def test_review_is_posted_as_one_comment_on_the_pull_request():
    github = mock.MagicMock()
    github.get.return_value.json.return_value = [{"filename": "a.py", "patch": "+a = 1"}]
    with mock.patch.object(app.requests, "Session", return_value=github), \
         mock.patch.object(app, "run_review", return_value="**Verdict:** APPROVED"):
        app.review_pull_request(PR)
    assert github.post.call_count == 1
    assert github.post.call_args.args[0].endswith("/repos/owner/repo/issues/7/comments")
    assert "a.py" in github.post.call_args.kwargs["json"]["body"]


def test_report_renders_as_github_markdown():
    report = generate_final_review({
        "pr_context": {"primary_language": "Python", "core_concept": "SQL Query"},
        "security_findings": [
            {"severity": "LOW", "line_number": 9, "description": "Verbose error", "fix": "Log it"},
            {"severity": "CRITICAL", "line_number": 4, "description": "SQL injection", "fix": "Parameterise"},
        ],
        "static_findings": [],
    })["final_review"]
    assert report.index("**CRITICAL**") < report.index("**LOW**"), "sorted by severity"
    assert "\n   - **Fix:** Parameterise" in report, "fix nested under its finding"
    assert "CHANGES REQUESTED" in report








if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
            print("ok ", name)
