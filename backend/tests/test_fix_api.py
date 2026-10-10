from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from google.genai import errors as genai_errors
from google.genai import types

from quantumtrace.ai import fixer
from quantumtrace.ai.fixer import FixSuggestion, build_prompt, same_file, suggest_fix
from quantumtrace.api.app import create_app
from quantumtrace.api.settings import Settings, get_settings
from quantumtrace.api.v1 import routes
from quantumtrace.core.models import Finding


def _client(samples: Path, key: str | None) -> TestClient:
    settings = Settings(samples_dir=samples, gemini_api_key=key)
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def _scan(client: TestClient, sample: str) -> dict[str, Any]:
    res = client.post("/api/v1/scans/sample", json={"sample": sample})
    assert res.status_code == 200
    body: dict[str, Any] = res.json()
    return body


@pytest.fixture(autouse=True)
def _no_cache() -> None:
    routes._fixes.clear()


def test_health_reports_ai_fix(samples: Path) -> None:
    assert _client(samples, None).get("/api/v1/health").json()["ai_fix"] is False
    assert _client(samples, "sk-test").get("/api/v1/health").json()["ai_fix"] is True


def test_fix_off_without_key(samples: Path) -> None:
    client = _client(samples, None)
    scan = _scan(client, "sample-repos")
    fid = scan["findings"][0]["id"]
    res = client.post(f"/api/v1/scans/{scan['id']}/findings/{fid}/fix")
    assert res.status_code == 503
    assert "GEMINI_API_KEY" in res.json()["detail"]


def test_fix_unknown_finding_404(samples: Path) -> None:
    client = _client(samples, "sk-test")
    scan = _scan(client, "sample-repos")
    assert client.post(f"/api/v1/scans/{scan['id']}/findings/nope/fix").status_code == 404
    assert client.post("/api/v1/scans/nope/findings/nope/fix").status_code == 404


def test_fix_rejects_network_finding(samples: Path) -> None:
    client = _client(samples, "sk-test")
    scan = _scan(client, "network-capture")
    fid = scan["findings"][0]["id"]
    assert client.post(f"/api/v1/scans/{scan['id']}/findings/{fid}/fix").status_code == 422


def test_fix_code_finding(samples: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake(finding: Finding, **_: Any) -> FixSuggestion:
        calls.append(finding.id)
        return FixSuggestion(
            finding_id=finding.id,
            summary="Use AES-256-GCM",
            original_snippet=finding.asset.evidence.snippet or "",
            fixed_snippet="fixed",
            changed=True,
            snippet_start_line=finding.asset.evidence.snippet_start_line or 1,
            explanation="because",
            model="stub",
        )

    monkeypatch.setattr(routes, "suggest_fix", fake)
    client = _client(samples, "sk-test")
    scan = _scan(client, "sample-repos")
    fid = scan["findings"][0]["id"]
    url = f"/api/v1/scans/{scan['id']}/findings/{fid}/fix"
    body = client.post(url).json()
    assert (body["finding_id"], body["fixed_snippet"], body["caveats"]) == (fid, "fixed", [])
    client.post(url)
    assert calls == [fid]  # the second click is served from the cache


def _ecb_finding(samples: Path) -> Finding:
    client = _client(samples, None)
    scan = _scan(client, "sample-repos")
    found = [
        f
        for f in scan["findings"]
        if "ecb" in " ".join(f["asset"]["flags"]).lower() and f["asset"]["evidence"]["snippet"]
    ]
    assert found, "expected an ECB finding in sample-repos"
    return Finding.model_validate(found[0])


def test_prompt_marks_line_and_carries_classification(samples: Path) -> None:
    f = _ecb_finding(samples)
    prompt = build_prompt(f)
    flagged = [line for line in prompt.splitlines() if line.startswith(">>")]
    assert len(flagged) == 1 and f" {f.asset.evidence.line} |" in flagged[0]
    assert f.classification.name in prompt
    assert any(flag in prompt for flag in f.asset.flags)
    if f.classification.replacement:
        assert f.classification.replacement in prompt


def _gemini(parsed: Any, finish: str = "STOP") -> tuple[SimpleNamespace, dict[str, Any]]:
    seen: dict[str, Any] = {}

    def generate_content(**kwargs: Any) -> SimpleNamespace:
        seen.update(kwargs)
        candidate = SimpleNamespace(finish_reason=types.FinishReason(finish))
        return SimpleNamespace(parsed=parsed, candidates=[candidate], model_version="gemini-x")

    return SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)), seen


def test_suggest_fix_maps_structured_output(samples: Path) -> None:
    f = _ecb_finding(samples)
    draft = fixer._Draft(summary="s", fixed_snippet="\nnew\n", explanation="e", caveats=["c"])
    client, seen = _gemini(draft)
    fix = suggest_fix(f, api_key="k", model="gemini-2.5-flash", client=client)
    assert (fix.fixed_snippet, fix.caveats, fix.model) == ("new", ["c"], "gemini-x")
    assert fix.original_snippet == f.asset.evidence.snippet
    assert seen["config"].response_schema is fixer._Draft
    assert seen["config"].response_mime_type == "application/json"
    assert seen["config"].thinking_config is None
    suggest_fix(f, api_key="k", model="m", thinking="low", client=client)
    thinking = seen["config"].thinking_config
    assert thinking is not None and thinking.thinking_level == types.ThinkingLevel.LOW


def test_suggest_fix_without_output(samples: Path) -> None:
    f = _ecb_finding(samples)
    with pytest.raises(fixer.FixUnavailable, match="cut short"):
        suggest_fix(f, api_key="k", model="m", client=_gemini(None, "MAX_TOKENS")[0])
    same = fixer._Draft(
        summary="s", fixed_snippet=f.asset.evidence.snippet or "", explanation="e", caveats=[]
    )
    with pytest.raises(fixer.FixUnavailable, match="didn't change"):
        suggest_fix(f, api_key="k", model="m", client=_gemini(same)[0])
    elsewhere = same.model_copy(update={"caveats": ['import "crypto/rand"']})
    fix = suggest_fix(f, api_key="k", model="m", client=_gemini(elsewhere)[0])
    assert fix.changed is False and fix.caveats == ['import "crypto/rand"']
    with pytest.raises(fixer.FixUnavailable, match="no usable fix"):
        suggest_fix(f, api_key="k", model="m", client=_gemini(None, "SAFETY")[0])


def test_fix_maps_gemini_rate_limit(samples: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def limited(*_: Any, **__: Any) -> FixSuggestion:
        raise genai_errors.ClientError(429, {"error": {"message": "quota"}})

    monkeypatch.setattr(routes, "suggest_fix", limited)
    client = _client(samples, "k")
    scan = _scan(client, "sample-repos")
    fid = scan["findings"][0]["id"]
    res = client.post(f"/api/v1/scans/{scan['id']}/findings/{fid}/fix")
    assert res.status_code == 429 and "free-tier" in res.json()["detail"]


def test_prompt_lists_other_crypto_in_the_file(samples: Path) -> None:
    client = _client(samples, None)
    findings = [Finding.model_validate(f) for f in _scan(client, "sample-repos")["findings"]]
    keygen = next(
        f
        for f in findings
        if f.asset.usage == "key-generation"
        and f.asset.evidence.location.endswith("invoice-service/main.go")
    )
    prompt = build_prompt(keygen, same_file(keygen, findings))
    assert "Other crypto in this file" in prompt
    assert "rsa.SignPKCS1v15" in prompt and "usage: signature" in prompt


def test_reindent_is_not_a_fix() -> None:
    assert fixer._same_code("if x:\n    return y", "if x:\n\treturn y\n")
    assert not fixer._same_code("rand.Read(b)", "crand.Read(b)")


def test_copied_line_numbers_are_stripped() -> None:
    echoed = '   11 | void f() {\n>> 12 |     g("ML-DSA-65");\n   13 | }'
    assert fixer._strip_gutter(echoed) == 'void f() {\n    g("ML-DSA-65");\n}'
    plain = "x = 1 | 2\ny = 3"
    assert fixer._strip_gutter(plain) == plain
