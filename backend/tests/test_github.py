"""Scanning a GitHub repository by URL, against a fake GitHub (no network)."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from quantumtrace.api import github
from quantumtrace.api.app import create_app
from quantumtrace.api.settings import Settings, get_settings

SHA = "672971d66a2ef9f85151e53283113f33d642dabd"
BRANCH_SHA = "1111111111111111111111111111111111111111"
TAG_OBJECT = "2222222222222222222222222222222222222222"
TAG_COMMIT = "3333333333333333333333333333333333333333"


def pkt(line: bytes) -> bytes:
    return f"{len(line) + 4:04x}".encode() + line


def advertisement(refs: dict[str, str], head_branch: str = "main") -> bytes:
    """A git smart-HTTP ref advertisement, as github.com serves it."""
    out = pkt(b"# service=git-upload-pack\n") + b"0000"
    for i, (name, sha) in enumerate(refs.items()):
        caps = f"\0multi_ack symref=HEAD:refs/heads/{head_branch} agent=git/x" if i == 0 else ""
        out += pkt(f"{sha} {name}{caps}\n".encode())
    return out + b"0000"


REFS = {
    "HEAD": SHA,
    "refs/heads/main": SHA,
    "refs/heads/feature/pq": BRANCH_SHA,
    "refs/tags/v1.0": TAG_OBJECT,
    "refs/tags/v1.0^{}": TAG_COMMIT,
}


def repo_zip(samples: Path, sha: str = SHA, extra: dict[str, bytes] | None = None) -> bytes:
    """What codeload serves: every file under one `<repo>-<sha>/` folder."""
    files = {
        "python/license_token.py": (samples / "sample-repos/python/license_token.py").read_bytes(),
        "java/ReceiptSigner.java": (samples / "sample-repos/java/ReceiptSigner.java").read_bytes(),
        "README.md": b"# vault\n",
        "docs/logo.png": b"\x89PNG" + b"\x00" * 64,
        "node_modules/dep/index.py": b"import hashlib\nhashlib.md5(b'')\n",
        "build/generated.py": b"import hashlib\nhashlib.md5(b'')\n",
        "web/package-lock.json": b'{"Keys": []}',
        **(extra or {}),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(f"vault-{sha}/{name}", data)
    return buf.getvalue()


Handler = Callable[[httpx.Request], httpx.Response]


def fake_github(archive: bytes, *, seen: list[str] | None = None) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(f"{request.url.host}{request.url.path}")
        if request.url.host == "github.com" and request.url.path == "/acme/vault.git/info/refs":
            return httpx.Response(200, content=advertisement(REFS))
        if request.url.host == "github.com":  # missing and private repos look alike: 401
            return httpx.Response(401)
        if request.url.path in {f"/acme/vault/zip/{s}" for s in (SHA, BRANCH_SHA, TAG_COMMIT)}:
            return httpx.Response(200, content=archive)
        return httpx.Response(404)

    return handler


def make_client(handler: Handler, samples: Path, **settings: object) -> TestClient:
    config = Settings(samples_dir=samples, **settings)  # type: ignore[arg-type]
    app = create_app(config)

    def http() -> Iterator[httpx.Client]:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            yield client

    app.dependency_overrides[get_settings] = lambda: config
    app.dependency_overrides[github.github_http] = http
    return TestClient(app)


def scan(client: TestClient, url: str) -> httpx.Response:
    res: httpx.Response = client.post("/api/v1/scans/github", json={"url": url})
    return res


# --- URL parsing --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "owner", "repo", "tree"),
    [
        ("https://github.com/acme/vault", "acme", "vault", ()),
        ("https://github.com/acme/vault/", "acme", "vault", ()),
        ("http://www.github.com/acme/vault.git", "acme", "vault", ()),
        ("github.com/acme/vault?tab=readme#top", "acme", "vault", ()),
        ("acme/vault", "acme", "vault", ()),
        ("git@github.com:acme/vault.git", "acme", "vault", ()),
        ("https://github.com/acme/vault/tree/feature/pq/src", "acme", "vault",
         ("feature", "pq", "src")),
    ],
)  # fmt: skip
def test_parse_url(text: str, owner: str, repo: str, tree: tuple[str, ...]) -> None:
    assert github.parse_url(text) == github.RepoUrl(owner, repo, tree)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("https://gitlab.com/acme/vault", "Only github.com"),
        ("https://github.com/acme", "Paste a repository link"),
        ("https://github.com/acme/vault/blob/main/app.py", "not to a file"),
        ("https://github.com/acme/vault/issues", "not to a file"),
        ("https://github.com/-acme/vault", "isn't a valid"),
        ("https://github.com/acme/vault/tree/main/../secrets", "folder"),
    ],
)
def test_parse_url_rejects(text: str, message: str) -> None:
    with pytest.raises(HTTPException) as exc:
        github.parse_url(text)
    assert exc.value.status_code == 400
    assert message in exc.value.detail


# --- refs ---------------------------------------------------------------------------------
def test_parse_refs_reads_head_default_branch_and_peeled_tags() -> None:
    refs = github.parse_refs(advertisement(REFS))
    assert (refs.head, refs.head_branch) == (SHA, "main")
    assert refs.commits["refs/heads/feature/pq"] == BRANCH_SHA
    assert refs.commits["refs/tags/v1.0"] == TAG_COMMIT  # the commit, not the tag object


def test_parse_refs_empty_repository() -> None:
    empty = advertisement({"capabilities^{}": "0" * 40})
    assert github.parse_refs(empty).head is None


@pytest.mark.parametrize(
    ("tree", "sha", "ref", "folder"),
    [
        ((), SHA, "main", ""),
        (("main",), SHA, "main", ""),
        (("feature", "pq", "src", "app"), BRANCH_SHA, "feature/pq", "src/app"),
        (("v1.0",), TAG_COMMIT, "v1.0", ""),
        (("672971D", "java"), "672971d", None, "java"),
    ],
)
def test_resolve(tree: tuple[str, ...], sha: str, ref: str | None, folder: str) -> None:
    refs = github.parse_refs(advertisement(REFS))
    assert github.resolve(github.RepoUrl("acme", "vault", tree), refs) == github.Commit(
        sha, ref, folder
    )


def test_resolve_unknown_branch_is_404() -> None:
    refs = github.parse_refs(advertisement(REFS))
    with pytest.raises(HTTPException) as exc:
        github.resolve(github.RepoUrl("acme", "vault", ("nope",)), refs)
    assert exc.value.status_code == 404
    assert "no branch or tag named nope" in exc.value.detail


# --- through the API ----------------------------------------------------------------------
def test_scan_repository_pins_commit_and_links_lines(samples: Path) -> None:
    seen: list[str] = []
    client = make_client(fake_github(repo_zip(samples), seen=seen), samples)
    res = scan(client, "https://github.com/acme/vault")
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["targets"] == [f"github.com/acme/vault@{SHA[:7]}"]
    assert seen == [
        "github.com/acme/vault.git/info/refs",
        f"codeload.github.com/acme/vault/zip/{SHA}",
    ]

    files = {f["asset"]["evidence"]["location"] for f in body["findings"]}
    assert files == {"vault/python/license_token.py", "vault/java/ReceiptSigner.java"}
    names = {f["classification"]["name"] for f in body["findings"]}
    assert {"RSA-1024", "SHA-1"} <= names

    [keygen] = [
        f for f in body["findings"]
        if f["asset"]["usage"] == "key-generation"
        and f["asset"]["evidence"]["location"].endswith(".py")
    ]  # fmt: skip
    assert keygen["asset"]["evidence"]["context"]["source_url"] == (
        f"https://github.com/acme/vault/blob/{SHA}/python/license_token.py#L6"
    )
    note = body["limitations"][0]
    assert note["scanner"] == "github"
    assert "main, commit 672971d66a2e" in note["message"]
    assert "read 2 of its 7 files" in note["message"]  # node_modules, build/, lockfile left out
    assert client.get(f"/api/v1/scans/{body['id']}").status_code == 200  # saved for the report


def test_scan_folder_of_a_branch(samples: Path) -> None:
    client = make_client(fake_github(repo_zip(samples, BRANCH_SHA)), samples)
    res = scan(client, "https://github.com/acme/vault/tree/feature/pq/java")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["targets"] == [f"github.com/acme/vault/java@{BRANCH_SHA[:7]}"]
    files = {f["asset"]["evidence"]["location"] for f in body["findings"]}
    assert files == {"vault/java/ReceiptSigner.java"}


def test_missing_folder_is_404(samples: Path) -> None:
    client = make_client(fake_github(repo_zip(samples)), samples)
    res = scan(client, "https://github.com/acme/vault/tree/main/does-not-exist")
    assert res.status_code == 404
    assert "doesn't exist at main" in res.json()["detail"]


def test_private_or_missing_repository_is_404(samples: Path) -> None:
    client = make_client(fake_github(repo_zip(samples)), samples)
    res = scan(client, "https://github.com/acme/secret")
    assert res.status_code == 404
    assert "doesn't exist or is private" in res.json()["detail"]


def test_bad_url_is_400(samples: Path) -> None:
    client = make_client(fake_github(repo_zip(samples)), samples)
    assert scan(client, "https://gitlab.com/acme/vault").status_code == 400


def test_github_unreachable_is_502(samples: Path) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    res = scan(make_client(down, samples), "https://github.com/acme/vault")
    assert res.status_code == 502
    assert "Couldn't reach GitHub" in res.json()["detail"]


def test_download_over_limit_is_413(samples: Path) -> None:
    big = repo_zip(samples, extra={"blob.bin": bytes(range(256)) * 8192})  # 2 MB, stored as-is
    client = make_client(fake_github(big), samples, max_repo_mb=1)
    res = scan(client, "https://github.com/acme/vault")
    assert res.status_code == 413
    assert "1 MB download limit" in res.json()["detail"]


def test_unpacked_over_limit_suggests_a_folder(samples: Path) -> None:
    big = repo_zip(samples, extra={"data/huge.json": b"[" + b"0," * 700_000 + b"0]"})
    client = make_client(fake_github(big), samples, max_unpacked_mb=1)
    res = scan(client, "https://github.com/acme/vault")
    assert res.status_code == 413
    assert "Scan one folder of it" in res.json()["detail"]


def test_nothing_scannable_is_422(samples: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"vault-{SHA}/README.md", b"# docs only\n")
    client = make_client(fake_github(buf.getvalue()), samples)
    res = scan(client, "https://github.com/acme/vault")
    assert res.status_code == 422
    assert "Nothing in github.com/acme/vault" in res.json()["detail"]


def test_needs_api_key_when_configured(samples: Path) -> None:
    client = make_client(fake_github(repo_zip(samples)), samples, api_key="s3cret")
    assert scan(client, "https://github.com/acme/vault").status_code == 401


def test_health_advertises_repo_limit(samples: Path) -> None:
    client = make_client(fake_github(b""), samples, max_repo_mb=150)
    assert client.get("/api/v1/health").json()["max_repo_mb"] == 150
