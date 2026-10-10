"""Scan a public GitHub repository from its URL, without cloning it.

1. Parse the URL into owner and repository, plus what follows `/tree/`: a branch, tag or
   commit and optionally a folder (https://github.com/owner/repo/tree/main/backend).
2. List the repository's branches and tags from git's smart-HTTP endpoint (`info/refs`, what
   `git ls-remote` reads). It names the default branch and every ref's commit, so a scan is
   pinned to one commit. api.github.com would too, but allows 60 anonymous requests an hour per
   IP, and serverless hosts share their IPs.
3. Download that commit's zip from codeload.github.com, streamed to disk under a byte cap, and
   unpack only the files a scanner reads, under the same unpacked budget as uploads.

Only github.com and codeload.github.com are contacted, at URLs built from a validated owner and
repository name, so callers can't aim the API anywhere else (SSRF). Private repositories answer
401 exactly like missing ones, so both are reported as "doesn't exist or is private".
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import httpx
from fastapi import HTTPException, status

from quantumtrace import __version__
from quantumtrace.api.uploads import CHUNK, _Budget, _extract
from quantumtrace.core.models import ScanNote, ScanResult, SourceType
from quantumtrace.scanners.code.source import EXTENSIONS as CODE_EXTENSIONS
from quantumtrace.scanners.code.source import MAX_FILE_BYTES as MAX_CODE_BYTES

SCANNER = "github"
GITHUB = "https://github.com"
CODELOAD = "https://codeload.github.com"

# What the scanners read (scanners/*). The rest of a repository stays in the zip.
SCANNED_SUFFIXES = frozenset({*CODE_EXTENSIONS, ".json", ".pcap", ".pcapng", ".cap"})
# Folders and files a repository commits but no scan should count: dependencies, build output,
# lockfiles (same lists as the web app's lib/intake.ts).
SKIPPED_DIRS = frozenset({
    "venv", "env", ".gradle", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".next",
    "dist", "build", "target", "out",
})  # fmt: skip
SKIPPED_FILES = frozenset({"package-lock.json", "npm-shrinkwrap.json"})
MAX_REFS_BYTES = 16 * 1024 * 1024

_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
_SHA = re.compile(r"[0-9a-f]{40}")
_SHORT_SHA = re.compile(r"[0-9a-fA-F]{7,40}")
_HOSTS = {"github.com", "www.github.com"}


@dataclass(frozen=True)
class RepoUrl:
    owner: str
    repo: str
    tree: tuple[str, ...] = ()  # after /tree/: a ref, then maybe a folder

    @property
    def name(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass
class Refs:
    head: str | None = None  # the commit HEAD points at
    head_branch: str | None = None
    commits: dict[str, str] = field(default_factory=dict)  # refs/heads/x -> commit


@dataclass(frozen=True)
class Commit:
    sha: str
    ref: str | None  # branch or tag; None when the URL named a commit
    folder: str  # "" for the whole repository


@dataclass(frozen=True)
class Fetched:
    root: Path  # the unpacked files, in a folder named after the repository
    label: str  # github.com/owner/repo[/folder]@abc1234, shown as the scan target
    blob_url: str  # https://github.com/owner/repo/blob/<sha>
    note: ScanNote


def github_http() -> Iterator[httpx.Client]:
    """The HTTP client for GitHub. A FastAPI dependency, so tests can swap the transport."""
    with httpx.Client(
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"User-Agent": f"quantumtrace/{__version__}"},
        follow_redirects=True,  # a renamed repository redirects to its new name
    ) as client:
        yield client


def _bad(message: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, message)


def _missing(url: RepoUrl) -> HTTPException:
    return HTTPException(
        status.HTTP_404_NOT_FOUND,
        f"github.com/{url.name} doesn't exist or is private. QuantumTrace can scan public "
        "repositories only.",
    )


def _unreachable() -> HTTPException:
    return HTTPException(
        status.HTTP_502_BAD_GATEWAY, "Couldn't reach GitHub. Try again in a moment."
    )


def parse_url(text: str) -> RepoUrl:
    """Accepts https://github.com/owner/repo[.git][/tree/<ref>[/<folder>]], the same without a
    scheme, owner/repo, and git@github.com:owner/repo.git."""
    raw = text.strip()
    if m := re.fullmatch(r"git@github\.com:(.+)", raw):
        path = m.group(1)
    else:
        if "://" not in raw:
            first = raw.split("/", 1)[0]
            raw = f"https://{raw}" if "." in first else f"{GITHUB}/{raw}"
        parts = urlsplit(raw)
        if (parts.hostname or "").lower() not in _HOSTS:
            raise _bad(
                "Only github.com repositories can be scanned. Paste a link such as "
                "https://github.com/owner/repo."
            )
        path = parts.path
    segments = [unquote(s) for s in path.split("/") if s]
    if len(segments) < 2:
        raise _bad("Paste a repository link such as https://github.com/owner/repo.")
    owner, repo, *rest = segments
    repo = repo.removesuffix(".git")
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(repo) or repo in (".", ".."):
        raise _bad(f"{owner}/{repo} isn't a valid GitHub repository name.")
    if rest and (rest[0] != "tree" or len(rest) < 2):
        raise _bad(
            "Link to the repository, or to a branch or folder in it "
            "(https://github.com/owner/repo/tree/main/src), not to a file or page."
        )
    if any(s in (".", "..") for s in rest):
        raise _bad("The folder in that link isn't valid.")
    return RepoUrl(owner, repo, tuple(rest[1:]))


def parse_refs(data: bytes) -> Refs:
    """Read a git smart-HTTP ref advertisement: pkt-lines of `<sha> <ref>`, with the server's
    capabilities (including `symref=HEAD:refs/heads/<default>`) after a NUL on the first."""
    refs = Refs()
    i = 0
    while i + 4 <= len(data):
        try:
            size = int(data[i : i + 4], 16)
        except ValueError:
            break
        if size == 0:  # flush-pkt between sections
            i += 4
            continue
        if size < 4:
            break
        line, i = data[i + 4 : i + size].rstrip(b"\n"), i + size
        if line.startswith(b"#"):  # "# service=git-upload-pack"
            continue
        head, _, caps = line.partition(b"\0")
        if m := re.search(rb"symref=HEAD:refs/heads/(\S+)", caps):
            refs.head_branch = m.group(1).decode(errors="replace")
        sha, _, name = head.decode(errors="replace").partition(" ")
        if not _SHA.fullmatch(sha) or not sha.strip("0"):  # empty repos advertise zeros
            continue
        if name == "HEAD":
            refs.head = sha
        elif name.endswith("^{}"):  # an annotated tag, peeled to the commit it tags
            refs.commits[name.removesuffix("^{}")] = sha
        else:
            refs.commits.setdefault(name, sha)
    return refs


def list_refs(http: httpx.Client, url: RepoUrl) -> Refs:
    try:
        with http.stream(
            "GET", f"{GITHUB}/{url.name}.git/info/refs", params={"service": "git-upload-pack"}
        ) as resp:
            if resp.status_code in (401, 403, 404):
                raise _missing(url)
            if resp.status_code != 200:
                raise _unreachable()
            data = bytearray()
            for chunk in resp.iter_bytes(CHUNK):
                data += chunk
                if len(data) > MAX_REFS_BYTES:
                    raise _bad(f"github.com/{url.name} has too many branches and tags to list.")
    except httpx.HTTPError as exc:
        raise _unreachable() from exc
    return parse_refs(bytes(data))


def resolve(url: RepoUrl, refs: Refs) -> Commit:
    """The commit to scan: the default branch, or the longest branch or tag the /tree/ path
    starts with (branch names may contain slashes), or a commit id."""
    if not url.tree:
        if refs.head is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"github.com/{url.name} is empty: it has no commits."
            )
        return Commit(refs.head, refs.head_branch, "")
    for n in range(len(url.tree), 0, -1):
        name = "/".join(url.tree[:n])
        for kind in ("heads", "tags"):
            if sha := refs.commits.get(f"refs/{kind}/{name}"):
                return Commit(sha, name, "/".join(url.tree[n:]))
    first = url.tree[0]
    if _SHORT_SHA.fullmatch(first):  # codeload resolves abbreviated ids; a wrong one is a 404
        return Commit(first.lower(), None, "/".join(url.tree[1:]))
    raise HTTPException(
        status.HTTP_404_NOT_FOUND, f"github.com/{url.name} has no branch or tag named {first}."
    )


def download(http: httpx.Client, url: RepoUrl, commit: Commit, dest: Path, max_bytes: int) -> None:
    too_big = HTTPException(
        status.HTTP_413_CONTENT_TOO_LARGE,
        f"github.com/{url.name} is over the {max_bytes // (1024 * 1024)} MB download limit. "
        "Clone it and run QuantumTrace locally for repositories this size.",
    )
    try:
        with http.stream("GET", f"{CODELOAD}/{url.name}/zip/{commit.sha}") as resp:
            if resp.status_code == 404:
                raise HTTPException(
                    status.HTTP_404_NOT_FOUND,
                    f"github.com/{url.name} has no commit {commit.sha}.",
                )
            if resp.status_code != 200:
                raise _unreachable()
            if int(resp.headers.get("content-length") or 0) > max_bytes:
                raise too_big
            written = 0
            with dest.open("wb") as out:
                for chunk in resp.iter_bytes(CHUNK):
                    written += len(chunk)
                    if written > max_bytes:
                        raise too_big
                    out.write(chunk)
    except httpx.HTTPError as exc:
        raise _unreachable() from exc


def fetch(
    text: str, dest: Path, http: httpx.Client, *, max_download: int, max_unpacked: int
) -> Fetched:
    """Download and unpack the scannable files of a repository into `dest/<repo>/`."""
    url = parse_url(text)
    commit = resolve(url, list_refs(http, url))
    archive = dest / f"{url.repo}.zip"
    download(http, url, commit, archive, max_download)

    folder = PurePosixPath(*commit.folder.split("/")) if commit.folder else None
    in_folder = 0

    def keep(path: PurePosixPath, size: int) -> bool:
        nonlocal in_folder
        if folder is not None:
            if path.parts[: len(folder.parts)] != folder.parts:
                return False
            in_folder += 1
        if SKIPPED_DIRS.intersection(path.parts[:-1]) or path.name in SKIPPED_FILES:
            return False
        suffix = path.suffix.lower()
        if suffix in CODE_EXTENSIONS and size > MAX_CODE_BYTES:  # the code scanner skips these
            return False
        return suffix in SCANNED_SUFFIXES

    root = dest / url.repo
    budget = _Budget(max_unpacked, max_unpacked)
    try:
        kept, total = _extract(archive, root, budget, keep=keep, strip_top=True)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_413_CONTENT_TOO_LARGE:
            raise
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"The files QuantumTrace reads in github.com/{url.name} add up to over "
            f"{max_unpacked // (1024 * 1024)} MB. Scan one folder of it "
            f"(https://github.com/{url.name}/tree/<branch>/<folder>) or run QuantumTrace locally.",
        ) from exc
    finally:
        archive.unlink(missing_ok=True)

    where = f"github.com/{url.name}" + (f"/{commit.folder}" if commit.folder else "")
    if folder is not None and not in_folder:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"{where} doesn't exist at {commit.ref or commit.sha}."
        )
    if not kept:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Nothing in {where} is something QuantumTrace reads: Python, Java or Go source, "
            "AWS JSON exports or packet captures.",
        )

    at = f"{commit.ref}, commit {commit.sha[:12]}" if commit.ref else f"commit {commit.sha}"
    scope = in_folder if folder is not None else total
    return Fetched(
        root=root,
        label=f"{where}@{commit.sha[:7]}",
        blob_url=f"{GITHUB}/{url.name}/blob/{commit.sha}",
        note=ScanNote(
            scanner=SCANNER,
            message=(
                f"Scanned {where} at {at}. QuantumTrace read {kept} of its {scope} files: "
                "Python, Java and Go source, JSON and packet captures. Dependency folders, build "
                "output and lockfiles were left out."
            ),
        ),
    )


def link_evidence(result: ScanResult, fetched: Fetched) -> None:
    """Point each code finding at its line on GitHub. Evidence locations read `<repo>/<path>`
    once relativised."""
    prefix = f"{fetched.root.name}/"
    for f in result.findings:
        for ev in f.asset.all_evidence:
            if ev.source_type is not SourceType.CODE or not ev.location.startswith(prefix):
                continue
            line = f"#L{ev.line}" if ev.line else ""
            ev.context["source_url"] = (
                f"{fetched.blob_url}/{ev.location.removeprefix(prefix)}{line}"
            )
