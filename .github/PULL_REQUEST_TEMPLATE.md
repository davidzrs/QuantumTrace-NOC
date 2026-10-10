## What & why

<!-- One or two sentences. Link the issue / challenge requirement this addresses. -->

## Type

- [ ] `feat`: new capability
- [ ] `detect`: new or improved detection (scanner)
- [ ] `rules`: algorithm / tier / FIPS mapping change (`rules/*.yaml`)
- [ ] `fix`: bug fix
- [ ] `refactor` / `perf` / `test` / `docs` / `ci` / `chore`

## Areas touched

- [ ] Engine (`core/`: models, classifier, scoring)
- [ ] Scanners: [ ] cloud  [ ] code  [ ] network
- [ ] CBOM export
- [ ] API / CLI
- [ ] Web app / shared UI
- [ ] SDK (`frontend/packages/sdk`)
- [ ] Extensions (VS Code / browser)
- [ ] Infra (Docker, Fly, Vercel, workflows)

## Detection impact

<!-- Required for `detect` / `rules` PRs; delete otherwise. Judges weigh accuracy at 40%. -->

| Sample / input | Before | After |
| --- | --- | --- |
| e.g. `samples/cloud-posture` | 25 critical / 11 medium / 33 safe | … |

- Algorithms added or re-tiered:
- NIST mapping (FIPS 203/204/205, IR 8547) checked: [ ] yes
- False-positive risk and how it's mitigated:

## How I tested

- [ ] `make test`
- [ ] `make lint`
- [ ] `uv run quantumtrace scan ../samples` output looks right
- [ ] UI checked in the browser (attach screenshots below for UI changes)

## Checklist

- [ ] Every new detection has a golden test against `samples/`
- [ ] No classification logic outside `core/` + `rules/` (clients stay thin)
- [ ] API changed → ran `make gen-sdk` and committed the SDK diff
- [ ] No secrets, tokens or absolute server paths in responses or logs
- [ ] Docs / skills updated if workflows changed (`.claude/`)

## Screenshots

<!-- UI changes only -->
