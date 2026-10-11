# QuantumTrace for VS Code

Highlights quantum-vulnerable cryptography in Python, Java and Go files, explains each finding
and says what to migrate to.

It is a thin client. Every tier, rationale and replacement comes from the engine
(`backend/src/quantumtrace/rules/`); nothing is classified here.

## What it does

- Scans a file when you open or save it. Lines with Grover-weakened code (`medium`) are
  highlighted in yellow, lines with Shor-vulnerable code (`critical`) in red. A line with both is
  red. Resilient algorithms are not marked. A few words after the code say what is wrong, for
  example "RSA-1024: broken by Shor's algorithm".
- Click a highlighted line, or hover it, for the explanation: the engine's rationale, the NIST
  replacement, the reference and any misuse flags such as `ecb-mode`.
- **Dismiss warning** in that pop-up, or under Quick Fix, hides one finding. Dismissals are kept
  per workspace and listed under **Dismissed warnings** in the QuantumTrace side bar: click one to
  open its line, or restore it from there. **QuantumTrace: Restore dismissed warnings** brings
  them all back.
- **QuantumTrace: Scan workspace** scans the whole folder. With `quantumtrace.style` set to
  `underline` it also lists every finding in the Problems panel; VS Code only lists what is
  underlined, so the default `highlight` style has no such list.

## Install

Download `quantumtrace-vscode.vsix` from the QuantumTrace web app, then in VS Code open the
Extensions view, pick **Install from VSIX…** in its `...` menu and choose the file.

The extension runs the QuantumTrace CLI on your machine. If it finds none, it asks once whether
it may scan through the API that web app uses, and names the address your files would go to.
"Keep it local" is remembered too; change either answer with `quantumtrace.backend`.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `quantumtrace.backend` | `auto` | `auto` runs the local CLI and, if none is installed, asks once before using the API. `cli` never uploads. `api` always uploads, through `@quantumtrace/sdk`. |
| `quantumtrace.cli.command` | `["quantumtrace"]` | Command that starts the CLI, one item per argument. Use absolute paths. |
| `quantumtrace.api.url` | empty | Base URL of the API, for example `http://localhost:8000`. Empty uses the API the package was built for, if any. Store a key with **QuantumTrace: Set API key**. |
| `quantumtrace.scanOnSave` | `true` | Scan on open and on save. Turn off to scan only on command. |
| `quantumtrace.style` | `highlight` | `highlight` colours the whole line. `underline` underlines the call and fills the Problems panel. |
| `quantumtrace.criticalSeverity` | `error` | Set to `warning` to show Shor-vulnerable code in yellow too. |
| `quantumtrace.explainOnClick` | `true` | Open the explanation on click, not only on hover. |
| `quantumtrace.inlineHint` | `true` | Show the few words after each marked line. |

The highlight colours follow the QuantumTrace palette (`frontend/packages/ui/src/tokens.css`): crimson for
Shor, ochre for Grover. Override them under `workbench.colorCustomizations` with
`quantumtrace.criticalLineBackground`, `quantumtrace.mediumLineBackground` and
`quantumtrace.unknownLineBackground`.

In an untrusted workspace the first three are read from user settings only, so a repository
cannot choose which command runs or where code is sent.

## Run it from this repository

```sh
pnpm install
pnpm -F quantumtrace-vscode build
```

Then press F5 in VS Code and pick **Run QuantumTrace extension**. A second window opens on
`samples/sample-repos` with the extension loaded.

That window needs an engine. Point `quantumtrace.cli.command` (user settings) at the backend's
CLI with an absolute path, for example:

```json
"quantumtrace.cli.command": ["C:/path/to/repo/backend/.venv/Scripts/quantumtrace.exe"]
```

`pnpm -F quantumtrace-vscode package` builds a `.vsix` you can install with
`code --install-extension`.

## Notes for contributors

- This folder is a member of the pnpm workspace (`extensions/*` in `pnpm-workspace.yaml`), so it
  shares the lockfile, `frontend/tsconfig.base.json` and `@quantumtrace/sdk`.
- The package is named `quantumtrace-vscode`, not `@quantumtrace/...`: VS Code extension names
  cannot be scoped.
- Only `src/extension.ts` and `src/dismissedView.ts` import `vscode`. The rest is plain TypeScript
  with tests next to it (`pnpm -F quantumtrace-vscode test`).
- The engine reports a line per finding, not a column. In the `underline` style the underline
  covers the observed call when it appears on that line verbatim, otherwise the whole line.
- The engine reads files from disk, so unsaved edits are scanned on the next save. Until then
  the marks follow the text as you type.
- Only source-code findings are shown. Cloud exports and packet captures in the workspace are
  scanned by the engine but have no editor lines to mark.
