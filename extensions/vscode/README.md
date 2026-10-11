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
- Keeps up while you edit. With the local CLI the file is scanned again a moment after you stop
  typing, saved or not, so new code is marked and fixed code is cleared without a save. Undo and
  redo bring back the marks the text had, at once, whichever backend is used.
- Click a highlighted line, or hover it, for the explanation: the engine's rationale, the NIST
  replacement, the reference and any misuse flags such as `ecb-mode`.
- Shows what is in use. **QuantumTrace: Run tests with the runtime tracer** runs your tests
  (`quantumtrace.trace.command`) with a small Python tracer, then scans again. Above each marked
  line that ran it says so, for example "RSA-1024 · ran 14× in test_login", and the pop-up adds
  the parameters the call really used, such as the key size read off the key. Marked lines the
  run never reached are drawn fainter and say "did not run". Calls the code scan cannot see are
  found too: an algorithm named by a variable, a key size taken from configuration, or
  cryptography reached through a library. See [What is in use](#what-is-in-use).
- **Fix with AI** in that pop-up, or under Quick Fix, has the QuantumTrace API's model rewrite
  the lines around the finding and puts the rewrite in the editor. It asks first, because the
  file goes to the API and those lines on to Google's Gemini; **Always send to this API** stops
  the question for that API. Nothing is saved: review the change, or **Undo** it from the
  notification or with Ctrl+Z, and the mark is back. What the rewrite cannot do on those lines (an import, a
  library to install, callers to update) is listed under **Show what else to change**. The key
  for the model stays on the API; the extension never holds it.
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

## What is in use

The code scan says where cryptography can be. A traced run says what your code executes.

1. Set `quantumtrace.trace.command` to the command that runs your tests, one item per argument.
   The default is `["python", "-m", "pytest"]`; a leading `python` becomes the interpreter the
   Python extension has selected. It needs Python 3.12 or newer.
2. Run **QuantumTrace: Run tests with the runtime tracer**. The tests run in a terminal as
   usual. The tracer that ships with the extension goes on their `PYTHONPATH`, and writes
   `.quantumtrace/trace.jsonl` in the workspace folder.
3. The engine reads the trace with the code and the editor shows the result.

With `quantumtrace.trace.debugSessions` on, the Python debug sessions you start in VS Code are
traced the same way.

Each traced run replaces the trace of the one before. **QuantumTrace: Clear the runtime trace**
deletes it and scans again, so the marks say what the code alone says, with nothing about what
ran. To keep the trace but hide the words above the lines, turn off `quantumtrace.codeLens`.

What to know:

- **What the tracer records.** Which lines of your project ran, and each call into `hashlib`,
  `hmac` and the `cryptography` package with the algorithm, key size, curve and mode it used,
  and the test it ran in. Never a key, a message or an IV. It decides nothing: the engine
  classifies what ran with the same rules as everything else.
- **Where it stays.** On your machine with the local CLI. When scans go through the API, the
  trace file is uploaded with the sources it describes, under the consent you already gave.
- **Only what ran.** "Did not run" means the traced run never reached the line, not that the
  code is unused. Other libraries (PyCryptodome, PyNaCl) and C extensions only show as a line
  that ran, without parameters. Java and Go have no tracer yet, so their findings make no
  claim either way.
- **One run, one version of the code.** A trace describes the files as they were. Edit a file
  and its runtime evidence is left out until you run the tests again; undo the edit and it is
  back. Add `.quantumtrace/` to your `.gitignore`.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `quantumtrace.backend` | `auto` | `auto` runs the local CLI and, if none is installed, asks once before using the API. `cli` never uploads. `api` always uploads, through `@quantumtrace/sdk`. |
| `quantumtrace.cli.command` | `["quantumtrace"]` | Command that starts the CLI, one item per argument. Use absolute paths. |
| `quantumtrace.api.url` | empty | Base URL of the API, for example `http://localhost:8000`. Empty uses the API the package was built for, if any. Store a key with **QuantumTrace: Set API key**. |
| `quantumtrace.scanOnSave` | `true` | Scan on open and on save. Turn off to scan only on command. |
| `quantumtrace.scanOnType` | `true` | Scan again a moment after you stop typing, without saving. Local CLI only: unsaved text is never uploaded. |
| `quantumtrace.style` | `highlight` | `highlight` colours the whole line. `underline` underlines the call and fills the Problems panel. |
| `quantumtrace.criticalSeverity` | `error` | Set to `warning` to show Shor-vulnerable code in yellow too. |
| `quantumtrace.explainOnClick` | `true` | Open the explanation on click, not only on hover. |
| `quantumtrace.inlineHint` | `true` | Show the few words after each marked line. |
| `quantumtrace.trace.command` | `["python", "-m", "pytest"]` | The command a traced run starts in the workspace folder. Must start Python 3.12 or newer. |
| `quantumtrace.trace.debugSessions` | `false` | Also trace the Python debug sessions started in VS Code. |
| `quantumtrace.codeLens` | `true` | After a traced run, show above each marked line that ran how often it ran and in which test. |
| `quantumtrace.aiFix` | `true` | Offer **Fix with AI**. It needs an API: `quantumtrace.api.url`, or the one the package was built for. Turn off to never offer sending code to the model. |

The highlight colours follow the QuantumTrace palette (`frontend/packages/ui/src/tokens.css`): crimson for
Shor, ochre for Grover. Override them under `workbench.colorCustomizations` with
`quantumtrace.criticalLineBackground`, `quantumtrace.mediumLineBackground` and
`quantumtrace.unknownLineBackground`.

In an untrusted workspace the first three and the two `quantumtrace.trace.*` settings are read
from user settings only, so a repository cannot choose which command runs or where code is
sent. A traced run executes the folder's tests, so it only starts in a trusted workspace.

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
- The Python tracer has one source, `backend/src/quantumtrace/tracers/python`. `build.mjs`
  copies it to `tracer/python` (not committed), which the package ships and a traced run puts
  on `PYTHONPATH` (`src/runtime.ts`). The engine merges the trace with the code scan
  (`scanners/runtime`): `evidence.execution` on each place, and `observation: "executed"`.
- The engine reports a line per finding, not a column. In the `underline` style the underline
  covers the observed call when it appears on that line verbatim, otherwise the whole line.
- The engine reads files, so to scan unsaved edits the CLI is given a copy of the editor's text
  in the temporary folder, deleted right after (`cliEngine.scanText`). The API is never sent
  unsaved text: there the marks follow the text as you type and are refreshed on save.
- `src/history.ts` remembers the marks of each text a file has read as since its last scans, so
  an undo or redo restores them without the engine.
- **Fix with AI** uploads the file as it reads in the editor, saved or not, asks
  `POST /scans/{id}/findings/{fid}/fix` for the matching finding and deletes that scan again
  (`src/fix.ts`). The engine merges repeats of the same code in a file into one finding and the
  API fixes its first place, so on a later place the extension offers to fix the first one. A
  rewrite is applied only when the lines still read as the API saw them.
- Only source-code findings are shown. Cloud exports and packet captures in the workspace are
  scanned by the engine but have no editor lines to mark.
