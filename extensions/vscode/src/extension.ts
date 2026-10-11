/** VS Code wiring: scan with the engine, underline the findings, explain, fix and dismiss them. */
import { existsSync, rmSync, statSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import type { Finding, FixSuggestion } from "@quantumtrace/sdk";
import { ApiConsent, originOf } from "./consent";
import { dismissed, Dismissals, type DismissedRow } from "./dismissals";
import { DismissedView, fileKey, uriOf } from "./dismissedView";
import {
  apiEngine,
  autoEngine,
  cliEngine,
  DEFAULT_API_URL,
  type Engine,
  EngineError,
  type Scan,
} from "./engine";
import {
  commandLink,
  explanation,
  headline,
  inlineHint,
  label,
  lensTitle,
  type Tone,
} from "./explain";
import { EarlierPlaceError, linesLabel, replacement, report, requestFix } from "./fix";
import { MarkHistory } from "./history";
import { findProgram, sameFile, traceFile, tracerEnvironment } from "./runtime";
import {
  applyEdits,
  mostSevereFirst,
  occurrenceKey,
  occurrences,
  type Occurrence,
} from "./occurrences";

const SOURCE = "QuantumTrace";
const DISMISS = "quantumtrace.dismiss";
const FIX = "quantumtrace.fix";
const EXPLAIN = "quantumtrace.explain";
const API_KEY_SECRET = "quantumtrace.apiKey";
const EXTENSIONS = new Set([".py", ".java", ".go"]);
/** How long the typing must pause before the file is scanned again, in milliseconds. */
const SETTLE_MS = 400;
const SELECTOR: vscode.DocumentSelector = { scheme: "file", pattern: "**/*.{py,java,go}" };

/** The pop-up takes the colour of the line it explains. */
const TONES: Record<vscode.DiagnosticSeverity, Tone> = {
  [vscode.DiagnosticSeverity.Error]: "critical",
  [vscode.DiagnosticSeverity.Warning]: "medium",
  [vscode.DiagnosticSeverity.Information]: "unknown",
  [vscode.DiagnosticSeverity.Hint]: "unknown",
};

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("quantumtrace");
  const log = vscode.window.createOutputChannel("QuantumTrace");
  const dismissals = new Dismissals(context.workspaceState);
  // per user, not per folder: it is about where this person's code may be sent
  const consent = new ApiConsent(context.globalState);
  /** Questions still open in this window, by API origin, so each is asked once. */
  const asking = new Map<string, Promise<boolean>>();
  // a separate answer: an AI fix also sends the flagged lines on to the model's provider
  const aiConsent = new ApiConsent(context.globalState, "quantumtrace.aiFixConsent");
  /** Files with a fix on its way, by URI: one at a time, so a rewrite never lands on moved lines. */
  const fixing = new Set<string>();
  const dismissedView = new DismissedView(dismissals);
  const dismissedTree = vscode.window.createTreeView("quantumtrace.dismissed", {
    treeDataProvider: dismissedView,
  });
  /** Redraws the list of dismissed warnings and its count on the QuantumTrace icon. */
  const refreshDismissed = () => {
    const count = dismissals.count();
    dismissedView.refresh();
    dismissedTree.badge = count
      ? { value: count, tooltip: plural(count, "dismissed warning") }
      : undefined;
  };
  /** Every occurrence from the latest scan of each file (by URI), dismissed ones included. */
  const found = new Map<string, Occurrence[]>();
  /** The marks each file had for the texts it has read as: an undo gets them back at once. */
  const history = new MarkHistory();
  /** Files edited a moment ago, by URI: each is scanned again once the typing pauses. */
  const settling = new Map<string, ReturnType<typeof setTimeout>>();
  let lastFailure = "";

  const lineStyle = (tier: string, ruler: string, quiet = false) =>
    vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      backgroundColor: new vscode.ThemeColor(
        `quantumtrace.${tier}${quiet ? "Idle" : ""}LineBackground`,
      ),
      overviewRulerColor: quiet ? undefined : new vscode.ThemeColor(ruler),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    });
  /** Whole-line colours by severity, for the "highlight" style. */
  const lineStyles: [vscode.DiagnosticSeverity, vscode.TextEditorDecorationType][] = [
    [vscode.DiagnosticSeverity.Error, lineStyle("critical", "editorOverviewRuler.errorForeground")],
    [vscode.DiagnosticSeverity.Warning, lineStyle("medium", "editorOverviewRuler.warningForeground")],
    [vscode.DiagnosticSeverity.Information, lineStyle("unknown", "editorOverviewRuler.infoForeground")],
  ];
  /** The same colours, fainter: lines a traced run of the tests never reached. */
  const idleStyles: [vscode.DiagnosticSeverity, vscode.TextEditorDecorationType][] = [
    [vscode.DiagnosticSeverity.Error, lineStyle("critical", "", true)],
    [vscode.DiagnosticSeverity.Warning, lineStyle("medium", "", true)],
    [vscode.DiagnosticSeverity.Information, lineStyle("unknown", "", true)],
  ];
  /** Tells VS Code the words above the lines that ran have changed. */
  const lensesChanged = new vscode.EventEmitter<void>();
  /** Where the tracer that ships with the extension lives: it goes on the traced run's PYTHONPATH. */
  const tracerFolder = path.join(context.extensionPath, "tracer", "python");
  /** The traced run in progress, if any: its task and the folder it runs in. */
  let tracing: { execution: vscode.TaskExecution; root: string; command: string } | undefined;
  const hintStyle = (tier: string) =>
    vscode.window.createTextEditorDecorationType({
      after: {
        color: new vscode.ThemeColor(`quantumtrace.${tier}Foreground`),
        margin: "0 0 0 3ch",
        fontStyle: "italic",
      },
    });
  /** The few words after the code of a marked line, in the line's risk colour. */
  const hintStyles: [vscode.DiagnosticSeverity, vscode.TextEditorDecorationType][] = [
    [vscode.DiagnosticSeverity.Error, hintStyle("critical")],
    [vscode.DiagnosticSeverity.Warning, hintStyle("medium")],
    [vscode.DiagnosticSeverity.Information, hintStyle("unknown")],
  ];

  const setting = <T>(name: string, fallback: T): T =>
    vscode.workspace.getConfiguration("quantumtrace").get<T>(name, fallback);
  const underlined = () => setting<string>("style", "highlight") === "underline";
  const isSource = (uri: vscode.Uri) =>
    uri.scheme === "file" && EXTENSIONS.has(path.extname(uri.fsPath).toLowerCase());
  const shown = (uri: vscode.Uri) =>
    (found.get(uri.toString()) ?? []).filter((o) => !dismissals.has(fileKey(uri), o.key));
  /** Findings under a position, most severe first: the underlined call, or anywhere on a
   * highlighted line. */
  const at = (uri: vscode.Uri, position: vscode.Position) =>
    mostSevereFirst(
      shown(uri).filter(
        (o) =>
          o.line === position.line &&
          (!underlined() || (position.character >= o.start && position.character <= o.end)),
      ),
    );
  const dismissArgs = (uri: vscode.Uri, o: Occurrence) => [
    uri.toString(),
    o.line,
    o.finding.classification.rule_id,
    o.finding.asset.usage,
  ];

  function severity(finding: Finding): vscode.DiagnosticSeverity {
    const { tier } = finding.classification;
    if (tier === "medium") return vscode.DiagnosticSeverity.Warning;
    if (tier !== "critical") return vscode.DiagnosticSeverity.Information;
    return setting<string>("criticalSeverity", "error") === "warning"
      ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Error;
  }

  function toDiagnostic(o: Occurrence): vscode.Diagnostic {
    const range = new vscode.Range(o.line, o.start, o.line, o.end);
    const diagnostic = new vscode.Diagnostic(range, headline(o.finding), severity(o.finding));
    diagnostic.source = SOURCE;
    diagnostic.code = o.finding.classification.rule_id;
    return diagnostic;
  }

  /** Draws a file's findings in the current style and clears the other style. */
  function render(uri: vscode.Uri): void {
    const items = shown(uri);
    const underline = underlined();
    diagnostics.set(uri, underline ? items.map(toDiagnostic) : []);

    // per line, most severe first: that finding gives the line its colour and its few words
    const byLine = new Map<number, Occurrence[]>();
    for (const o of mostSevereFirst(items)) byLine.set(o.line, [...(byLine.get(o.line) ?? []), o]);
    const levelOf = (onLine: Occurrence[]) => Math.min(...onLine.map((o) => severity(o.finding)));
    // a traced run of the tests reached none of the findings on the line: it is drawn fainter
    const idle = (onLine: Occurrence[]) => onLine.every((o) => o.execution?.ran === false);
    const hinted = setting("inlineHint", true);

    for (const editor of vscode.window.visibleTextEditors) {
      const { document } = editor;
      if (document.uri.toString() !== uri.toString()) continue;
      const lines = [...byLine].filter(([line]) => line < document.lineCount);
      const draw = (styles: typeof lineStyles, faint: boolean) => {
        for (const [level, style] of styles) {
          const coloured = underline
            ? []
            : lines.filter(([, onLine]) => levelOf(onLine) === level && idle(onLine) === faint);
          editor.setDecorations(
            style,
            coloured.map(([line]) => new vscode.Range(line, 0, line, 0)),
          );
        }
      };
      draw(lineStyles, false);
      draw(idleStyles, true);
      for (const [level, style] of hintStyles) {
        const worded = hinted ? lines.filter(([, onLine]) => levelOf(onLine) === level) : [];
        editor.setDecorations(
          style,
          worded.map(([line, onLine]) => {
            const end = document.lineAt(line).range.end;
            const contentText = inlineHint(onLine.map((o) => o.finding), idle(onLine));
            return { range: new vscode.Range(end, end), renderOptions: { after: { contentText } } };
          }),
        );
      }
    }
    lensesChanged.fire();
  }

  /** Above each line a traced run reached: what ran there, how often and in which test. */
  function provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!setting("codeLens", true)) return [];
    return mostSevereFirst(shown(document.uri)).flatMap((o) => {
      if (!o.execution?.ran || o.line >= document.lineCount) return [];
      return new vscode.CodeLens(new vscode.Range(o.line, 0, o.line, 0), {
        title: lensTitle(o.finding, o.execution),
        tooltip: "Seen by the QuantumTrace tracer in the last traced run. Click for the explanation.",
        command: EXPLAIN,
        arguments: [document.uri.toString(), o.line],
      });
    });
  }

  /** Opens the pop-up of a marked line (the words above a line that ran lead here). */
  async function explain(uriText: string, line: number): Promise<void> {
    const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(uriText));
    if (line >= document.lineCount) return;
    const at = new vscode.Position(line, document.lineAt(line).firstNonWhitespaceCharacterIndex);
    await vscode.window.showTextDocument(document, { selection: new vscode.Range(at, at) });
    await vscode.commands.executeCommand("editor.action.showHover");
  }

  function renderAll(): void {
    for (const key of found.keys()) render(vscode.Uri.parse(key));
  }

  /** The setting wins; a build downloaded from the web app falls back to that deployment's API. */
  const apiUrl = () => setting("api.url", "").trim() || DEFAULT_API_URL;

  async function engine(): Promise<Engine> {
    const backend = setting<string>("backend", "auto");
    const cli = cliEngine(setting("cli.command", ["quantumtrace"]));
    if (backend === "cli") return cli;

    const baseUrl = apiUrl();
    const api = baseUrl
      ? apiEngine({ baseUrl, apiKey: await context.secrets.get(API_KEY_SECRET) })
      : undefined;
    if (backend !== "api") return autoEngine(cli, api, () => mayUseApi(baseUrl));
    if (!api) {
      throw new EngineError(
        "Set quantumtrace.api.url to the QuantumTrace API, or switch quantumtrace.backend to cli.",
      );
    }
    return api;
  }

  /** The answer the user gave for this API. Unanswered, it asks once per window: closing the
   * question is not a yes, and is not remembered either. */
  function mayUseApi(baseUrl: string): Promise<boolean> {
    const answer = consent.answerFor(baseUrl);
    if (answer !== undefined) return Promise.resolve(answer);
    const origin = originOf(baseUrl);
    let question = asking.get(origin);
    if (!question) {
      question = askToUseApi(baseUrl);
      asking.set(origin, question);
    }
    return question;
  }

  async function askToUseApi(baseUrl: string): Promise<boolean> {
    const choice = await vscode.window.showInformationMessage(
      `QuantumTrace found no local scanner on this computer. Scan through the QuantumTrace API instead? The files you scan are sent to ${originOf(baseUrl)}.`,
      "Use the API",
      "Keep it local",
    );
    if (!choice) return false;
    const granted = choice === "Use the API";
    await consent.record(baseUrl, granted);
    return granted;
  }

  function failed(error: unknown): void {
    const message =
      error instanceof EngineError ? error.message : `QuantumTrace could not scan: ${String(error)}`;
    log.appendLine(message);
    if (message === lastFailure) return; // scanning on save would repeat it on every save
    lastFailure = message;
    void vscode.window.showErrorMessage(message, "Open settings").then((choice) => {
      if (choice) {
        void vscode.commands.executeCommand("workbench.action.openSettings", "quantumtrace.");
      }
    });
  }

  function logNotes(scan: Scan): void {
    for (const error of scan.errors) log.appendLine(`Scanner error: ${error}`);
    for (const note of scan.limitations) log.appendLine(`${note.scanner}: ${note.message}`);
  }

  async function scanDocument(document: vscode.TextDocument, asked = false): Promise<void> {
    const uri = document.uri;
    const say = (message: string) => {
      if (asked) void vscode.window.showInformationMessage(message);
    };
    if (!isSource(uri)) {
      say("QuantumTrace scans Python, Java and Go files.");
      return;
    }
    const root = vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath ?? path.dirname(uri.fsPath);
    const { version } = document;
    const text = document.getText();
    try {
      const scanner = await engine();
      // a saved file is scanned where it is; unsaved edits only where the text stays local
      const scan = document.isDirty
        ? await scanner.scanText(text, uri.fsPath, root)
        : await scanner.scan([uri.fsPath], root, traceOf(root));
      if (!scan) {
        say("Save the file, then scan again: unsaved edits are only scanned by the local QuantumTrace CLI.");
        return;
      }
      lastFailure = "";
      logNotes(scan);
      if (document.version !== version) return; // edited meanwhile; the next pause or save rescans
      const lineAt = (line: number) =>
        line < document.lineCount ? document.lineAt(line).text : undefined;
      // a trace speaks of every file it saw run: only this file's findings belong on its lines
      const here = scan.findings.filter(
        (f) => f.asset.evidence.source_type === "code" && sameFile(f.asset.evidence.location, uri.fsPath),
      );
      const marks = occurrences(here, lineAt);
      found.set(uri.toString(), marks);
      history.remember(uri.toString(), text, marks);
      render(uri);
      if (!shown(uri).length) say("QuantumTrace found nothing to flag in this file.");
    } catch (error) {
      failed(error);
    }
  }

  /** The trace of the folder's last traced run, if it has one: scans read it with the code. */
  const traceOf = (root: string) => (existsSync(traceFile(root)) ? traceFile(root) : undefined);

  async function scanWorkspace(report: () => void = summarise): Promise<void> {
    const folders = vscode.workspace.workspaceFolders ?? [];
    if (!folders.length) {
      void vscode.window.showInformationMessage("Open a folder, then scan it with QuantumTrace.");
      return;
    }
    lastFailure = "";
    const progress = {
      location: vscode.ProgressLocation.Notification,
      title: "QuantumTrace is scanning the workspace",
    };
    await vscode.window.withProgress(progress, async () => {
      try {
        const scanner = await engine();
        const byFile = new Map<string, Finding[]>();
        for (const folder of folders) {
          const root = folder.uri.fsPath;
          const scan = await scanner.scan([root], root, traceOf(root));
          logNotes(scan);
          for (const finding of scan.findings) {
            const { source_type, location } = finding.asset.evidence;
            if (source_type !== "code") continue;
            const file = path.resolve(root, location);
            byFile.set(file, [...(byFile.get(file) ?? []), finding]);
          }
        }
        const before = [...found.keys()];
        found.clear();
        history.clear();
        for (const [file, findings] of byFile) {
          const lines = (await readFile(file, "utf8")).split(/\r?\n/);
          found.set(
            vscode.Uri.file(file).toString(),
            occurrences(findings, (line) => lines[line]),
          );
        }
        vscode.workspace.textDocuments.forEach(seed);
        // files that had findings before and have none now must be cleared too
        for (const key of new Set([...before, ...found.keys()])) render(vscode.Uri.parse(key));
        report();
      } catch (error) {
        failed(error);
      }
    });
  }

  /** "In use": runs the project's tests with the tracer, then scans, so every marked line says
   * whether it really ran and with what. The command is the user's own, from their settings. */
  async function traceRun(): Promise<void> {
    const active = vscode.window.activeTextEditor?.document.uri;
    const folder =
      (active && vscode.workspace.getWorkspaceFolder(active)) ?? vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      void vscode.window.showInformationMessage("Open a folder, then run its tests with QuantumTrace.");
      return;
    }
    if (!vscode.workspace.isTrusted) {
      void vscode.window.showWarningMessage(
        "A traced run executes this folder's tests. Trust the folder first, then run it again.",
      );
      return;
    }
    if (tracing) {
      const again = await vscode.window.showInformationMessage(
        `QuantumTrace is still tracing "${tracing.command}".`,
        "Stop it and start again",
      );
      if (!again) return;
      tracing?.execution.terminate();
      tracing = undefined;
    }
    const [program, ...args] = setting<string[]>("trace.command", ["python", "-m", "pytest"]);
    const root = folder.uri.fsPath;
    const chosen = program === "python" ? await selectedPython(folder) : undefined;
    const interpreter =
      chosen ?? (program && findProgram(program, process.env, (file) => isFile(file, root)));
    if (!program || !interpreter) {
      // found out here: a terminal that cannot start its program just sits there
      const choice = await vscode.window.showErrorMessage(
        program
          ? `Can't find "${program}" to run the tests. Set quantumtrace.trace.command to the command that runs them, with a full path if needed.`
          : "The setting quantumtrace.trace.command is empty. Set it to the command that runs your tests.",
        "Open settings",
      );
      if (choice) {
        void vscode.commands.executeCommand("workbench.action.openSettings", "quantumtrace.trace");
      }
      return;
    }
    const out = traceFile(root);
    // a trace is one run: what an earlier run saw would describe code that may have changed
    await rm(out, { force: true });
    const task = new vscode.Task(
      { type: "quantumtrace" },
      folder,
      "Traced run",
      SOURCE,
      new vscode.ProcessExecution(interpreter, args, {
        cwd: root,
        env: tracerEnvironment(tracerFolder, root, out, process.env),
      }),
      [],
    );
    task.presentationOptions = {
      reveal: vscode.TaskRevealKind.Always,
      panel: vscode.TaskPanelKind.Dedicated,
      clear: true,
    };
    const command = [path.basename(program), ...args].join(" ");
    tracing = { execution: await vscode.tasks.executeTask(task), root, command };
  }

  /** Whether a program path, taken from the folder the run starts in, is a file. */
  function isFile(file: string, root: string): boolean {
    try {
      return statSync(path.resolve(root, file)).isFile();
    } catch {
      return false;
    }
  }

  /** The interpreter the Python extension uses for this folder, so the tests run in the same
   * environment as when the user runs them. Undefined when that extension is not there. */
  async function selectedPython(folder: vscode.WorkspaceFolder): Promise<string | undefined> {
    try {
      const python = vscode.extensions.getExtension<{
        environments?: { getActiveEnvironmentPath?: (uri: vscode.Uri) => { path?: string } };
      }>("ms-python.python");
      const api = python && (python.isActive ? python.exports : await python.activate());
      const found = api?.environments?.getActiveEnvironmentPath?.(folder.uri)?.path;
      return found && path.isAbsolute(found) ? found : undefined;
    } catch {
      return undefined;
    }
  }

  /** Forgets the last traced run: its trace is deleted, and the marks go back to what the code
   * alone says, with nothing about what ran. */
  async function traceClear(): Promise<void> {
    const traces = (vscode.workspace.workspaceFolders ?? [])
      .map((folder) => traceFile(folder.uri.fsPath))
      .filter((trace) => existsSync(trace));
    if (!traces.length) {
      void vscode.window.showInformationMessage("There is no runtime trace to clear.");
      return;
    }
    for (const trace of traces) await rm(trace, { force: true });
    await scanWorkspace(() => {
      void vscode.window.showInformationMessage(
        "Runtime trace cleared. Run the tests with the tracer to record a new one.",
      );
    });
  }

  function endTrace(execution: vscode.TaskExecution, exitCode: number | undefined): void {
    if (execution !== tracing?.execution) return;
    const { root, command } = tracing;
    tracing = undefined;
    void traced(root, command, exitCode);
  }

  /** After a traced run: scan again with the trace, and say what it showed. */
  async function traced(root: string, command: string, exitCode: number | undefined): Promise<void> {
    if (!existsSync(traceFile(root))) {
      const choice = await vscode.window.showWarningMessage(
        `"${command}" wrote no trace. The tracer follows Python 3.12 or newer: check that quantumtrace.trace.command starts it.`,
        "Open settings",
      );
      if (choice) {
        void vscode.commands.executeCommand("workbench.action.openSettings", "quantumtrace.trace");
      }
      return;
    }
    await scanWorkspace(() => {
      const all = [...found.keys()].flatMap((key) => shown(vscode.Uri.parse(key)));
      const ran = all.filter((o) => o.execution?.ran).length;
      const idle = all.filter((o) => o.execution?.ran === false).length;
      const failedRun = exitCode ? ` The command ended with exit code ${exitCode}.` : "";
      void vscode.window.showInformationMessage(
        ran + idle
          ? `QuantumTrace traced "${command}": ${plural(ran, "marked place")} ran, ${idle} did not.${failedRun}`
          : `QuantumTrace traced "${command}", and it reached no Python file with findings.${failedRun}`,
      );
    });
  }

  /** With quantumtrace.trace.debugSessions on, Python debug sessions started here are traced
   * too: the same tracer, added to the session's environment. */
  function traceDebugSession(
    folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
  ): vscode.DebugConfiguration {
    const python = config.type === "python" || config.type === "debugpy";
    if (!folder || !python || config.request !== "launch" || !setting("trace.debugSessions", false)) {
      return config;
    }
    const root = folder.uri.fsPath;
    const out = traceFile(root);
    rmSync(out, { force: true });
    const own = (config.env ?? {}) as Record<string, string | undefined>;
    const base = { PYTHONPATH: own.PYTHONPATH ?? process.env.PYTHONPATH };
    return { ...config, env: { ...own, ...tracerEnvironment(tracerFolder, root, out, base) } };
  }

  function summarise(): void {
    const perFile = [...found.keys()].map((key) => shown(vscode.Uri.parse(key)));
    const all = perFile.flat();
    const files = perFile.filter((items) => items.length).length;
    const shor = all.filter((o) => o.finding.classification.threat === "shor").length;
    void vscode.window.showInformationMessage(
      all.length
        ? `QuantumTrace flagged ${plural(all.length, "finding")} in ${plural(files, "file")}, ${shor} of them breakable with Shor's algorithm.`
        : "QuantumTrace found nothing to flag in this workspace's Python, Java and Go files.",
    );
  }

  /** Marks from a scan of the saved file belong to the text the file reads as now: remembered,
   * so that undoing the first edit after it brings them back. */
  function seed(document: vscode.TextDocument): void {
    const key = document.uri.toString();
    const marks = found.get(key);
    if (marks && !history.has(key) && !document.isDirty) {
      history.remember(key, document.getText(), marks);
    }
  }

  function onEdit(event: vscode.TextDocumentChangeEvent): void {
    const { document } = event;
    const key = document.uri.toString();
    const current = found.get(key);
    if (!current || !event.contentChanges.length) return; // never scanned: nothing to keep up
    const text = document.getText();
    // a text the file has read as before (an undo, a redo) gets the marks it had then
    let marks = history.recall(key, text);
    if (!marks) {
      const edits = event.contentChanges.map((change) => ({
        startLine: change.range.start.line,
        startChar: change.range.start.character,
        endLine: change.range.end.line,
        endChar: change.range.end.character,
        text: change.text,
      }));
      marks = applyEdits(current, edits);
      history.remember(key, text, marks);
    }
    found.set(key, marks);
    render(document.uri);
    scanSoon(document);
  }

  /** Scans a file once the typing pauses, so the marks follow the code without a save. */
  function scanSoon(document: vscode.TextDocument): void {
    const key = document.uri.toString();
    clearTimeout(settling.get(key));
    settling.delete(key);
    // turning off scanning on save means scanning on command only
    if (!setting("scanOnType", true) || !setting("scanOnSave", true)) return;
    settling.set(
      key,
      setTimeout(() => {
        settling.delete(key);
        if (!document.isClosed) void scanDocument(document);
      }, SETTLE_MS),
    );
  }

  /** A plain mouse click on a marked finding opens the same pop-up as hovering it. */
  function onSelection(event: vscode.TextEditorSelectionChangeEvent): void {
    const [selection] = event.selections;
    if (
      event.kind !== vscode.TextEditorSelectionChangeKind.Mouse ||
      event.selections.length !== 1 ||
      !selection?.isEmpty ||
      !setting("explainOnClick", true)
    ) {
      return;
    }
    if (at(event.textEditor.document.uri, selection.active).length) {
      void vscode.commands.executeCommand("editor.action.showHover");
    }
  }

  function provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.Hover | undefined {
    const hits = at(document.uri, position);
    const [first] = hits;
    if (!first) return undefined;
    // an underline comes with a diagnostic that already states the reason; a highlight does not
    const wholeLine = !underlined();
    const withFix = setting("aiFix", true);
    const sections = hits.map((o) => {
      const args = dismissArgs(document.uri, o);
      return explanation(o.finding, commandLink(DISMISS, args), {
        tone: TONES[severity(o.finding)],
        withRationale: wholeLine,
        fixLink: withFix ? commandLink(FIX, args) : undefined,
        execution: o.execution,
      });
    });
    const markdown = new vscode.MarkdownString(sections.join("\n\n---\n\n"));
    markdown.isTrusted = { enabledCommands: [DISMISS, FIX] };
    markdown.supportThemeIcons = true;
    markdown.supportHtml = true; // for the coloured title and the buttons
    return new vscode.Hover(
      markdown,
      wholeLine
        ? document.lineAt(first.line).range
        : new vscode.Range(first.line, first.start, first.line, first.end),
    );
  }

  function provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    actionContext: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const onLines = shown(document.uri).filter(
      (o) => o.line >= range.start.line && o.line <= range.end.line,
    );
    const withFix = setting("aiFix", true);
    return mostSevereFirst(onLines).flatMap((o) => {
      const ruleId = o.finding.classification.rule_id;
      const about = actionContext.diagnostics.filter(
        (d) => d.source === SOURCE && d.range.start.line === o.line && d.code === ruleId,
      );
      const action = (title: string, command: string, short: string) => {
        const made = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
        made.diagnostics = about;
        made.command = { command, title: short, arguments: dismissArgs(document.uri, o) };
        return made;
      };
      return [
        ...(withFix ? [action(`Fix ${label(o.finding)} with AI`, FIX, "Fix with AI")] : []),
        action(`Dismiss this ${label(o.finding)} warning`, DISMISS, "Dismiss warning"),
      ];
    });
  }

  async function dismiss(
    uriText: string,
    line: number,
    ruleId: string,
    usage: string | null,
  ): Promise<void> {
    const uri = vscode.Uri.parse(uriText);
    const target = shown(uri).find(
      (o) =>
        o.line === line &&
        o.finding.classification.rule_id === ruleId &&
        o.finding.asset.usage === usage,
    );
    if (!target) return;
    // key it by the line as it reads now: it may have been edited since the scan
    const document = vscode.workspace.textDocuments.find((d) => d.uri.toString() === uriText);
    if (document && line < document.lineCount) {
      target.key = occurrenceKey(target.finding, document.lineAt(line).text);
    }
    const { tier } = target.finding.classification;
    await dismissals.add(
      fileKey(uri),
      dismissed(target.key, label(target.finding), tier, target.line),
    );
    render(uri);
    refreshDismissed();
    // not every VS Code version has this command; the pop-up closes on the next mouse move anyway
    void vscode.commands.executeCommand("editor.action.hideHover").then(undefined, () => undefined);

    // not awaited: the command is done, however long the notification stays up
    void vscode.window
      .showInformationMessage(`Dismissed the ${label(target.finding)} warning.`, "Undo")
      .then(async (undo) => {
        if (!undo) return;
        await dismissals.remove(fileKey(uri), target.key);
        render(uri);
        refreshDismissed();
      });
  }

  /** "Fix with AI" on one finding: the API's model rewrites the lines around it, and the rewrite
   * replaces them in the editor. Nothing is saved, so the user reviews it and can undo it. */
  async function fix(
    uriText: string,
    line: number,
    ruleId: string,
    usage: string | null,
  ): Promise<void> {
    const uri = vscode.Uri.parse(uriText);
    const target = shown(uri).find(
      (o) =>
        o.line === line &&
        o.finding.classification.rule_id === ruleId &&
        o.finding.asset.usage === usage,
    );
    if (!target) return; // the pop-up was for a finding that has since gone
    void vscode.commands.executeCommand("editor.action.hideHover").then(undefined, () => undefined);
    const { observed } = target.finding.asset;
    await fixAt(uri, { line, ruleId, usage, observed }, label(target.finding));
  }

  async function fixAt(
    uri: vscode.Uri,
    at: { line: number; ruleId: string; usage: string | null; observed: string },
    name: string,
    agreed = false,
  ): Promise<void> {
    const baseUrl = apiUrl();
    if (!baseUrl) {
      const choice = await vscode.window.showErrorMessage(
        "Fix with AI needs a QuantumTrace API to write the fix. Set quantumtrace.api.url to its address.",
        "Open settings",
      );
      if (choice) {
        void vscode.commands.executeCommand("workbench.action.openSettings", "quantumtrace.api.url");
      }
      return;
    }
    const key = uri.toString();
    if (fixing.has(key)) {
      void vscode.window.showInformationMessage("QuantumTrace is still writing a fix for this file.");
      return;
    }
    const document = await vscode.workspace.openTextDocument(uri);
    const folder = vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath;
    const file = folder
      ? path.relative(folder, uri.fsPath).split(path.sep).join("/")
      : path.basename(uri.fsPath);
    if (!agreed && !(await maySendForFix(baseUrl, file))) return;

    let earlier: number | undefined;
    fixing.add(key);
    try {
      const { version } = document;
      const apiKey = await context.secrets.get(API_KEY_SECRET);
      const suggestion = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `QuantumTrace is writing a fix for ${name}`,
        },
        () => requestFix({ baseUrl, apiKey }, { text: document.getText(), name: file, ...at }),
      );
      log.appendLine(`\n${report(suggestion, file)}`);
      await applyFix(document, suggestion, at.line, name, document.version !== version);
    } catch (error) {
      if (error instanceof EarlierPlaceError) {
        earlier = error.line;
      } else {
        const message =
          error instanceof EngineError ? error.message : `Fix with AI failed: ${String(error)}`;
        log.appendLine(message);
        void vscode.window.showErrorMessage(message);
      }
    } finally {
      fixing.delete(key);
    }
    if (earlier === undefined) return;

    // the engine merges repeats in a file into one finding, and the API fixes its first place
    const first = `line ${earlier + 1}`;
    const choice = await vscode.window.showInformationMessage(
      `This is the same ${name} as on ${first}, and the AI writes its fix for the first place the code appears. Fix ${first} first.`,
      `Fix ${first}`,
    );
    if (choice) await fixAt(uri, { ...at, line: earlier }, name, true);
  }

  /** Puts a suggestion into the editor, or says why it can't, and offers the way back. */
  async function applyFix(
    document: vscode.TextDocument,
    suggestion: FixSuggestion,
    line: number,
    name: string,
    edited: boolean,
  ): Promise<void> {
    const details = (choice: string | undefined) => {
      if (choice) log.show(true);
    };
    if (!suggestion.changed) {
      void vscode.window
        .showWarningMessage(
          `The AI changed nothing on these lines: the fix for ${name} belongs elsewhere in the code.`,
          "Show what to change",
        )
        .then(details);
      return;
    }
    const place = edited
      ? undefined
      : replacement(suggestion, (n) =>
          n < document.lineCount ? document.lineAt(n).text : undefined,
        );
    if (!place || line < place.startLine || line > place.endLine) {
      void vscode.window
        .showWarningMessage(
          edited
            ? "The file changed while the fix was being written, so nothing was applied. Run Fix with AI again."
            : "Could not place the AI fix: the lines it rewrites are not what the API read (lines over 200 characters are cut short). Nothing was changed.",
          "Show the fix",
        )
        .then(details);
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(new vscode.Position(place.startLine, 0), document.lineAt(place.endLine).range.end),
      place.lines.join(document.eol === vscode.EndOfLine.CRLF ? "\r\n" : "\n"),
    );
    if (!(await vscode.workspace.applyEdit(edit))) {
      void vscode.window.showErrorMessage(
        "VS Code refused the edit, so the AI fix was not applied. Check that the file is not read-only.",
      );
      return;
    }
    const applied = document.version;
    const lastLine = place.startLine + place.lines.length - 1;
    // back to the editor the file is already in, so Undo is one keystroke away
    const show = () =>
      vscode.window.showTextDocument(document, {
        viewColumn: vscode.window.visibleTextEditors.find((e) => e.document === document)?.viewColumn,
      });
    (await show()).revealRange(
      new vscode.Range(place.startLine, 0, lastLine, 0),
      vscode.TextEditorRevealType.InCenterIfOutsideViewport,
    );

    const where = linesLabel(place.startLine, lastLine);
    const more = suggestion.caveats.length;
    // not awaited: the command is done, however long the notification stays up
    const answer = more
      ? vscode.window.showWarningMessage(
          `AI fix applied to ${where}, not saved yet. ${suggestion.summary} It needs ${plural(more, "more change")} elsewhere to work.`,
          "Show what else to change",
          "Undo",
        )
      : vscode.window.showInformationMessage(
          `AI fix applied to ${where}, not saved yet. ${suggestion.summary} Review it before you save.`,
          "Show details",
          "Undo",
        );
    void answer.then(async (choice) => {
      if (choice !== "Undo") return details(choice);
      if (document.version !== applied) {
        void vscode.window.showInformationMessage(
          "The file changed after the fix. Use Undo in the editor to step back to it.",
        );
        return;
      }
      await show();
      await vscode.commands.executeCommand("undo");
    });
  }

  /** An AI fix sends the file to the API and the flagged lines on to the model's provider, so it
   * asks first: every time, unless the user said always for this API. */
  async function maySendForFix(baseUrl: string, file: string): Promise<boolean> {
    if (aiConsent.answerFor(baseUrl)) return true;
    const always = "Always send to this API";
    const choice = await vscode.window.showInformationMessage(
      `Send ${file} to ${originOf(baseUrl)} to write a fix?`,
      {
        modal: true,
        detail:
          "The QuantumTrace API scans the file and sends the lines around this finding to Google's Gemini model. " +
          "The rewrite replaces those lines in the editor without saving, so you can review it or undo it.",
      },
      "Send",
      always,
    );
    if (choice === always) await aiConsent.record(baseUrl, true);
    return choice !== undefined;
  }

  async function restoreDismissed(): Promise<void> {
    const count = dismissals.count();
    await dismissals.clear();
    renderAll();
    refreshDismissed();
    void vscode.window.showInformationMessage(
      count ? `Restored ${plural(count, "dismissed warning")}.` : "No dismissed warnings to restore.",
    );
  }

  /** Restores one warning from the list. */
  async function restoreOne({ file, item }: DismissedRow): Promise<void> {
    await dismissals.remove(file, item.key);
    renderAll();
    refreshDismissed();
  }

  /** Opens a dismissed warning's file at its line. */
  async function revealDismissed({ file, item }: DismissedRow): Promise<void> {
    const uri = uriOf(file);
    try {
      if (!uri) throw new Error("its folder is not open");
      const document = await vscode.workspace.openTextDocument(uri);
      // the line may have moved since it was dismissed: find its text, nearest to where it was
      const was = item.line ?? 0;
      const matches = [...Array(document.lineCount).keys()]
        .filter((n) => document.lineAt(n).text.trim() === item.text)
        .sort((a, b) => Math.abs(a - was) - Math.abs(b - was));
      const line = matches[0] ?? Math.min(was, document.lineCount - 1);
      await vscode.window.showTextDocument(document, {
        selection: new vscode.Range(line, 0, line, 0),
      });
    } catch {
      void vscode.window.showWarningMessage(
        `Can't open ${file}. It may have been moved or deleted, or its folder is not open.`,
      );
    }
  }

  async function setApiKey(): Promise<void> {
    const key = await vscode.window.showInputBox({
      title: "QuantumTrace API key",
      prompt: "Sent as X-API-Key. Leave empty to remove the stored key.",
      password: true,
      ignoreFocusOut: true,
    });
    if (key === undefined) return;
    await (key ? context.secrets.store(API_KEY_SECRET, key) : context.secrets.delete(API_KEY_SECRET));
  }

  const scanQuietly = (document: vscode.TextDocument) => {
    if (setting("scanOnSave", true)) void scanDocument(document);
  };

  context.subscriptions.push(
    diagnostics,
    log,
    ...lineStyles.map(([, style]) => style),
    ...hintStyles.map(([, style]) => style),
    // highlights belong to an editor, not a file: draw them whenever one comes into view
    vscode.window.onDidChangeVisibleTextEditors((editors) => {
      for (const editor of editors) render(editor.document.uri);
    }),
    { dispose: () => settling.forEach((timer) => clearTimeout(timer)) },
    vscode.workspace.onDidSaveTextDocument(scanQuietly),
    vscode.workspace.onDidOpenTextDocument(seed),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && !found.has(editor.document.uri.toString())) scanQuietly(editor.document);
    }),
    vscode.workspace.onDidChangeTextDocument(onEdit),
    vscode.window.onDidChangeTextEditorSelection(onSelection),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration("quantumtrace")) return;
      lastFailure = "";
      renderAll();
    }),
    vscode.languages.registerHoverProvider(SELECTOR, { provideHover }),
    vscode.languages.registerCodeActionsProvider(
      SELECTOR,
      { provideCodeActions },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
    vscode.commands.registerCommand("quantumtrace.scanFile", () => {
      const document = vscode.window.activeTextEditor?.document;
      if (!document) return undefined;
      lastFailure = "";
      return scanDocument(document, true);
    }),
    vscode.commands.registerCommand("quantumtrace.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("quantumtrace.restoreDismissed", restoreDismissed),
    vscode.commands.registerCommand("quantumtrace.restoreOne", restoreOne),
    vscode.commands.registerCommand("quantumtrace.revealDismissed", revealDismissed),
    dismissedTree,
    vscode.commands.registerCommand("quantumtrace.setApiKey", setApiKey),
    vscode.commands.registerCommand(DISMISS, dismiss),
    vscode.commands.registerCommand(FIX, fix),
    ...idleStyles.map(([, style]) => style),
    lensesChanged,
    vscode.languages.registerCodeLensProvider(SELECTOR, {
      onDidChangeCodeLenses: lensesChanged.event,
      provideCodeLenses,
    }),
    vscode.commands.registerCommand(EXPLAIN, explain),
    vscode.commands.registerCommand("quantumtrace.traceRun", traceRun),
    vscode.commands.registerCommand("quantumtrace.traceClear", traceClear),
    vscode.tasks.onDidEndTaskProcess((event) => endTrace(event.execution, event.exitCode)),
    // a command that could not even start has no process to end: the task still does
    vscode.tasks.onDidEndTask((event) => endTrace(event.execution, undefined)),
    vscode.debug.registerDebugConfigurationProvider("*", {
      resolveDebugConfigurationWithSubstitutedVariables: traceDebugSession,
    }),
    vscode.debug.onDidTerminateDebugSession((session) => {
      const env = session.configuration.env as Record<string, string> | undefined;
      const root = session.workspaceFolder?.uri.fsPath;
      if (root && env?.QT_TRACE_FILE) void traced(root, `debug: ${session.name}`, undefined);
    }),
  );

  refreshDismissed();
  for (const editor of vscode.window.visibleTextEditors) scanQuietly(editor.document);
}
