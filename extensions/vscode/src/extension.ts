/** VS Code wiring: scan with the engine, underline the findings, explain and dismiss them. */
import { readFile } from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import type { Finding } from "@quantumtrace/sdk";
import { dismissed, Dismissals, type DismissedRow } from "./dismissals";
import { DismissedView, fileKey, uriOf } from "./dismissedView";
import { apiEngine, cliEngine, type Engine, EngineError, type Scan } from "./engine";
import { commandLink, explanation, headline, label, type Tone } from "./explain";
import {
  applyEdits,
  mostSevereFirst,
  occurrenceKey,
  occurrences,
  type Occurrence,
} from "./occurrences";

const SOURCE = "QuantumTrace";
const DISMISS = "quantumtrace.dismiss";
const API_KEY_SECRET = "quantumtrace.apiKey";
const EXTENSIONS = new Set([".py", ".java", ".go"]);
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
  let lastFailure = "";

  const lineStyle = (tier: string, ruler: string) =>
    vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      backgroundColor: new vscode.ThemeColor(`quantumtrace.${tier}LineBackground`),
      overviewRulerColor: new vscode.ThemeColor(ruler),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    });
  /** Whole-line colours by severity, for the "highlight" style. */
  const lineStyles: [vscode.DiagnosticSeverity, vscode.TextEditorDecorationType][] = [
    [vscode.DiagnosticSeverity.Error, lineStyle("critical", "editorOverviewRuler.errorForeground")],
    [vscode.DiagnosticSeverity.Warning, lineStyle("medium", "editorOverviewRuler.warningForeground")],
    [vscode.DiagnosticSeverity.Information, lineStyle("unknown", "editorOverviewRuler.infoForeground")],
  ];

  const setting = <T>(name: string, fallback: T): T =>
    vscode.workspace.getConfiguration("quantumtrace").get<T>(name, fallback);
  const underlined = () => setting<string>("style", "highlight") === "underline";
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

    // one colour per line: the most severe finding on it
    const worst = new Map<number, number>();
    if (!underline) {
      for (const o of items) {
        worst.set(o.line, Math.min(worst.get(o.line) ?? Infinity, severity(o.finding)));
      }
    }
    for (const editor of vscode.window.visibleTextEditors) {
      if (editor.document.uri.toString() !== uri.toString()) continue;
      for (const [level, style] of lineStyles) {
        const lines = [...worst].filter(([, s]) => s === level).map(([line]) => line);
        editor.setDecorations(
          style,
          lines.map((line) => new vscode.Range(line, 0, line, 0)),
        );
      }
    }
  }

  function renderAll(): void {
    for (const key of found.keys()) render(vscode.Uri.parse(key));
  }

  async function engine(): Promise<Engine> {
    if (setting<string>("backend", "cli") !== "api") {
      return cliEngine(setting("cli.command", ["quantumtrace"]));
    }
    const baseUrl = setting("api.url", "").trim();
    if (!baseUrl) {
      throw new EngineError(
        "Set quantumtrace.api.url to the QuantumTrace API, or switch quantumtrace.backend to cli.",
      );
    }
    return apiEngine({ baseUrl, apiKey: await context.secrets.get(API_KEY_SECRET) });
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
    if (uri.scheme !== "file" || !EXTENSIONS.has(path.extname(uri.fsPath).toLowerCase())) {
      say("QuantumTrace scans Python, Java and Go files.");
      return;
    }
    if (document.isDirty) {
      // the engine reads the file from disk, so its line numbers would not match the editor
      say("Save the file, then scan again: QuantumTrace reads it from disk.");
      return;
    }
    const root = vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath ?? path.dirname(uri.fsPath);
    const { version } = document;
    try {
      const scan = await (await engine()).scan([uri.fsPath], root);
      lastFailure = "";
      logNotes(scan);
      if (document.version !== version) return; // edited meanwhile; the next save rescans
      const lineAt = (line: number) =>
        line < document.lineCount ? document.lineAt(line).text : undefined;
      found.set(uri.toString(), occurrences(scan.findings, lineAt));
      render(uri);
      if (!shown(uri).length) say("QuantumTrace found nothing to flag in this file.");
    } catch (error) {
      failed(error);
    }
  }

  async function scanWorkspace(): Promise<void> {
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
          const scan = await scanner.scan([root], root);
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
        for (const [file, findings] of byFile) {
          const lines = (await readFile(file, "utf8")).split(/\r?\n/);
          found.set(
            vscode.Uri.file(file).toString(),
            occurrences(findings, (line) => lines[line]),
          );
        }
        // files that had findings before and have none now must be cleared too
        for (const key of new Set([...before, ...found.keys()])) render(vscode.Uri.parse(key));
        summarise();
      } catch (error) {
        failed(error);
      }
    });
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

  function onEdit(event: vscode.TextDocumentChangeEvent): void {
    const key = event.document.uri.toString();
    const current = found.get(key);
    if (!current?.length || !event.contentChanges.length) return;
    const edits = event.contentChanges.map((change) => ({
      startLine: change.range.start.line,
      startChar: change.range.start.character,
      endLine: change.range.end.line,
      endChar: change.range.end.character,
      text: change.text,
    }));
    found.set(key, applyEdits(current, edits));
    render(event.document.uri);
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
    const sections = hits.map((o) =>
      explanation(o.finding, commandLink(DISMISS, dismissArgs(document.uri, o)), {
        tone: TONES[severity(o.finding)],
        withRationale: wholeLine,
      }),
    );
    const markdown = new vscode.MarkdownString(sections.join("\n\n---\n\n"));
    markdown.isTrusted = { enabledCommands: [DISMISS] };
    markdown.supportThemeIcons = true;
    markdown.supportHtml = true; // for the coloured title and the dismiss button
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
    return mostSevereFirst(onLines).map((o) => {
      const ruleId = o.finding.classification.rule_id;
      const action = new vscode.CodeAction(
        `Dismiss this ${label(o.finding)} warning`,
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = actionContext.diagnostics.filter(
        (d) => d.source === SOURCE && d.range.start.line === o.line && d.code === ruleId,
      );
      action.command = {
        command: DISMISS,
        title: "Dismiss warning",
        arguments: dismissArgs(document.uri, o),
      };
      return action;
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
    // highlights belong to an editor, not a file: draw them whenever one comes into view
    vscode.window.onDidChangeVisibleTextEditors((editors) => {
      for (const editor of editors) render(editor.document.uri);
    }),
    vscode.workspace.onDidSaveTextDocument(scanQuietly),
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
  );

  refreshDismissed();
  for (const editor of vscode.window.visibleTextEditors) scanQuietly(editor.document);
}
