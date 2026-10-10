/** The "Dismissed warnings" list in the QuantumTrace side bar. */
import * as path from "node:path";
import * as vscode from "vscode";
import type { Dismissals, DismissedRow } from "./dismissals";

const ICONS: Record<string, [icon: string, color: string]> = {
  critical: ["error", "quantumtrace.criticalForeground"],
  medium: ["warning", "quantumtrace.mediumForeground"],
};

/** The key dismissals are stored under: the path relative to the workspace, folder name first. */
export function fileKey(uri: vscode.Uri): string {
  return vscode.workspace.asRelativePath(uri, true);
}

/** The reverse of `fileKey`; undefined when the file's workspace folder is not open. */
export function uriOf(file: string): vscode.Uri | undefined {
  const [name, ...rest] = file.split("/");
  const folder = vscode.workspace.workspaceFolders?.find((f) => f.name === name);
  if (folder && rest.length) return vscode.Uri.joinPath(folder.uri, ...rest);
  return path.isAbsolute(file) ? vscode.Uri.file(file) : undefined;
}

export class DismissedView implements vscode.TreeDataProvider<DismissedRow> {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;

  constructor(private readonly dismissals: Dismissals) {}

  refresh(): void {
    this.changed.fire();
  }

  getChildren(row?: DismissedRow): DismissedRow[] {
    return row ? [] : this.dismissals.list();
  }

  getTreeItem({ file, item }: DismissedRow): vscode.TreeItem {
    const uri = uriOf(file);
    const shortPath = uri ? vscode.workspace.asRelativePath(uri, false) : file;
    const where = item.line === null ? shortPath : `${shortPath}:${item.line + 1}`;
    const [icon, color] = ICONS[item.tier] ?? ["info", "quantumtrace.unknownForeground"];

    const node = new vscode.TreeItem(item.label);
    node.description = `${where}  ${item.text}`;
    node.tooltip = `${item.label} (dismissed)\n${where}\n${item.text}`;
    node.iconPath = new vscode.ThemeIcon(icon, new vscode.ThemeColor(color));
    node.contextValue = "dismissed";
    node.command = {
      command: "quantumtrace.revealDismissed",
      title: "Show in file",
      arguments: [{ file, item }],
    };
    return node;
  }
}
