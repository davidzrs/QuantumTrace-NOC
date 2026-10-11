/** Wording and layout for one finding. Every fact comes from the engine; this file only lays
 * it out, in Markdown plus the few inline styles VS Code allows in a hover. */
import type { Finding } from "@quantumtrace/sdk";

type Tier = Finding["classification"]["tier"];
type Threat = Finding["classification"]["threat"];
type Confidence = Finding["asset"]["confidence"];
type Execution = NonNullable<Finding["asset"]["evidence"]["execution"]>;

/** Which risk colour the pop-up uses; the extension passes the one it gave the line. */
export type Tone = "critical" | "medium" | "unknown";

export interface PopupOptions {
  /** Defaults to the finding's own tier. */
  tone?: Tone;
  /** Adds the engine's reason, for when no diagnostic message sits beside the pop-up. */
  withRationale?: boolean;
  /** Adds the "Fix with AI" button, which runs this `command:` link. */
  fixLink?: string;
  /** What a traced run saw at this place: adds a line saying whether and how it ran. */
  execution?: Execution | null;
}

// same words as the web app (packages/ui/src/tiers.ts)
const TIER_LABEL: Record<Tier, string> = {
  critical: "Critical",
  medium: "Weakened",
  safe: "Resilient",
  unknown: "Unclassified",
};

const THREAT: Partial<Record<Threat, string>> = {
  shor: "Broken by Shor's algorithm",
  grover: "Security halved by Grover's algorithm",
};

const CONFIDENCE: Partial<Record<Confidence, string>> = {
  medium: "Medium confidence: inferred, for example a key size taken from elsewhere in the file.",
  low: "Low confidence: the input was incomplete.",
};

const TONE_ICON: Record<Tone, string> = { critical: "error", medium: "warning", unknown: "info" };

/** The precise form when the engine knows it (AES-128-ECB, Ed25519), otherwise the rule name. */
export function label(finding: Finding): string {
  const { name } = finding.classification;
  const size = finding.asset.key_size;
  return finding.asset.variant ?? (size && !name.includes(String(size)) ? `${name}-${size}` : name);
}

/** The diagnostic message: what it is and why it is a problem. */
export function headline(finding: Finding): string {
  return `${label(finding)}: ${finding.classification.rationale}`;
}

const HINT: Partial<Record<Threat, string>> = {
  shor: "broken by Shor's algorithm",
  grover: "weakened by Grover's algorithm",
};
const HINT_LENGTH = 72;

/** A few words for the end of a marked line: what the worst finding on it is and why it
 * matters, and how many more share the line. `findings` are most severe first. `notRun` adds
 * that a traced run never reached the line. */
export function inlineHint(findings: readonly Finding[], notRun = false): string {
  const [worst, ...others] = findings;
  if (!worst) return "";
  const c = worst.classification;
  const why =
    HINT[c.threat] ??
    (c.classically_broken ? "already broken today" : TIER_LABEL[c.tier].toLowerCase());
  const more =
    (others.length ? ` (+${others.length} more)` : "") + (notRun ? " · did not run" : "");
  const name = label(worst);
  // the name can come from the scanned source, so it is the part that gives way
  const room = HINT_LENGTH - why.length - more.length - 2;
  const shown = name.length > room ? `${name.slice(0, Math.max(room - 1, 1))}…` : name;
  return `${shown}: ${why}${more}`;
}

/** `test_login` from `tests/test_auth.py::TestAuth::test_login` or `pkg.Case.test_login`. */
export function testName(id: string): string {
  const cut = id.includes("::") ? id.lastIndexOf("::") + 2 : id.lastIndexOf(".") + 1;
  return id.slice(cut) || id;
}

/** What a traced run saw at a place, in a few words: "ran 14× in test_login". */
export function ranSummary(execution: Execution): string {
  if (!execution.ran) return "did not run";
  const times = execution.calls === null ? "ran" : `ran ${execution.calls}×`;
  const [first] = execution.tests;
  if (first === undefined) return execution.run ? `${times} during ${execution.run}` : times;
  const more = execution.test_count - 1;
  const others = more > 0 ? ` and ${more} more test${more === 1 ? "" : "s"}` : "";
  return `${times} in ${testName(first)}${others}`;
}

/** The words above a line that ran: "RSA-1024 · ran 14× in test_login". */
export function lensTitle(finding: Finding, execution: Execution): string {
  return `${label(finding)} · ${ranSummary(execution)}`;
}

/** A `command:` link that stays intact inside a Markdown link, whatever the arguments contain. */
export function commandLink(command: string, args: readonly unknown[]): string {
  const query = encodeURIComponent(JSON.stringify(args)).replace(
    /[()]/g,
    (c) => `%${c.charCodeAt(0).toString(16)}`,
  );
  return `command:${command}?${query}`;
}

// VS Code keeps a span's style only in exactly this shape: color, background-color and
// border-radius, in that order, each ending in ";" and with theme variables or hex colours.
const themed = (id: string) => `var(--vscode-${id})`;
const span = (style: string, content: string) => `<span style="${style}">${content}</span>`;

/** Markdown for the pop-up: a coloured title with the tier, the verdict, then how to fix it,
 * the reference, any misuse flags, and the buttons. */
export function explanation(
  finding: Finding,
  dismissLink: string,
  { tone, withRationale = false, fixLink, execution }: PopupOptions = {},
): string {
  const c = finding.classification;
  const shade: Tone = tone ?? (c.tier === "critical" || c.tier === "medium" ? c.tier : "unknown");
  const ink = `color:${themed(`quantumtrace-${shade}Foreground`)};`;
  const wash = `background-color:${themed(`quantumtrace-${shade}LineBackground`)};`;

  const title =
    `${span(ink, `$(${TONE_ICON[shade]})`)}&nbsp; **${escape(label(finding))}** &nbsp;` +
    span(`${ink}${wash}border-radius:4px;`, `&nbsp;${TIER_LABEL[c.tier]}&nbsp;`);
  const verdict = [
    THREAT[c.threat],
    c.classically_broken ? "already broken without a quantum computer" : undefined,
  ]
    .filter((fact) => fact !== undefined)
    .join(" · ");

  const details: string[] = [];
  if (c.replacement) {
    details.push(`$(lightbulb)&nbsp; **How to fix:** switch to ${escape(c.replacement)}`);
  }
  if (c.nist_reference) details.push(`$(book)&nbsp; ${escape(c.nist_reference)}`);
  if (finding.asset.flags.length) {
    details.push(`$(tag)&nbsp; ${finding.asset.flags.map((f) => `\`${f}\``).join(" ")}`);
  }
  const confidence = CONFIDENCE[finding.asset.confidence];
  if (confidence) details.push(`$(info)&nbsp; ${confidence}`);
  if (execution) details.push(runtimeLine(execution));

  // badge colours are a background and a text colour every theme defines as a readable pair
  const button = (caption: string, link: string) =>
    span(
      `background-color:${themed("badge-background")};border-radius:4px;`,
      `&nbsp; [${span(`color:${themed("badge-foreground")};`, caption)}](${link}) &nbsp;`,
    );
  const buttons = [
    fixLink ? button("$(sparkle) Fix with AI", fixLink) : undefined,
    button("$(close) Dismiss warning", dismissLink),
  ]
    .filter((b) => b !== undefined)
    .join(" &nbsp; ");

  const lineBreak = "  \n";
  return [
    verdict
      ? title + lineBreak + span(`color:${themed("descriptionForeground")};`, capitalise(verdict))
      : title,
    withRationale ? escape(c.rationale) : undefined,
    details.length ? details.join(lineBreak) : undefined,
    buttons,
  ]
    .filter((part) => part !== undefined)
    .join("\n\n");
}

const capitalise = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);

/** The pop-up's line on what a traced run saw: how often it ran, in which tests, with what. */
function runtimeLine(execution: Execution): string {
  const during = execution.run ? ` during ${asCode(execution.run)}` : "";
  if (!execution.ran) return `$(circle-slash)&nbsp; **Did not run**${during}`;
  const tests = execution.tests.map((id) => asCode(testName(id)));
  const hidden = execution.test_count - tests.length;
  const where = tests.length
    ? ` in ${tests.join(", ")}${hidden > 0 ? ` and ${hidden} more` : ""}`
    : during;
  const { key_size: size, curve, mode, via } = execution.parameters;
  const used = [
    size && `key size ${escape(size)}`,
    curve && escape(curve),
    mode && `${escape(mode)} mode`,
    via && `through ${escape(via)}`,
  ].filter(Boolean);
  const times = execution.calls === null ? "" : ` ${execution.calls}×`;
  const facts = used.length ? ` · ${used.join(" · ")}` : "";
  return `$(play)&nbsp; **Seen running**${times}${where}${facts}`;
}

/** Test names and commands come from the trace: shown as code, with nothing to break out of it. */
const asCode = (text: string) => "`" + text.replace(/[`\\<>[\]]/g, "") + "`";

/** Names of unclassified algorithms come straight from the scanned source: keep them inert,
 * as Markdown, as HTML and as `$(icon)` references. */
function escape(text: string): string {
  return text.replace(/[\\`*_{}[\]<>()#|~$&]/g, "\\$&");
}
