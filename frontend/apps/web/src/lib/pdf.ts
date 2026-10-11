import type { Finding, RiskTier, ScanResult } from "@quantumtrace/sdk";
import type { jsPDF } from "jspdf";
import { FIX_BY, fixRows, type FixBy, type FixRow } from "./fix";
import { algorithmLabel, placeLabel, plural, SOURCE_LABEL, SOURCES, usageLabel } from "./format";
import { heroSub, tally } from "./summary";
import { TIER, TIERS } from "./tiers";

/**
 * A one- or two-page PDF summary of a scan for people who won't open the dashboard: the headline,
 * the score, what to fix first and what the scan couldn't see. Every detail stays in the report and
 * the CBOM. jsPDF is downloaded only when someone exports, so the report page doesn't carry it.
 */
export async function exportPdf(result: ScanResult, reportUrl: string): Promise<void> {
  const doc = await renderPdf(result, reportUrl);
  doc.save(`quantumtrace-summary-${result.id.slice(0, 8)}.pdf`);
}

export async function renderPdf(result: ScanResult, reportUrl: string): Promise<jsPDF> {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  doc.setProperties({ title: "QuantumTrace summary", subject: result.targets.join(", "), creator: "QuantumTrace" });
  draw(doc, result, reportUrl);
  return doc;
}

const FIX_SHOWN = 8;
const NOTES_SHOWN = 6;

// Paper is always light, so the light theme's tokens (packages/ui/src/tokens.css).
type Rgb = [number, number, number];
const rgb = (hex: string): Rgb => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as Rgb;
const INK = rgb("#1b2430");
const MUTED = rgb("#5b6878");
const FAINT = rgb("#8a96a5");
const RULE = rgb("#d5dbe2");
const RULE_STRONG = rgb("#aeb8c4");
const TIER_RGB: Record<RiskTier, Rgb> = {
  critical: rgb("#b3123f"),
  medium: rgb("#9a6a12"),
  unknown: rgb("#6b7685"),
  safe: rgb("#0f7b6c"),
};
const FIX_RGB: Record<FixBy, Rgb> = {
  now: TIER_RGB.critical,
  "before-2030": TIER_RGB.critical,
  harden: TIER_RGB.medium,
  review: TIER_RGB.unknown,
  none: TIER_RGB.safe,
};

// A4 in millimetres. Font sizes are points.
const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 18;
const WIDTH = PAGE_W - 2 * MARGIN;
const BOTTOM = PAGE_H - 24; // content stops here; the footer sits below
const PT = 0.3528;
const lineH = (size: number) => size * PT * 1.4;

// The built-in Helvetica only has WinAnsi glyphs: anything else would print as junk.
const WIN_ANSI_EXTRA = "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ";
const FALLBACK: Record<string, string> = { "→": "->", "←": "<-", "≥": ">=", "≤": "<=", "≈": "~" };

/** Text the built-in PDF font can print: other characters lose their accents or become ASCII. */
export function pdfText(s: string): string {
  return [...s]
    .map((ch) => {
      const code = ch.codePointAt(0) ?? 0;
      if ((code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff) || WIN_ANSI_EXTRA.includes(ch)) return ch;
      return FALLBACK[ch] ?? (ch.normalize("NFKD").replace(/[^\x20-\x7e]/g, "") || "?");
    })
    .join("");
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

/** Why a finding needs fixing, in one plain sentence. */
function reason(f: Finding): string {
  const c = f.classification;
  const harvest = c.hndl ? " Traffic recorded today can be decrypted later." : "";
  switch (c.tier) {
    case "critical":
      return (c.classically_broken ? "Already broken today, and Shor’s algorithm breaks it." : "Shor’s algorithm breaks it.") + harvest;
    case "medium":
      return c.classically_broken ? "Already broken today, and Grover’s algorithm weakens it further." : "Grover’s algorithm halves its strength.";
    case "unknown":
      return "No rule matches it yet, so check it by hand.";
    default:
      return "";
  }
}

function draw(doc: jsPDF, result: ScanResult, reportUrl: string): void {
  let y = MARGIN;
  const all = result.findings;
  const counts = tally(all);

  const color = (c: Rgb) => doc.setTextColor(c[0], c[1], c[2]);
  const fill = (c: Rgb) => doc.setFillColor(c[0], c[1], c[2]);
  const font = (size: number, bold = false, c: Rgb = INK) => {
    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setFontSize(size);
    color(c);
  };
  /** Lines of `text` at the current font, wrapped to `width`. */
  const wrap = (text: string, width: number) => doc.splitTextToSize(pdfText(text), width) as string[];
  const write = (text: string, x: number, at: number, align: "left" | "right" = "left") =>
    doc.text(pdfText(text), x, at, { baseline: "top", align });
  const rule = (at: number, c: Rgb = RULE, from = MARGIN, to = PAGE_W - MARGIN) => {
    doc.setDrawColor(c[0], c[1], c[2]);
    doc.setLineWidth(0.2);
    doc.line(from, at, to, at);
  };
  /** Start a new page unless `h` more millimetres fit on this one. */
  const room = (h: number) => {
    if (y + h <= BOTTOM) return;
    doc.addPage();
    y = MARGIN;
  };
  const para = (text: string, o: { size?: number; bold?: boolean; c?: Rgb; x?: number; width?: number; after?: number } = {}) => {
    const { size = 10, bold = false, c = INK, x = MARGIN, width = WIDTH, after = 0 } = o;
    font(size, bold, c);
    for (const line of wrap(text, width)) {
      room(lineH(size));
      doc.text(line, x, y, { baseline: "top" });
      y += lineH(size);
    }
    y += after;
  };
  const section = (title: string, sub?: string) => {
    room(22); // never strand a heading at the foot of a page
    y += 4;
    para(title, { size: 12.5, bold: true, after: 0.5 });
    if (sub) para(sub, { size: 8.5, c: MUTED });
    y += 3;
  };

  // ---------------------------------------------------------------- header
  // The site's wordmark: a miniature debt strip, two Shor ticks, one Grover, one resilient.
  const ticks: [number, number, Rgb][] = [
    [0, 4.6, TIER_RGB.critical],
    [1.5, 4.6, TIER_RGB.critical],
    [3, 3, TIER_RGB.medium],
    [4.5, 1.8, TIER_RGB.safe],
  ];
  for (const [dx, h, c] of ticks) {
    fill(c);
    doc.rect(MARGIN + dx, y + 4.6 - h, 0.8, h, "F");
  }
  font(11, true);
  write("QuantumTrace", MARGIN + 7.5, y + 0.3);
  font(9, false, MUTED);
  write("Post-quantum readiness summary", PAGE_W - MARGIN, y + 0.8, "right");
  y += 9;
  rule(y);
  y += 5;

  const shown = result.targets.slice(0, 4).join(", ");
  const more = result.targets.length > 4 ? `, and ${result.targets.length - 4} more` : "";
  para(`Scan run ${dateFmt.format(new Date(result.created_at))} on ${shown}${more}`, { size: 8.5, c: MUTED, after: 6 });

  // ---------------------------------------------------------------- headline
  const headline = counts.c
    ? `${counts.c} of ${all.length} cryptographic assets are critical.`
    : all.length
      ? `None of these ${plural(all.length, "asset")} is breakable by Shor’s algorithm.`
      : "No cryptography found.";
  font(18, true);
  if (counts.c && wrap(headline, WIDTH).length === 1) {
    // The count in crimson, like the report's hero.
    const n = String(counts.c);
    color(TIER_RGB.critical);
    write(n, MARGIN, y);
    color(INK);
    write(headline.slice(n.length), MARGIN + doc.getTextWidth(n), y);
    y += lineH(18);
  } else {
    para(headline, { size: 18, bold: true });
  }
  y += 1.5;
  para(
    all.length
      ? heroSub(counts)
      : "None of the scanners recognised anything in these files. QuantumTrace reads AWS posture exports (JSON), Python, Java and Go source, and .pcap or .pcapng captures.",
    { size: 10, c: MUTED, after: 7 },
  );

  if (all.length) {
    // ---------------------------------------------------------------- score and tiers
    room(42);
    const top = y;
    font(8.5, false, MUTED);
    write("Quantum risk score", MARGIN, top);
    const value = result.score.value.toFixed(1);
    const base = top + 5 + 30 * PT * 0.72; // the big number's baseline
    font(30, true);
    doc.text(value, MARGIN, base);
    const valueW = doc.getTextWidth(value);
    font(9, false, MUTED);
    doc.text(pdfText(`of 100 · grade ${result.score.grade}`), MARGIN + valueW + 2.5, base);
    y = base + 3;
    para("0 is quantum-ready, 100 is every asset broken and exposed.", { size: 7.5, c: FAINT, width: 54 });
    const leftEnd = y;

    const x0 = MARGIN + 68;
    const w = PAGE_W - MARGIN - x0;
    font(8.5, false, MUTED);
    write("Assets by quantum risk", x0, top);
    const present = TIERS.filter((t) => tierCount(t) > 0);
    const gap = 0.8;
    let x = x0;
    for (const t of present) {
      const segW = ((w - gap * (present.length - 1)) * tierCount(t)) / all.length;
      fill(TIER_RGB[t]);
      doc.rect(x, top + 5.5, segW, 5, "F");
      x += segW + gap;
    }
    let row = top + 14;
    for (const t of TIERS) {
      fill(TIER_RGB[t]);
      doc.rect(x0, row + 0.5, 2.6, 2.6, "F");
      font(9.5, true);
      write(String(tierCount(t)), x0 + 17, row, "right");
      write(TIER[t].label, x0 + 20, row);
      font(9, false, MUTED);
      write(TIER[t].threat, x0 + 44, row);
      row += 5.6;
    }
    y = Math.max(leftEnd, row) + 3;

    // ---------------------------------------------------------------- by source
    const sources = SOURCES.map((s) => ({ s, f: all.filter((f) => f.asset.evidence.source_type === s) })).filter(
      (g) => g.f.length > 0,
    );
    if (sources.length > 1) {
      section("By source");
      const cols: [string, number][] = [
        ["Assets", MARGIN + 82],
        ["Critical", MARGIN + 104],
        ["Medium", MARGIN + 126],
        ["Safe", MARGIN + 148],
        ["Risk score", PAGE_W - MARGIN],
      ];
      font(8, false, MUTED);
      write("Source", MARGIN, y);
      for (const [label, at] of cols) write(label, at, y, "right");
      y += 5;
      rule(y, RULE_STRONG);
      for (const { s, f } of sources) {
        room(7);
        y += 2;
        const t = tally(f);
        const score = result.score_by_source[s];
        font(9.5);
        write(SOURCE_LABEL[s], MARGIN, y);
        write(String(f.length), cols[0]![1], y, "right");
        color(TIER_RGB.critical);
        write(String(t.c), cols[1]![1], y, "right");
        color(INK);
        write(String(t.m), cols[2]![1], y, "right");
        write(String(t.s), cols[3]![1], y, "right");
        write(score ? `${score.value.toFixed(1)}  ${score.grade}` : "–", cols[4]![1], y, "right");
        y += 4.5;
        rule(y);
      }
      y += 2;
    }

    // ---------------------------------------------------------------- fix first
    const rows = fixRows(all).filter((r) => r.fixBy !== "none");
    section(
      "What to fix first",
      rows.length ? "Most urgent first. The same cryptography in several places counts once." : undefined,
    );
    if (!rows.length) para("Nothing. Every asset found is quantum-resistant.", { size: 9.5, after: 2 });
    for (const r of rows.slice(0, FIX_SHOWN)) fixItem(r);
    if (rows.length > FIX_SHOWN) {
      para(`And ${plural(rows.length - FIX_SHOWN, "more issue")} in the full report.`, { size: 8.5, c: MUTED, after: 2 });
    }
  }

  // ---------------------------------------------------------------- blind spots
  const notes = result.limitations.map((n) => n.message);
  if (all.length && !all.some((f) => f.asset.evidence.source_type === "network")) {
    notes.push(
      "No packet capture in this scan, so nothing here shows what clients actually negotiate, or how much traffic is already being recorded with these keys.",
    );
  }
  if (result.errors.length) {
    notes.unshift(`${plural(result.errors.length, "input")} couldn’t be scanned: ${result.errors.slice(0, 3).join("; ")}.`);
  }
  if (notes.length) {
    section("What this scan couldn’t see", "Stated so nobody mistakes silence for safety.");
    for (const note of notes.slice(0, NOTES_SHOWN)) {
      font(8.5);
      room(lineH(8.5) * Math.min(wrap(note, WIDTH - 4).length, 3));
      write("•", MARGIN, y);
      para(note, { size: 8.5, x: MARGIN + 4, width: WIDTH - 4, after: 1.5 });
    }
    if (notes.length > NOTES_SHOWN) {
      para(`And ${plural(notes.length - NOTES_SHOWN, "more")} in the full report.`, { size: 8.5, c: MUTED });
    }
  }

  // ---------------------------------------------------------------- where the detail is
  room(16);
  y += 6;
  para(
    "For every finding with its file, line and NIST reference, open the full report, or export its CBOM (CycloneDX 1.6) from there.",
    { size: 8.5, c: MUTED, after: 1 },
  );
  font(8.5);
  doc.textWithLink(pdfText(reportUrl), MARGIN, y + 8.5 * PT, { url: reportUrl });

  // ---------------------------------------------------------------- footer on every page
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    rule(PAGE_H - 15);
    font(7.5, false, FAINT);
    write(`QuantumTrace · scan ${result.id.slice(0, 8)} · classified against NIST FIPS 203, 204 and 205`, MARGIN, PAGE_H - 12.5);
    write(`Page ${i} of ${pages}`, PAGE_W - MARGIN, PAGE_H - 12.5, "right");
  }

  function tierCount(t: RiskTier): number {
    return { critical: counts.c, medium: counts.m, unknown: counts.u, safe: counts.s }[t];
  }

  function fixItem(r: FixRow) {
    const f = r.lead;
    const x = MARGIN + 27;
    const w = PAGE_W - MARGIN - x;
    const usage = f.asset.usage ? ` · ${usageLabel(f.asset.usage)}` : "";
    const others = r.members.length - 1;
    const where = [
      placeLabel(f) + (others ? `, and ${plural(others, "more place")}` : ""),
      f.asset.exposure === "internet" ? "internet-facing" : "",
    ]
      .filter(Boolean)
      .join(" · ");
    const replacement = f.classification.replacement ? ` Recommended: ${f.classification.replacement}.` : "";
    font(10, true);
    const title = wrap(algorithmLabel(f) + usage, w);
    font(8.5);
    const place = wrap(where, w);
    const advice = wrap(reason(f) + replacement, w);
    room(title.length * lineH(10) + (place.length + advice.length) * lineH(8.5) + 6);

    font(8, true, FIX_RGB[r.fixBy]);
    write(FIX_BY[r.fixBy].label, MARGIN, y + 0.5);
    font(10, true);
    for (const line of title) {
      doc.text(line, x, y, { baseline: "top" });
      y += lineH(10);
    }
    y += 0.5;
    font(8.5, false, MUTED);
    for (const line of place) {
      doc.text(line, x, y, { baseline: "top" });
      y += lineH(8.5);
    }
    font(8.5);
    for (const line of advice) {
      doc.text(line, x, y, { baseline: "top" });
      y += lineH(8.5);
    }
    y += 2.5;
    rule(y);
    y += 3;
  }
}
