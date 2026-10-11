"""The one- or two-page PDF summary `quantumtrace report` writes beside report.json and the CBOM:
the headline, the score, what to fix first and what the scan couldn't see.

It mirrors the web app's export (`frontend/apps/web/src/lib/pdf.ts`, with `lib/fix.ts`,
`lib/summary.ts` and the labels in `packages/ui/src/labels.ts`), so both say the same thing.
Formatting only: tiers, names and replacements come from the engine.
"""

# The printed copy uses typographic apostrophes and dashes on purpose, like the web's.
# ruff: noqa: RUF001

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from quantumtrace.core.models import Exposure, Finding, RiskTier, ScanResult, SourceType
from quantumtrace.report.pdf import PAGE_H, PAGE_W, PT, Canvas, Rgb, pdf_text, rgb, text_width

FIX_SHOWN = 8
NOTES_SHOWN = 6

# Paper is always light, so the light theme's tokens (packages/ui/src/tokens.css).
INK = rgb("#1b2430")
MUTED = rgb("#5b6878")
FAINT = rgb("#8a96a5")
RULE = rgb("#d5dbe2")
RULE_STRONG = rgb("#aeb8c4")
PANEL = rgb("#eef1f5")
TIER_RGB: dict[RiskTier, Rgb] = {
    RiskTier.CRITICAL: rgb("#b3123f"),
    RiskTier.MEDIUM: rgb("#9a6a12"),
    RiskTier.UNKNOWN: rgb("#6b7685"),
    RiskTier.SAFE: rgb("#0f7b6c"),
}
TIERS = [RiskTier.CRITICAL, RiskTier.MEDIUM, RiskTier.UNKNOWN, RiskTier.SAFE]
TIER_LABEL: dict[RiskTier, tuple[str, str]] = {
    RiskTier.CRITICAL: ("Critical", "Breakable by Shor"),
    RiskTier.MEDIUM: ("Medium", "Weakened by Grover"),
    RiskTier.UNKNOWN: ("Unclassified", "No rule matches yet"),
    RiskTier.SAFE: ("Safe", "Quantum-resistant"),
}
SOURCES = [SourceType.CLOUD, SourceType.CODE, SourceType.NETWORK]
SOURCE_LABEL = {
    SourceType.CLOUD: "Cloud posture",
    SourceType.CODE: "Source code",
    SourceType.NETWORK: "Network capture",
}

FixBy = Literal["now", "before-2030", "harden", "review", "none"]
FIX_BY: dict[FixBy, tuple[int, str, Rgb]] = {
    "now": (0, "Fix now", TIER_RGB[RiskTier.CRITICAL]),
    "before-2030": (1, "Before 2030", TIER_RGB[RiskTier.CRITICAL]),
    "harden": (2, "Harden", TIER_RGB[RiskTier.MEDIUM]),
    "review": (3, "Review", TIER_RGB[RiskTier.UNKNOWN]),
    "none": (4, "No action", TIER_RGB[RiskTier.SAFE]),
}

NOTHING_FOUND = (
    "None of the scanners recognised anything in these files. QuantumTrace reads AWS posture "
    "exports (JSON), Python, Java and Go source, SSH and TLS server configs, certificates and "
    "keys, Java and Go builds, and .pcap or .pcapng captures."
)

USAGE_LABELS = {
    "SIGN_VERIFY": "Signing key",
    "ENCRYPT_DECRYPT": "Encryption key",
    "KEY_AGREEMENT": "Key agreement",
    "GENERATE_VERIFY_MAC": "MAC key",
    "signature-digest": "Signature digest",
    "certificate-key": "Certificate key",
    "certificate-signature": "Certificate signature",
    "certificate-signature-digest": "Certificate digest",
    "tls-protocol": "TLS version",
    "tls-key-exchange": "TLS key exchange",
    "tls-authentication": "TLS authentication",
    "tls-cipher": "TLS cipher",
    "tls-mac": "TLS record MAC",
    "tls-policy": "TLS policy",
    "tls-cipher-suite": "TLS cipher suite",
    "transport": "Cleartext transport",
    "hash": "Hashing",
    "mac": "Message authentication",
    "kdf": "Key derivation",
    "kdf-prf": "Key derivation PRF",
    "signature": "Signing",
    "key-generation": "Key generation",
    "key-agreement": "Key agreement",
    "encryption": "Encryption",
    "rng": "Random numbers",
    "ssh-key-exchange": "SSH key exchange",
    "ssh-host-key": "SSH host key",
    "ssh-cipher": "SSH cipher",
    "ssh-mac": "SSH MAC",
    "ssh-kex-hash": "SSH exchange hash",
    "ssh-signature-digest": "SSH signature digest",
    "ssh-user-key": "SSH user key",
    "private-key": "Private key",
    "public-key": "Public key",
}

# A4 in millimetres. Font sizes are points.
MARGIN = 18.0
WIDTH = PAGE_W - 2 * MARGIN
BOTTOM = PAGE_H - 24  # content stops here; the footer sits below


def line_h(size: float) -> float:
    return size * PT * 1.4


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def usage_label(usage: str | None) -> str:
    if not usage:
        return "Unspecified"
    return USAGE_LABELS.get(usage) or usage.replace("-", " ").replace("_", " ")


def algorithm_label(f: Finding) -> str:
    """The precise form when known (AES-128-GCM, x25519, ECDSA P-384), else name and key size."""
    if f.asset.variant:
        return f.asset.variant
    size, name = f.asset.key_size, f.classification.name
    return f"{name}-{size}" if size and str(size) not in name else name


def place_label(f: Finding) -> str:
    """Where a finding lives: KMS alias, certificate domain, load balancer:port, server, or file."""
    ctx = f.asset.evidence.context
    if ctx.get("alias"):
        return ctx["alias"]
    if ctx.get("domain"):
        return ctx["domain"]
    if lb := ctx.get("load_balancer"):
        return f"{lb}:{ctx['port']}" if ctx.get("port") else lb
    if server := ctx.get("server"):
        host = ctx["sni"] if "sni" in ctx else ctx.get("host", server)
        return f"{ctx.get('service', 'tcp')} {host}:{ctx.get('server_port', '')}"
    loc = f.asset.evidence.location.replace("\\", "/")
    line = f":{f.asset.evidence.line}" if f.asset.evidence.line else ""
    return "/".join(loc.split("/")[-2:]) + line


@dataclass(frozen=True)
class Tally:
    c: int
    m: int
    u: int
    s: int
    internet_critical: int
    hndl: int
    internet_hndl: int


def tally(findings: list[Finding]) -> Tally:
    def count(tier: RiskTier) -> int:
        return sum(f.classification.tier is tier for f in findings)

    internet = [f for f in findings if f.asset.exposure is Exposure.INTERNET]
    return Tally(
        c=count(RiskTier.CRITICAL),
        m=count(RiskTier.MEDIUM),
        u=count(RiskTier.UNKNOWN),
        s=count(RiskTier.SAFE),
        internet_critical=sum(f.classification.tier is RiskTier.CRITICAL for f in internet),
        hndl=sum(f.classification.hndl for f in findings),
        internet_hndl=sum(f.classification.hndl for f in internet),
    )


def headline(result: ScanResult) -> str:
    n, c = len(result.findings), tally(result.findings).c
    if c:
        return f"{c} of {n} cryptographic assets are critical."
    if n:
        return f"None of these {plural(n, 'asset')} is breakable by Shor’s algorithm."
    return "No cryptography found."


def hero_sub(t: Tally) -> str:
    """The sentence under the headline: why the critical ones matter, then the rest by tier."""
    rest = [
        part
        for part in (
            f"{t.m} {'more ' if t.c else ''}{'is' if t.m == 1 else 'are'} medium, weakened by "
            "Grover’s"
            if t.m
            else "",
            f"{t.u} {'is' if t.u == 1 else 'are'} unclassified" if t.u else "",
            f"{t.s} {'is' if t.s == 1 else 'are'} safe" if t.s else "",
        )
        if part
    ]
    listed = f"{', '.join(rest[:-1])} and {rest[-1]}" if len(rest) > 1 else "".join(rest)
    lead = "Shor’s algorithm breaks them outright." if t.c else ""
    harvest = (
        f"{t.hndl} of them "
        f"{'is a key exchange or encryption' if t.hndl == 1 else 'are key exchanges or encryption'}"
        ", exposed to harvest-now, decrypt-later."
        if t.hndl
        else ""
    )
    # only key exchanges and encryption are harvested; a signature has to be forged live
    harvested = (
        f", {t.internet_hndl} of them key exchanges or encryption whose traffic can be recorded "
        "today and decrypted later"
        if t.internet_hndl
        else ""
    )
    exposure = ""
    if t.c:
        exposure = (
            f"{t.internet_critical} of the critical ones sit on internet-facing endpoints"
            f"{harvested}."
            if t.internet_critical
            else "None of them faces the internet directly."
        )
    sentence = f"{listed[:1].upper()}{listed[1:]}." if listed else ""
    return " ".join(part for part in (lead, harvest, sentence, exposure) if part)


def fix_by(f: Finding) -> FixBy:
    """When to fix, from the engine's tier and classically-broken flag. Ordering only."""
    c = f.classification
    if c.tier is RiskTier.CRITICAL:
        return "now" if c.classically_broken else "before-2030"
    if c.tier is RiskTier.MEDIUM:
        return "harden"
    return "review" if c.tier is RiskTier.UNKNOWN else "none"


@dataclass
class FixRow:
    key: str
    lead: Finding
    fix_by: FixBy
    members: list[Finding] = field(default_factory=list)


def group_key(f: Finding) -> str:
    """Identical crypto in several places: same tier, rule, variant, usage, flags, exposure and
    source."""
    a = f.asset
    return "|".join([
        f.classification.tier.value, f.classification.rule_id, a.variant or "", a.usage or "",
        "+".join(sorted(a.flags)), a.exposure.value, a.evidence.source_type.value,
    ])  # fmt: skip


def fix_rows(findings: list[Finding]) -> list[FixRow]:
    """Most urgent first: when to fix, then already broken, then harvest-now-decrypt-later, then
    internet-facing, then how many places."""
    rows: dict[str, FixRow] = {}
    for f in findings:
        key = group_key(f)
        if key not in rows:
            rows[key] = FixRow(key, f, fix_by(f))
        rows[key].members.append(f)

    def order(r: FixRow) -> tuple[int, int, int, int, int, int, str]:
        c = r.lead.classification
        return (
            FIX_BY[r.fix_by][0],
            -c.classically_broken,
            -c.hndl,
            -(r.lead.asset.exposure is Exposure.INTERNET),
            -len(r.members),
            TIERS.index(c.tier),
            r.key,
        )

    return sorted(rows.values(), key=order)


def reason(f: Finding) -> str:
    """Why a finding needs fixing, in one plain sentence."""
    c = f.classification
    harvest = " Traffic recorded today can be decrypted later." if c.hndl else ""
    if c.tier is RiskTier.CRITICAL:
        broken = "Already broken today, and Shor’s algorithm breaks it."
        return (broken if c.classically_broken else "Shor’s algorithm breaks it.") + harvest
    if c.tier is RiskTier.MEDIUM:
        if c.classically_broken:
            return "Already broken today, and Grover’s algorithm weakens it further."
        return "Grover’s algorithm halves its strength."
    if c.tier is RiskTier.UNKNOWN:
        return "No rule matches it yet, so check it by hand."
    return ""


def wrap(text: str, width: float, size: float, bold: bool = False) -> list[str]:
    """Lines of `text` at `size` that fit `width`; a word wider than the line breaks anywhere."""
    lines: list[str] = []
    line = ""
    for word in pdf_text(text).split(" "):
        candidate = f"{line} {word}" if line else word
        if text_width(candidate, size, bold) <= width:
            line = candidate
            continue
        if line:
            lines.append(line)
        while len(word) > 1 and text_width(word, size, bold) > width:
            cut = len(word) - 1
            while cut > 1 and text_width(word[:cut], size, bold) > width:
                cut -= 1
            lines.append(word[:cut])
            word = word[cut:]
        line = word
    if line or not lines:
        lines.append(line)
    return lines


def render_summary(
    result: ScanResult, *, report_name: str = "report.json", cbom_name: str = "cbom.cdx.json"
) -> bytes:
    """The summary as PDF bytes. `report_name` and `cbom_name` are the files it points to for
    the detail, written next to it."""
    canvas = Canvas(title="QuantumTrace summary", subject=", ".join(result.targets))
    _Sheet(canvas, result, report_name, cbom_name).draw()
    return canvas.save()


class _Sheet:
    def __init__(self, canvas: Canvas, result: ScanResult, report_name: str, cbom_name: str):
        self.canvas = canvas
        self.result = result
        self.report_name = report_name
        self.cbom_name = cbom_name
        self.y = MARGIN

    # ------------------------------------------------------------------ drawing helpers
    def write(
        self,
        text: str,
        x: float,
        at: float,
        size: float,
        bold: bool = False,
        color: Rgb = INK,
        align: Literal["left", "right"] = "left",
    ) -> None:
        self.canvas.text(text, x, at, size=size, bold=bold, color=color, align=align)

    def rule(
        self, at: float, color: Rgb = RULE, start: float = MARGIN, end: float = PAGE_W - MARGIN
    ) -> None:
        self.canvas.line(start, at, end, at, color, 0.2)

    def room(self, h: float) -> None:
        """Start a new page unless `h` more millimetres fit on this one."""
        if self.y + h <= BOTTOM:
            return
        self.canvas.add_page()
        self.y = MARGIN

    def para(
        self,
        text: str,
        *,
        size: float = 10,
        bold: bool = False,
        color: Rgb = INK,
        x: float = MARGIN,
        width: float = WIDTH,
        after: float = 0,
    ) -> None:
        for line in wrap(text, width, size, bold):
            self.room(line_h(size))
            self.write(line, x, self.y, size, bold, color)
            self.y += line_h(size)
        self.y += after

    def section(self, title: str, sub: str | None = None) -> None:
        self.room(22)  # never strand a heading at the foot of a page
        self.y += 4
        self.para(title, size=12.5, bold=True, after=0.5)
        if sub:
            self.para(sub, size=8.5, color=MUTED)
        self.y += 3

    # ------------------------------------------------------------------ the page
    def draw(self) -> None:
        self.header()
        findings = self.result.findings
        if findings:
            self.score()
            self.by_source()
            self.fix_first()
        self.blind_spots()
        self.details()
        self.footer()

    def header(self) -> None:
        result, y = self.result, self.y
        # The site's wordmark: a miniature debt strip, two Shor ticks, one Grover, one resilient.
        for dx, h, tier in (
            (0.0, 4.6, RiskTier.CRITICAL),
            (1.5, 4.6, RiskTier.CRITICAL),
            (3.0, 3.0, RiskTier.MEDIUM),
            (4.5, 1.8, RiskTier.SAFE),
        ):
            self.canvas.rect(MARGIN + dx, y + 4.6 - h, 0.8, h, TIER_RGB[tier])
        self.write("QuantumTrace", MARGIN + 7.5, y + 0.3, 11, bold=True)
        self.write(
            "Post-quantum readiness summary",
            PAGE_W - MARGIN,
            y + 0.8,
            9,
            color=MUTED,
            align="right",
        )
        self.y += 9
        self.rule(self.y)
        self.y += 5

        when = result.created_at.astimezone()
        shown = ", ".join(result.targets[:4])
        more = f", and {len(result.targets) - 4} more" if len(result.targets) > 4 else ""
        self.para(
            f"Scan run {when.day} {when:%b %Y, %H:%M} on {shown}{more}",
            size=8.5,
            color=MUTED,
            after=6,
        )

        title = headline(result)
        counts = tally(result.findings)
        if counts.c and len(wrap(title, WIDTH, 18, bold=True)) == 1:
            # The count in crimson, like the report's hero.
            n = str(counts.c)
            self.write(n, MARGIN, self.y, 18, bold=True, color=TIER_RGB[RiskTier.CRITICAL])
            self.write(title[len(n) :], MARGIN + text_width(n, 18, True), self.y, 18, bold=True)
            self.y += line_h(18)
        else:
            self.para(title, size=18, bold=True)
        self.y += 1.5
        self.para(
            hero_sub(counts) if result.findings else NOTHING_FOUND, size=10, color=MUTED, after=7
        )

    def score(self) -> None:
        result, all_ = self.result, self.result.findings
        counts = tally(all_)
        per_tier = {
            RiskTier.CRITICAL: counts.c,
            RiskTier.MEDIUM: counts.m,
            RiskTier.UNKNOWN: counts.u,
            RiskTier.SAFE: counts.s,
        }
        self.room(42)
        top = self.y
        self.write("Quantum risk score", MARGIN, top, 8.5, color=MUTED)
        value = f"{result.score.value:.1f}"
        base = top + 5 + 30 * PT * 0.72  # the big number's baseline
        self.canvas.text(value, MARGIN, base, size=30, bold=True, color=INK, baseline="alphabetic")
        self.canvas.text(
            f"of 10 · grade {result.score.grade}",
            MARGIN + text_width(value, 30, True) + 2.5,
            base,
            size=9,
            color=MUTED,
            baseline="alphabetic",
        )
        self.y = base + 3
        self.para(
            "0 is quantum-ready, 10 is every asset broken and exposed.",
            size=7.5,
            color=FAINT,
            width=54,
        )
        left_end = self.y

        x0 = MARGIN + 68
        w = PAGE_W - MARGIN - x0
        self.write("Assets by quantum risk", x0, top, 8.5, color=MUTED)
        present = [t for t in TIERS if per_tier[t]]
        gap = 0.8
        x = x0
        for t in present:
            seg = (w - gap * (len(present) - 1)) * per_tier[t] / len(all_)
            self.canvas.rect(x, top + 5.5, seg, 5, TIER_RGB[t])
            x += seg + gap
        row = top + 14
        for t in TIERS:
            label, threat = TIER_LABEL[t]
            self.canvas.rect(x0, row + 0.5, 2.6, 2.6, TIER_RGB[t])
            self.write(str(per_tier[t]), x0 + 17, row, 9.5, bold=True, align="right")
            self.write(label, x0 + 20, row, 9.5, bold=True)
            self.write(threat, x0 + 44, row, 9, color=MUTED)
            row += 5.6
        self.y = max(left_end, row) + 3

    def by_source(self) -> None:
        groups = [
            (s, [f for f in self.result.findings if f.asset.evidence.source_type is s])
            for s in SOURCES
        ]
        groups = [(s, fs) for s, fs in groups if fs]
        if len(groups) < 2:
            return
        self.section("By source")
        cols = [
            ("Assets", MARGIN + 82),
            ("Critical", MARGIN + 104),
            ("Medium", MARGIN + 126),
            ("Safe", MARGIN + 148),
            ("Risk score", PAGE_W - MARGIN),
        ]
        self.write("Source", MARGIN, self.y, 8, color=MUTED)
        for label, at in cols:
            self.write(label, at, self.y, 8, color=MUTED, align="right")
        self.y += 5
        self.rule(self.y, RULE_STRONG)
        for source, fs in groups:
            self.room(7)
            self.y += 2
            t = tally(fs)
            score = self.result.score_by_source.get(source)
            y = self.y
            self.write(SOURCE_LABEL[source], MARGIN, y, 9.5)
            self.write(str(len(fs)), cols[0][1], y, 9.5, align="right")
            self.write(
                str(t.c), cols[1][1], y, 9.5, color=TIER_RGB[RiskTier.CRITICAL], align="right"
            )
            self.write(str(t.m), cols[2][1], y, 9.5, align="right")
            self.write(str(t.s), cols[3][1], y, 9.5, align="right")
            shown = f"{score.value:.1f}  {score.grade}" if score else "–"
            self.write(shown, cols[4][1], y, 9.5, align="right")
            self.y += 4.5
            self.rule(self.y)
        self.y += 2

    def fix_first(self) -> None:
        rows = [r for r in fix_rows(self.result.findings) if r.fix_by != "none"]
        self.section(
            "What to fix first",
            "Most urgent first. The same cryptography in several places counts once."
            if rows
            else None,
        )
        if not rows:
            self.para("Nothing. Every asset found is quantum-resistant.", size=9.5, after=2)
        for r in rows[:FIX_SHOWN]:
            self.fix_item(r)
        if len(rows) > FIX_SHOWN:
            self.para(
                f"And {plural(len(rows) - FIX_SHOWN, 'more issue')} in {self.report_name}.",
                size=8.5,
                color=MUTED,
                after=2,
            )

    def fix_item(self, r: FixRow) -> None:
        f, c = r.lead, r.lead.classification
        x = MARGIN + 27
        w = PAGE_W - MARGIN - x
        usage = f" · {usage_label(f.asset.usage)}" if f.asset.usage else ""
        others = len(r.members) - 1
        where = " · ".join(
            part
            for part in (
                place_label(f) + (f", and {plural(others, 'more place')}" if others else ""),
                "internet-facing" if f.asset.exposure is Exposure.INTERNET else "",
            )
            if part
        )
        replacement = f" Recommended: {c.replacement}." if c.replacement else ""
        title = wrap(algorithm_label(f) + usage, w, 10, bold=True)
        place = wrap(where, w, 8.5)
        advice = wrap(reason(f) + replacement, w, 8.5)
        self.room(len(title) * line_h(10) + (len(place) + len(advice)) * line_h(8.5) + 6)

        _, label, color = FIX_BY[r.fix_by]
        self.write(label, MARGIN, self.y + 0.5, 8, bold=True, color=color)
        for line in title:
            self.write(line, x, self.y, 10, bold=True)
            self.y += line_h(10)
        self.y += 0.5
        for line in place:
            self.write(line, x, self.y, 8.5, color=MUTED)
            self.y += line_h(8.5)
        for line in advice:
            self.write(line, x, self.y, 8.5)
            self.y += line_h(8.5)
        self.y += 2.5
        self.rule(self.y)
        self.y += 3

    def blind_spots(self) -> None:
        result, all_ = self.result, self.result.findings
        notes = [n.message for n in result.limitations]
        if all_ and not any(f.asset.evidence.source_type is SourceType.NETWORK for f in all_):
            notes.append(
                "No packet capture in this scan, so nothing here shows what clients actually "
                "negotiate, or how much traffic is already being recorded with these keys."
            )
        if result.errors:
            notes.insert(
                0,
                f"{plural(len(result.errors), 'input')} couldn’t be scanned: "
                f"{'; '.join(result.errors[:3])}.",
            )
        if not notes:
            return
        self.section("What this scan couldn’t see", "Stated so nobody mistakes silence for safety.")
        for note in notes[:NOTES_SHOWN]:
            self.room(line_h(8.5) * min(len(wrap(note, WIDTH - 4, 8.5)), 3))
            self.write("•", MARGIN, self.y, 8.5)
            self.para(note, size=8.5, x=MARGIN + 4, width=WIDTH - 4, after=1.5)
        if len(notes) > NOTES_SHOWN:
            self.para(
                f"And {plural(len(notes) - NOTES_SHOWN, 'more note')} in {self.report_name}.",
                size=8.5,
                color=MUTED,
            )

    def details(self) -> None:
        """A shaded callout rather than a footnote: this summary is the skim, the files beside
        it are the substance."""
        pad = 5.0
        text_x = MARGIN + 1.2 + pad
        text_w = PAGE_W - MARGIN - pad - text_x
        note = wrap(
            "Every finding with its file, line, evidence and NIST reference, and the CBOM "
            "(CycloneDX 1.6) to hand to other tools.",
            text_w,
            9,
        )
        files = wrap(f"{self.report_name}  ·  {self.cbom_name}", text_w, 9.5, bold=True)
        box_h = pad + line_h(11.5) + 1 + len(note) * line_h(9) + 2.5
        box_h += len(files) * line_h(9.5) + pad - 1
        self.room(box_h + 8)
        self.y += 8
        self.canvas.rect(MARGIN, self.y, WIDTH, box_h, PANEL)
        self.canvas.rect(MARGIN, self.y, 1.2, box_h, INK)
        self.y += pad
        self.write("The full details are in the files beside this one", text_x, self.y, 11.5, True)
        self.y += line_h(11.5) + 1
        for line in note:
            self.write(line, text_x, self.y, 9)
            self.y += line_h(9)
        self.y += 2.5
        for line in files:
            self.write(line, text_x, self.y, 9.5, bold=True)
            self.y += line_h(9.5)

    def footer(self) -> None:
        pages = self.canvas.page_count
        scan = self.result.id[:8]
        for i in range(pages):
            self.canvas.set_page(i)
            self.rule(PAGE_H - 15)
            self.write(
                f"QuantumTrace · scan {scan} · classified against NIST FIPS 203, 204 and 205",
                MARGIN,
                PAGE_H - 12.5,
                7.5,
                color=FAINT,
            )
            self.write(
                f"Page {i + 1} of {pages}", PAGE_W - MARGIN, PAGE_H - 12.5, 7.5, color=FAINT,
                align="right",
            )  # fmt: skip
