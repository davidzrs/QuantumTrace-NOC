"""A small PDF writer for the offline summary: A4 pages in the built-in Helvetica faces, with
text, filled rectangles and lines. Standard library only, so `quantumtrace report` needs no extra
package and nothing from the network. Coordinates are millimetres from the top-left corner, as in
the web app's jsPDF export (`frontend/apps/web/src/lib/pdf.ts`).
"""

# The glyph tables list typographic punctuation on purpose.
# ruff: noqa: RUF001

from __future__ import annotations

import re
import unicodedata
from typing import Literal

PAGE_W = 210.0
PAGE_H = 297.0
PT = 0.3528  # millimetres per point
_K = 72 / 25.4  # points per millimetre
_ASCENT = 0.75  # top of a line to its baseline, as a share of the font size

Rgb = tuple[int, int, int]


def rgb(hex_colour: str) -> Rgb:
    return (int(hex_colour[1:3], 16), int(hex_colour[3:5], 16), int(hex_colour[5:7], 16))


# Advance widths (1/1000 em) of ASCII 32-126 in Helvetica and Helvetica-Bold (Adobe AFM).
_ASCII_WIDTHS: tuple[list[int], list[int]] = (
    [
        278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
    ],
    [
        278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
        975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
        333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
        611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
    ],
)  # fmt: skip
# WinAnsi punctuation beyond ASCII; accented letters take their base letter's width.
_EXTRA_WIDTHS: dict[str, tuple[int, int]] = {
    "’": (222, 278), "‘": (222, 278), "‚": (222, 278), "“": (333, 500), "”": (333, 500),
    "„": (333, 500), "•": (350, 350), "–": (556, 556), "—": (1000, 1000), "…": (1000, 1000),
    "·": (278, 278), "€": (556, 556), " ": (278, 278), "°": (400, 400), "×": (584, 584),
    "©": (737, 737), "®": (737, 737), "«": (556, 556), "»": (556, 556), "ß": (611, 611),
    "æ": (889, 889), "Æ": (1000, 1000), "™": (1000, 1000), "±": (584, 584),
}  # fmt: skip

# The built-in fonts only have WinAnsi glyphs: anything else would print as junk.
_WIN_ANSI_EXTRA = "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ"
_FALLBACK = {"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "≈": "~"}


def pdf_text(s: str) -> str:
    """Text the built-in fonts can print: other characters lose their accents or become ASCII."""
    out = []
    for ch in s:
        code = ord(ch)
        if 0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF or ch in _WIN_ANSI_EXTRA:
            out.append(ch)
        else:
            plain = re.sub(r"[^\x20-\x7e]", "", unicodedata.normalize("NFKD", ch))
            out.append(_FALLBACK.get(ch) or plain or "?")
    return "".join(out)


def text_width(s: str, size: float, bold: bool = False) -> float:
    """Width in millimetres of `s`, already through `pdf_text`, at `size` points."""
    return sum(_glyph_width(ch, bold) for ch in s) * size * PT / 1000


def _glyph_width(ch: str, bold: bool) -> int:
    widths = _ASCII_WIDTHS[bold]
    if 32 <= ord(ch) <= 126:
        return widths[ord(ch) - 32]
    if ch in _EXTRA_WIDTHS:
        return _EXTRA_WIDTHS[ch][bold]
    base = unicodedata.normalize("NFKD", ch)[:1]
    return widths[ord(base) - 32] if base and 32 <= ord(base) <= 126 else 556


class Canvas:
    """Pages of drawing operations, written out as one PDF by `save`."""

    def __init__(self, title: str = "", subject: str = "") -> None:
        self.title = title
        self.subject = subject
        self._pages: list[list[str]] = [[]]
        self._page = 0

    @property
    def page_count(self) -> int:
        return len(self._pages)

    def add_page(self) -> None:
        self._pages.append([])
        self._page = len(self._pages) - 1

    def set_page(self, index: int) -> None:
        """Draw on page `index` (0-based) from now on, e.g. to add footers once all exist."""
        self._page = index

    def text(
        self,
        s: str,
        x: float,
        y: float,
        *,
        size: float,
        bold: bool = False,
        color: Rgb = (0, 0, 0),
        align: Literal["left", "right"] = "left",
        baseline: Literal["top", "alphabetic"] = "top",
    ) -> None:
        s = pdf_text(s)
        if align == "right":
            x -= text_width(s, size, bold)
        base = y + size * PT * _ASCENT if baseline == "top" else y
        font = "F2" if bold else "F1"
        self._pages[self._page].append(
            f"BT /{font} {_n(size)} Tf {_rgb(color)} rg {_n(x * _K)} {_n((PAGE_H - base) * _K)} Td "
            f"({_escape(s)}) Tj ET"
        )

    def rect(self, x: float, y: float, w: float, h: float, color: Rgb) -> None:
        self._pages[self._page].append(
            f"{_rgb(color)} rg {_n(x * _K)} {_n((PAGE_H - y - h) * _K)} {_n(w * _K)} {_n(h * _K)} "
            "re f"
        )

    def line(self, x1: float, y1: float, x2: float, y2: float, color: Rgb, width: float) -> None:
        self._pages[self._page].append(
            f"{_rgb(color)} RG {_n(width * _K)} w {_n(x1 * _K)} {_n((PAGE_H - y1) * _K)} m "
            f"{_n(x2 * _K)} {_n((PAGE_H - y2) * _K)} l S"
        )

    def save(self) -> bytes:
        first_page = 6  # after the catalogue, page tree, two fonts and the info dictionary
        page_ids = [first_page + 2 * i for i in range(len(self._pages))]
        kids = " ".join(f"{p} 0 R" for p in page_ids)
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode(),
            _font("Helvetica"),
            _font("Helvetica-Bold"),
            b"<< /Title ("
            + _string(self.title)
            + b") /Subject ("
            + _string(self.subject)
            + b") /Creator (QuantumTrace) /Producer (QuantumTrace) >>",
        ]
        media = f"[0 0 {_n(PAGE_W * _K)} {_n(PAGE_H * _K)}]"
        for page_id, ops in zip(page_ids, self._pages, strict=True):
            stream = "\n".join(ops).encode("cp1252")
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox {media} /Resources << /Font << "
                f"/F1 3 0 R /F2 4 0 R >> >> /Contents {page_id + 1} 0 R >>".encode()
            )
            objects.append(
                f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
            )

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
        out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 5 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode()
        return bytes(out)


def _font(name: str) -> bytes:
    return (
        f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>".encode()
    )


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _string(s: str) -> bytes:
    return _escape(pdf_text(s)).encode("cp1252")


def _rgb(color: Rgb) -> str:
    return " ".join(_n(c / 255, 3) for c in color)


def _n(value: float, places: int = 2) -> str:
    text = f"{value:.{places}f}".rstrip("0").rstrip(".")
    return "0" if text in ("", "-0") else text
