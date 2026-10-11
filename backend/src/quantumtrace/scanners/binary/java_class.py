"""Java bytecode: the JCA calls a compiled class makes, without its source.

`Cipher.getInstance("AES/ECB/PKCS5Padding")` compiles to `ldc "AES/ECB/PKCS5Padding"` followed by
`invokestatic javax/crypto/Cipher.getInstance`. This module walks each method's code for those
pairs (and `KeyPairGenerator.initialize(1024)`, `KeyGenerator.init(256)`, `new java.util.Random`)
and keeps the source line from the class's LineNumberTable, so findings point at `Foo.java:42`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

JCA_ENGINES = {
    "javax/crypto/Cipher": "Cipher",
    "javax/crypto/Mac": "Mac",
    "javax/crypto/KeyGenerator": "KeyGenerator",
    "javax/crypto/KeyAgreement": "KeyAgreement",
    "javax/crypto/SecretKeyFactory": "SecretKeyFactory",
    "javax/crypto/KEM": "KEM",
    "java/security/MessageDigest": "MessageDigest",
    "java/security/Signature": "Signature",
    "java/security/KeyPairGenerator": "KeyPairGenerator",
    "java/security/KeyFactory": "KeyFactory",
}
INVOKEVIRTUAL, INVOKESTATIC, NEW = 0xB6, 0xB8, 0xBB
LDC, LDC_W, BIPUSH, SIPUSH = 0x12, 0x13, 0x10, 0x11


@dataclass
class Call:
    """One JCA call in bytecode order: what source would have said, and where."""

    text: str  # as source would read: Cipher.getInstance("AES/ECB/PKCS5Padding")
    line: int | None  # source line from the LineNumberTable
    method: str


@dataclass
class ClassFile:
    name: str  # com.acme.Vault
    source_file: str | None
    calls: list[Call] = field(default_factory=list)
    uses_random: bool = False


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.i = data, 0

    def u1(self) -> int:
        self.i += 1
        return self.data[self.i - 1]

    def u2(self) -> int:
        self.i += 2
        return int(struct.unpack_from(">H", self.data, self.i - 2)[0])

    def u4(self) -> int:
        self.i += 4
        return int(struct.unpack_from(">I", self.data, self.i - 4)[0])

    def take(self, n: int) -> bytes:
        self.i += n
        return self.data[self.i - n : self.i]


def parse(data: bytes) -> ClassFile:
    """Parse a .class file. Raises ValueError when it isn't one."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a Java class file")
    try:
        return _parse(_Reader(data))
    except (IndexError, struct.error, UnicodeDecodeError) as exc:
        raise ValueError(f"malformed class file: {exc}") from exc


class _Pool:
    """The constant pool, and the lookups bytecode operands need."""

    def __init__(self, r: _Reader) -> None:
        self.count = r.u2()
        self.entries: list[tuple[int, object]] = [(0, None)] * self.count
        k = 1
        while k < self.count:
            tag = r.u1()
            if tag == 1:
                self.entries[k] = (1, r.take(r.u2()).decode("utf-8", errors="replace"))
            elif tag in (3, 4):
                self.entries[k] = (tag, struct.unpack(">i", r.take(4))[0])
            elif tag in (5, 6):
                r.take(8)
                k += 1  # longs and doubles take two slots
            elif tag in (7, 8, 16, 19, 20):
                self.entries[k] = (tag, r.u2())
            elif tag in (9, 10, 11, 12, 17, 18):
                self.entries[k] = (tag, (r.u2(), r.u2()))
            elif tag == 15:
                self.entries[k] = (tag, (r.u1(), r.u2()))
            else:
                raise ValueError(f"unknown constant pool tag {tag}")
            k += 1

    def _get(self, i: int) -> tuple[int, object]:
        return self.entries[i] if 0 < i < self.count else (0, None)

    def utf8(self, i: int) -> str:
        tag, value = self._get(i)
        return value if tag == 1 and isinstance(value, str) else ""

    def class_name(self, i: int) -> str:
        tag, value = self._get(i)
        return self.utf8(value) if tag == 7 and isinstance(value, int) else ""

    def method_ref(self, i: int) -> tuple[str, str, str] | None:
        """(owner, name, descriptor) of a Methodref or InterfaceMethodref."""
        tag, value = self._get(i)
        if tag not in (10, 11) or not isinstance(value, tuple):
            return None
        _, nat = self._get(value[1])
        if not isinstance(nat, tuple):
            return None
        return self.class_name(value[0]), self.utf8(nat[0]), self.utf8(nat[1])

    def constant(self, i: int) -> str | int | None:
        """What `ldc` pushes: a String's text or an Integer."""
        tag, value = self._get(i)
        if tag == 8 and isinstance(value, int):
            return self.utf8(value)
        if tag == 3 and isinstance(value, int):
            return value
        return None


def _parse(r: _Reader) -> ClassFile:
    r.i = 8
    pool = _Pool(r)
    r.u2()  # access flags
    out = ClassFile(name=pool.class_name(r.u2()).replace("/", "."), source_file=None)
    r.u2()  # super
    r.take(2 * r.u2())  # interfaces
    for _ in range(r.u2()):  # fields
        r.take(6)
        for _ in range(r.u2()):
            r.u2()
            r.take(r.u4())
    for _ in range(r.u2()):  # methods
        r.u2()
        name = pool.utf8(r.u2())
        r.u2()
        for _ in range(r.u2()):
            attr = pool.utf8(r.u2())
            body = r.take(r.u4())
            if attr == "Code":
                _code(body, name, pool, out)
    for _ in range(r.u2()):  # class attributes
        attr = pool.utf8(r.u2())
        body = r.take(r.u4())
        if attr == "SourceFile":
            out.source_file = pool.utf8(struct.unpack(">H", body[:2])[0])
    return out


def _code(body: bytes, method: str, pool: _Pool, out: ClassFile) -> None:
    code_len = struct.unpack_from(">I", body, 4)[0]
    code = body[8 : 8 + code_len]
    rest = _Reader(body)
    rest.i = 8 + code_len
    rest.take(8 * rest.u2())  # exception table
    lines: list[tuple[int, int]] = []
    for _ in range(rest.u2()):
        attr = pool.utf8(rest.u2())
        data = rest.take(rest.u4())
        if attr == "LineNumberTable":
            n = struct.unpack_from(">H", data, 0)[0]
            lines += [struct.unpack_from(">HH", data, 2 + 4 * j) for j in range(n)]
    lines.sort()

    def line_at(pc: int) -> int | None:
        found = None
        for start, line in lines:
            if start > pc:
                break
            found = line
        return found

    def u2_at(at: int) -> int:
        return int.from_bytes(code[at : at + 2], "big")

    def operand_before(end: int) -> tuple[int, str | int] | None:
        """The ldc/push instruction that ends exactly at `end`, and the value it pushes."""
        if end >= 2 and code[end - 2] == LDC and (v := pool.constant(code[end - 1])) is not None:
            return end - 2, v
        if end >= 3 and code[end - 3] == LDC_W and (v := pool.constant(u2_at(end - 2))) is not None:
            return end - 3, v
        if end >= 3 and code[end - 3] == SIPUSH:
            return end - 3, int.from_bytes(code[end - 2 : end], "big", signed=True)
        if end >= 2 and code[end - 2] == BIPUSH:
            return end - 2, int.from_bytes(code[end - 1 : end], "big", signed=True)
        return None

    for pc in range(len(code) - 2):
        op = code[pc]
        if op == NEW and pool.class_name(u2_at(pc + 1)) == "java/util/Random":
            out.uses_random = True
            out.calls.append(Call("new Random()", line_at(pc), method))
            continue
        if op not in (INVOKESTATIC, INVOKEVIRTUAL):
            continue
        ref = pool.method_ref(u2_at(pc + 1))
        if ref is None:
            continue
        owner, name, desc = ref
        engine = JCA_ENGINES.get(owner)
        if engine is None:
            continue
        if op == INVOKESTATIC and name == "getInstance":
            last = operand_before(pc)
            if last is None or not isinstance(last[1], str):
                continue  # algorithm from a variable: not knowable from bytecode alone
            first = operand_before(last[0])
            if first is not None and isinstance(first[1], str):  # getInstance(alg, "BC")
                text = f'{engine}.getInstance("{first[1]}", "{last[1]}")'
            else:
                text = f'{engine}.getInstance("{last[1]}")'
            out.calls.append(Call(text, line_at(pc), method))
        elif (
            op == INVOKEVIRTUAL
            and desc.startswith("(I")
            and (
                (engine == "KeyPairGenerator" and name == "initialize")
                or (engine == "KeyGenerator" and name == "init")
            )
        ):
            arg = operand_before(pc)
            if arg is not None and isinstance(arg[1], int):
                out.calls.append(Call(f"generator.{name}({arg[1]})", line_at(pc), method))
