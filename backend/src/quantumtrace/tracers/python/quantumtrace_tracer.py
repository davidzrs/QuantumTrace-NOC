"""QuantumTrace runtime tracer for Python: which cryptography a program really runs.

Put this folder on PYTHONPATH and set QT_TRACE_FILE: `sitecustomize.py` starts the tracer in
every Python process of the run (tests, a debug session). It writes what it sees as JSON lines:
which lines of the project ran, and each call into hashlib, hmac or the `cryptography` package
with the parameters that call really used (hash name, key size, curve, mode).

It reports what the libraries say and nothing else: no keys, no messages, no IVs, and no
verdict. Whether RSA-1024 is a problem is decided later by the QuantumTrace engine, which reads
the file with the same rules as every other scan.

Stdlib only, and it must never break the program it watches: every hook swallows its own
errors. It needs `sys.monitoring` (Python 3.12+); on older versions it writes one line saying
so and stays out of the way.

Environment:
  QT_TRACE_FILE  where to append the trace (the tracer is off without it)
  QT_TRACE_ROOT  the project folder: only code under it counts as "yours" (default: cwd)
  QT_TRACE_RUN   id shared by every process of one run (default: a new one)
"""

import atexit
import hashlib
import itertools
import json
import os
import sys
import threading
import time
import types
import uuid

VERSION = 1
FLUSH_SECONDS = 2.0
# An uninteresting call site is switched off after this many calls. Sites in project code get
# more chances, because one line can call different functions over time (a dispatch table).
MISSES_IN_PROJECT = 32
MISSES_IN_LIBRARY = 3

IGNORE, PROJECT, LIBRARY = 0, 1, 2

# Folders under the project root that are not the project's own code.
NOT_PROJECT = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".tox",
        ".nox",
        ".idea",
        ".vscode",
        ".quantumtrace",
        "site-packages",
        "dist-packages",
    }
)
# Libraries whose calls are hooked directly: what they do inside is not reported twice.
HOOKED = frozenset({"cryptography", "Crypto", "Cryptodome", "nacl", "OpenSSL"})
# Test runners and debuggers: their own hashing is not the project's cryptography.
TOOLING = frozenset(
    {
        "pytest",
        "_pytest",
        "pluggy",
        "py",
        "iniconfig",
        "coverage",
        "debugpy",
        "pydevd",
        "_pydevd_bundle",
        "_pydev_bundle",
        "pydevd_plugins",
        "setuptools",
        "pkg_resources",
        "pip",
        "_distutils_hack",
        "xdist",
        "execnet",
        "hypothesis",
        "unittest",
        "nose",
        "tox",
        "nox",
    }
)
KEY_FAMILIES = frozenset({"rsa", "ec", "ed25519", "ed448", "x25519", "x448", "dsa", "dh"})
KEY_OPERATIONS = frozenset({"sign", "verify", "encrypt", "decrypt", "exchange"})


class Tracer(object):
    def __init__(self, out, root, run):
        self.out = out
        self.root = os.path.normcase(os.path.realpath(root))
        self.run = run
        self.own = os.path.normcase(os.path.dirname(os.path.realpath(__file__)))
        self.lock = threading.Lock()
        self.kinds = {}  # code object -> IGNORE / PROJECT / LIBRARY
        self.places = {}  # file name -> (kind, path relative to the root, library name)
        self.spans = {}  # (code object, instruction offset) -> (first line, last line)
        self.resolved = {}  # long-lived callable -> (api, how to read its argument) or None
        self.misses = {}  # (code object, instruction offset) -> uninteresting calls so far
        self.contexts = []  # (runner function, test name) of the tests running now, outermost first
        self.context_codes = set()
        self.calls = {}  # (file, line, end line, api, arguments, via, test) -> calls since flush
        self.lines = {}  # file -> {line: test that ran it first}
        self.files = {}  # file -> sha256 of its content, for files seen since the last flush
        self.header = False
        self.flushed = time.monotonic()
        self.tool = None
        self.by_object = hashlib_callables()

    # --- starting and stopping -------------------------------------------------------------

    def start(self):
        mon = sys.monitoring
        for tool in (3, 4):  # the ids CPython leaves to tools other than debuggers and coverage
            if mon.get_tool(tool) is None:
                mon.use_tool_id(tool, "quantumtrace")
                self.tool = tool
                break
        if self.tool is None:
            return False
        events = mon.events
        mon.register_callback(self.tool, events.PY_START, self.on_start)
        mon.register_callback(self.tool, events.PY_RETURN, self.on_leave)
        mon.register_callback(self.tool, events.CALL, self.on_call)
        mon.register_callback(self.tool, events.LINE, self.on_line)
        mon.set_events(self.tool, events.PY_START | events.CALL)
        atexit.register(self.flush)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self.forget)
        return True

    def stop(self):
        if self.tool is not None:
            sys.monitoring.set_events(self.tool, 0)
            sys.monitoring.free_tool_id(self.tool)
            self.tool = None
        self.flush()

    def forget(self):
        """A forked child starts counting from zero: the parent writes what it had."""
        self.calls, self.lines, self.files = {}, {}, {}

    # --- where code lives -------------------------------------------------------------------

    def place(self, filename):
        """(kind, path relative to the root with forward slashes, library name)."""
        known = self.places.get(filename)
        if known is not None:
            return known
        place = (IGNORE, None, None)
        if filename and not filename.startswith("<"):
            real = os.path.realpath(filename)
            path = os.path.normcase(real)
            parts = path.replace("\\", "/").split("/")
            library = None
            for marker in ("site-packages", "dist-packages"):
                if marker in parts:
                    library = parts[parts.index(marker) + 1]
                    library = library[:-3] if library.endswith(".py") else library
            if library is not None:
                if library not in HOOKED and library not in TOOLING:
                    place = (LIBRARY, None, library)
            elif path.startswith(self.root + os.sep) and not path.startswith(self.own):
                relative = path[len(self.root) + 1 :].replace("\\", "/")
                if not NOT_PROJECT.intersection(relative.split("/")[:-1]):
                    # as the file is spelled on disk, not lower-cased as normcase leaves it
                    real = real[len(self.root) + 1 :].replace("\\", "/")
                    place = (PROJECT, real, None)
                    self.files[real] = file_digest(filename)
        self.places[filename] = place
        return place

    def kind(self, code):
        kind = self.kinds.get(code)
        if kind is None:
            kind = self.kinds[code] = self.place(code.co_filename)[0]
        return kind

    def span(self, code, offset):
        """First and last line of the expression at an instruction: a call can span lines."""
        key = (code, offset)
        span = self.spans.get(key)
        if span is None:
            first = last = None
            try:
                position = next(itertools.islice(code.co_positions(), offset // 2, None))
                first, last = position[0], position[1]
            except Exception:
                pass
            first = first or code.co_firstlineno
            span = self.spans[key] = (first, last or first)
        return span

    def project_site(self, frame):
        """The nearest frame of project code at or above `frame`: (file, first line, last line)."""
        while frame is not None:
            code = frame.f_code
            if self.kind(code) == PROJECT:
                first, last = self.span(code, max(frame.f_lasti, 0))
                return self.place(code.co_filename)[1], first, last
            frame = frame.f_back
        return None

    # --- events -----------------------------------------------------------------------------

    def on_start(self, code, offset):
        try:
            hook = PYTHON_HOOKS.get(code.co_qualname)
            if hook is not None:
                filename = code.co_filename.replace("\\", "/")
                for suffix, handler in hook:
                    if filename.endswith(suffix) and self.kind(code) != PROJECT:
                        try:
                            handler(self, code, sys._getframe(1))
                        except Exception:
                            pass
                        return None  # stays on: every call of this function matters
            if self.kind(code) == PROJECT:
                sys.monitoring.set_local_events(self.tool, code, sys.monitoring.events.LINE)
        except Exception:
            pass
        return sys.monitoring.DISABLE

    def on_leave(self, code, offset, value):
        if self.contexts and self.contexts[-1][0] is code:
            self.contexts.pop()

    def on_line(self, code, line):
        try:
            file = self.place(code.co_filename)[1]
            if file is not None:
                with self.lock:
                    self.lines.setdefault(file, {}).setdefault(line, self.test())
                self.flush_if_due()
        except Exception:
            pass
        return sys.monitoring.DISABLE

    def on_call(self, code, offset, function, arg0):
        try:
            kind = self.kind(code)
            if kind == IGNORE:
                return sys.monitoring.DISABLE
            seen = self.identify(function, arg0)
            if seen is None:
                key = (code, offset)
                count = self.misses[key] = self.misses.get(key, 0) + 1
                limit = MISSES_IN_PROJECT if kind == PROJECT else MISSES_IN_LIBRARY
                return sys.monitoring.DISABLE if count >= limit else None
            api, arguments = seen
            if kind == PROJECT:
                first, last = self.span(code, offset)
                self.record(self.place(code.co_filename)[1], first, last, api, arguments, None)
            else:  # a library called it: report the project line that got there
                site = self.project_site(sys._getframe(1))
                if site is not None:
                    via = self.place(code.co_filename)[2]
                    self.record(site[0], site[1], site[2], api, arguments, via)
        except Exception:
            pass
        return None

    def called_from(self, callee, api, arguments):
        """Record a hooked Python function, if project code or a library other than the
        hooked one called it (its own internal calls are not news)."""
        caller = callee.f_back
        if caller is None:
            return
        kind = self.kind(caller.f_code)
        if kind == PROJECT:
            site = self.project_site(caller)
            via = None
        elif kind == LIBRARY:
            site = self.project_site(caller)
            via = self.place(caller.f_code.co_filename)[2]
        else:
            return
        if site is not None:
            self.record(site[0], site[1], site[2], api, arguments, via)

    def enter_test(self, code, name):
        if not name:
            return
        if code not in self.context_codes:
            self.context_codes.add(code)
            # a runner returns from this function when the test is over, pass or fail
            sys.monitoring.set_local_events(self.tool, code, sys.monitoring.events.PY_RETURN)
        # one left behind by a runner that was interrupted is over too
        self.contexts = [entry for entry in self.contexts if entry[0] is not code]
        self.contexts.append((code, str(name)))

    def test(self):
        return self.contexts[0][1] if self.contexts else None

    # --- what a callable is -----------------------------------------------------------------

    def identify(self, function, arg0):
        """(api, arguments) for a callable this tracer knows, else None. `arguments` holds
        only what the library itself states: a name, a size in bits, a curve, a mode."""
        kind = type(function)
        if kind is types.FunctionType:
            module = getattr(function, "__module__", None) or ""
            if function is not hashlib.new and not module.startswith("cryptography."):
                return None  # the project's own functions: by far the most calls
        elif kind is types.BuiltinFunctionType:
            if not isinstance(function.__self__, types.ModuleType):
                return None  # bound to some object, so not a library's entry point
        elif kind is not types.MethodDescriptorType and not isinstance(function, type):
            return None
        try:
            spec = self.by_object.get(function)
            if spec is None and function not in self.resolved:
                self.resolved[function] = resolve(function)
            spec = spec or self.resolved.get(function)
        except TypeError:  # unhashable callable
            return None
        if spec is None:
            return None
        api, how = spec
        arguments = {}
        missing = sys.monitoring.MISSING
        if how == "hash":
            arguments["name"] = api.rsplit(".", 1)[1]
        elif how == "arg0-name":
            name = arg0 if isinstance(arg0, str) else getattr(arg0, "name", None)
            if not isinstance(name, str):
                return None
            arguments["name"] = name.lower()
        elif how == "class-name":
            arguments["name"] = function.name
        elif how == "arg0-length":
            if isinstance(arg0, (bytes, bytearray, memoryview)):
                arguments["bits"] = len(arg0) * 8  # the key's length, never the key
        elif how == "arg0-curve":
            read_key(arg0, arguments, curve=arg0)
        elif how == "self-key":
            if arg0 is missing:
                return None
            read_key(arg0, arguments, curve=getattr(arg0, "curve", None))
        elif how == "arg0-hash":
            name = getattr(arg0, "name", None)
            if isinstance(name, str) and type(arg0).__module__.endswith(".hashes"):
                arguments["hash"] = name
        return api, arguments

    # --- recording --------------------------------------------------------------------------

    def record(self, file, first, last, api, arguments, via):
        key = (file, first, last, api, tuple(sorted(arguments.items())), via, self.test())
        with self.lock:
            self.calls[key] = self.calls.get(key, 0) + 1
        self.flush_if_due()

    def flush_if_due(self):
        # a debug session is often killed, not ended: don't hold more than a moment of trace
        if time.monotonic() - self.flushed >= FLUSH_SECONDS:
            self.flush()

    def flush(self):
        with self.lock:
            calls, self.calls = self.calls, {}
            lines, self.lines = self.lines, {}
            files, self.files = self.files, {}
            self.flushed = time.monotonic()
        records = []
        if not self.header:
            self.header = True
            records.append(run_record(self.run))
        for file, digest in sorted(files.items()):
            records.append({"kind": "file", "run": self.run, "file": file, "sha256": digest})
        for file, seen in sorted(lines.items()):
            by_test = {}
            for line, test in seen.items():
                by_test.setdefault(test, []).append(line)
            for test, numbers in by_test.items():
                records.append(
                    {
                        "kind": "lines",
                        "run": self.run,
                        "file": file,
                        "test": test,
                        "lines": sorted(numbers),
                    }
                )
        for (file, first, last, api, arguments, via, test), count in calls.items():
            records.append(
                {
                    "kind": "call",
                    "run": self.run,
                    "file": file,
                    "line": first,
                    "end_line": last,
                    "api": api,
                    "args": dict(arguments),
                    "via": via,
                    "test": test,
                    "count": count,
                }
            )
        if records:
            write(self.out, records)


def hashlib_callables():
    """hashlib's constructors by identity: `hashlib.md5`, `hashlib.sha256`, ..."""
    table = {}
    for name in sorted(hashlib.algorithms_available):
        function = getattr(hashlib, name, None)
        if callable(function):
            table[function] = ("hashlib." + name, "hash")
    table[hashlib.new] = ("hashlib.new", "arg0-name")
    table[hashlib.pbkdf2_hmac] = ("hashlib.pbkdf2_hmac", "arg0-name")
    if hasattr(hashlib, "scrypt"):
        table[hashlib.scrypt] = ("hashlib.scrypt", None)
    return table


def resolve(function):
    """What a callable of the `cryptography` package is, from its own name and module."""
    module = getattr(function, "__module__", None) or ""
    name = getattr(function, "__name__", "")
    if isinstance(function, type):
        if not module.startswith("cryptography."):
            return None
        if module == "cryptography.hazmat.primitives.hashes":
            if isinstance(getattr(function, "name", None), str):
                return ("cryptography.hashes." + name, "class-name")
            return None
        if module.endswith("_rust.openssl.hashes") and name == "Hash":
            return ("cryptography.hashes.Hash", "arg0-name")
        if module.endswith(".asymmetric.padding") and name in ("PKCS1v15", "PSS", "OAEP"):
            return ("cryptography.padding." + name, None)
        if module.endswith(".asymmetric.ec") and name == "ECDH":
            return ("cryptography.ec.ECDH", None)
        if module.endswith(".ciphers.algorithms"):
            return ("cryptography.algorithms." + name, "arg0-length")
        if module.endswith(".ciphers.aead") or module.endswith("_rust.openssl.aead"):
            return ("cryptography.aead." + name, "arg0-length")
        if module == "cryptography.fernet" and name == "Fernet":
            return ("cryptography.fernet.Fernet", None)
        if ".primitives.kdf." in module or module.endswith("_rust.openssl.kdf"):
            return ("cryptography.kdf." + name, "arg0-hash")
        return None
    kind = type(function)
    if kind is types.MethodDescriptorType:
        owner = getattr(function, "__objclass__", None)
        family = (getattr(owner, "__module__", None) or "").rpartition("_rust.openssl.")[2]
        if family in KEY_FAMILIES and name in KEY_OPERATIONS:
            return ("cryptography.%s.%s" % (family, name), "self-key")
        return None
    if kind is types.BuiltinFunctionType:
        if module == "ec" and name == "generate_private_key":
            return ("cryptography.ec.generate", "arg0-curve")
        if module == "dh" and name == "generate_parameters":
            return ("cryptography.dh.generate", None)
        return None
    if kind is types.FunctionType and module.startswith("cryptography.hazmat.primitives."):
        family = module.rsplit(".", 1)[1]
        qualified = getattr(function, "__qualname__", "")
        if family in ("ed25519", "ed448", "x25519", "x448") and qualified.endswith(
            "PrivateKey.generate"
        ):
            return ("cryptography.%s.generate" % family, None)
    return None


def read_key(key, arguments, curve):
    bits = getattr(key, "key_size", None)
    if isinstance(bits, int):
        arguments["bits"] = bits
    name = getattr(curve, "name", None)
    if isinstance(name, str):
        arguments["curve"] = name


def digest_name(tracer, digest):
    """The hash an hmac call was given: a name, a hashlib constructor, or a module."""
    if isinstance(digest, str):
        return digest.lower()
    try:
        spec = tracer.by_object.get(digest)
    except TypeError:
        spec = None
    if spec is not None and spec[1] == "hash":
        return spec[0].rsplit(".", 1)[1]
    name = getattr(digest, "__name__", None)
    if isinstance(name, str):
        return name.rsplit(".", 1)[-1].replace("openssl_", "").lower()
    return None


# --- hooks on Python functions: their arguments are read from the starting frame -------------


def hook_rsa_generate(tracer, code, frame):
    bits = frame.f_locals.get("key_size")
    arguments = {"bits": bits} if isinstance(bits, int) else {}
    tracer.called_from(frame, "cryptography.rsa.generate", arguments)


def hook_dsa_generate(tracer, code, frame):
    bits = frame.f_locals.get("key_size")
    arguments = {"bits": bits} if isinstance(bits, int) else {}
    tracer.called_from(frame, "cryptography.dsa.generate", arguments)


def hook_cipher(tracer, code, frame):
    algorithm = frame.f_locals.get("algorithm")
    mode = frame.f_locals.get("mode")
    arguments = {"name": type(algorithm).__name__}
    bits = getattr(algorithm, "key_size", None)
    if isinstance(bits, int):
        arguments["bits"] = bits
    mode_name = getattr(mode, "name", None)
    if isinstance(mode_name, str):
        arguments["mode"] = mode_name
    tracer.called_from(frame, "cryptography.cipher", arguments)


def hook_hmac(tracer, code, frame):
    values = frame.f_locals
    name = digest_name(tracer, values.get("digestmod", values.get("digest")))
    if name:
        tracer.called_from(frame, "hmac", {"name": name})


def hook_file_digest(tracer, code, frame):
    name = digest_name(tracer, frame.f_locals.get("digest"))
    if name:
        tracer.called_from(frame, "hashlib.file_digest", {"name": name})


def hook_pytest(tracer, code, frame):
    tracer.enter_test(code, getattr(frame.f_locals.get("item"), "nodeid", None))


def hook_unittest(tracer, code, frame):
    case = frame.f_locals.get("self")
    tracer.enter_test(code, case.id() if hasattr(case, "id") else None)


# function name -> ((end of the file's path, handler), ...)
PYTHON_HOOKS = {
    "generate_private_key": (
        ("/cryptography/hazmat/primitives/asymmetric/rsa.py", hook_rsa_generate),
        ("/cryptography/hazmat/primitives/asymmetric/dsa.py", hook_dsa_generate),
    ),
    "Cipher.__init__": (("/cryptography/hazmat/primitives/ciphers/base.py", hook_cipher),),
    "new": (("/hmac.py", hook_hmac),),
    "digest": (("/hmac.py", hook_hmac),),
    "HMAC.__init__": (("/hmac.py", hook_hmac),),
    "file_digest": (("/hashlib.py", hook_file_digest),),
    "runtestprotocol": (("/_pytest/runner.py", hook_pytest),),
    "TestCase.run": (("/unittest/case.py", hook_unittest),),
}


def file_digest(filename):
    try:
        with open(filename, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return None


def command():
    """How the run was started, without its arguments' values: `python -m pytest`."""
    argv = list(getattr(sys, "orig_argv", None) or sys.argv)
    words = ["python"]
    for word in argv[1:4]:
        if word.startswith("-") and "=" in word:
            word = word.split("=", 1)[0]
        words.append(os.path.basename(word) if os.sep in word or "/" in word else word)
    return " ".join(words)[:120]


def run_record(run):
    return {
        "kind": "run",
        "version": VERSION,
        "run": run,
        "language": "python",
        "runtime": "%s %s" % (sys.implementation.name, ".".join(map(str, sys.version_info[:3]))),
        "command": command(),
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": os.getpid(),
    }


def write(out, records):
    folder = os.path.dirname(out)
    if folder:
        os.makedirs(folder, exist_ok=True)
    text = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    with open(out, "a", encoding="utf-8") as handle:
        handle.write(text)


ACTIVE = None


def start():
    """Start tracing if QT_TRACE_FILE is set. Safe to call in every process of a run."""
    global ACTIVE
    out = os.environ.get("QT_TRACE_FILE")
    if not out or ACTIVE is not None:
        return ACTIVE
    run = os.environ.get("QT_TRACE_RUN") or uuid.uuid4().hex[:12]
    if getattr(sys, "monitoring", None) is None:
        record = run_record(run)
        record["unsupported"] = "the tracer needs Python 3.12 or newer"
        write(out, [record])
        return None
    tracer = Tracer(out, os.environ.get("QT_TRACE_ROOT") or os.getcwd(), run)
    if tracer.start():
        ACTIVE = tracer
    return ACTIVE
