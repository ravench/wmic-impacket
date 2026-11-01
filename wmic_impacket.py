#!/usr/bin/env python3
"""wmic-impacket: a drop-in replacement for the Samba-based Linux ``wmic`` binary.

The original ``wmic`` (wmi-1.3.x, "Version 4.0.0tp4-SVN-build-UNKNOWN") can only
talk DCOM at RPC_C_AUTHN_LEVEL_CONNECT.  Since Microsoft's DCOM hardening
(KB5004442 / CVE-2021-26414, enforced since March 2023) Windows rejects such
activation requests with System event 10036.  This tool reproduces wmic's command
line and output format on top of Impacket, which can run the whole DCOM/WMI
conversation at RPC_C_AUTHN_LEVEL_PKT_INTEGRITY or PKT_PRIVACY.

The output format is what Observium's ``wmi_parse()`` expects:

    CLASS: <class name>
    <prop>|<prop>|...
    <value>|<value>|...

Everything meant for the parser goes to stdout, everything meant for humans
(NTSTATUS lines, Impacket diagnostics, debug output) goes to stderr.

Only the standard library plus a handful of Impacket submodules are imported, and
Impacket is imported lazily so that ``--help`` / ``--version`` and the unit tests
stay fast.  The code is kept Python 3.8 compatible on purpose.
"""

import argparse
import errno
import logging
import os
import re
import signal
import socket
import sys
import traceback
import types
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

# The version string the original binary reports; some tooling greps for it.
SAMBA_WMIC_VERSION = "4.0.0tp4-SVN-build-UNKNOWN"

TAG = "[wmic-impacket]"

# The two WERR_CHECK messages from Samba's wmi/wmic.c that Observium knows about.
MSG_LOGIN = "Login to remote object."
MSG_RESULT = "Retrieve result data."

DEFAULT_NAMESPACE = "root\\cimv2"
DEFAULT_DELIMITER = "|"
DEFAULT_TIMEOUT = 30
DEFAULT_AUTH_LEVEL = "privacy"
AUTH_LEVELS = ("integrity", "privacy")

ENV_AUTH_LEVEL = "WMIC_IMPACKET_AUTH_LEVEL"
ENV_TIMEOUT = "WMIC_IMPACKET_TIMEOUT"

# ---------------------------------------------------------------------------
# CIM types ([MS-WMIO] 2.2.78 CimType).  Impacket reports a property's type as the
# raw CimType value with two flag bits that we strip before formatting.
# ---------------------------------------------------------------------------
CIM_ARRAY_FLAG = 0x2000
CIM_INHERITED_FLAG = 0x4000  # Impacket's "Inherited" bit, see wmi.py
CIM_TYPE_MASK = 0x1FFF

CIM_SINT16 = 2
CIM_SINT32 = 3
CIM_REAL32 = 4
CIM_REAL64 = 5
CIM_STRING = 8
CIM_BOOLEAN = 11
CIM_OBJECT = 13
CIM_SINT8 = 16
CIM_UINT8 = 17
CIM_UINT16 = 18
CIM_UINT32 = 19
CIM_SINT64 = 20
CIM_UINT64 = 21
CIM_DATETIME = 101
CIM_REFERENCE = 102
CIM_CHAR16 = 103

CIM_INTEGER_TYPES = frozenset(
    (CIM_SINT8, CIM_UINT8, CIM_SINT16, CIM_UINT16, CIM_SINT32, CIM_UINT32, CIM_SINT64, CIM_UINT64)
)
CIM_REAL_TYPES = frozenset((CIM_REAL32, CIM_REAL64))
CIM_STRINGISH_TYPES = frozenset((CIM_STRING, CIM_DATETIME, CIM_REFERENCE))

NULL_SCALAR = "(null)"  # what glibc printf("%s", NULL) produced in the original
NULL_ARRAY = "NULL"  # RETURN_CVAR_ARRAY_STR() for a NULL array
UNSUPPORTED = "Unsupported"  # string_CIMVAR() for CIM_CHAR16 / CIM_OBJECT

# Best-effort friendly texts for the NTSTATUS line on stderr.
NTSTATUS_TEXT = {
    "NT_STATUS_ACCESS_DENIED": "Access denied",
    "NT_STATUS_LOGON_FAILURE": "Logon failure: unknown user name or bad password",
    "NT_STATUS_IO_TIMEOUT": "Connection timed out",
    "NT_STATUS_CONNECTION_REFUSED": "Connection refused",
    "NT_STATUS_HOST_UNREACHABLE": "Host unreachable",
    "NT_STATUS_BAD_NETWORK_NAME": "Host name could not be resolved",
    "NT_STATUS_CONNECTION_RESET": "Connection reset by peer",
    "NT_STATUS_UNSUCCESSFUL": "Unsuccessful",
}

# Common WMI / DCOM HRESULTs, so the stderr line says something useful.
HRESULT_TEXT = {
    0x80041001: "WBEM_E_FAILED",
    0x80041002: "WBEM_E_NOT_FOUND",
    0x80041003: "WBEM_E_ACCESS_DENIED (user lacks Enable Account / Remote Enable on the namespace)",
    0x80041004: "WBEM_E_PROVIDER_FAILURE",
    0x80041006: "WBEM_E_OUT_OF_MEMORY",
    0x8004100E: "WBEM_E_INVALID_NAMESPACE",
    0x80041010: "WBEM_E_INVALID_CLASS",
    0x80041013: "WBEM_E_PROVIDER_LOAD_FAILURE",
    0x80041014: "WBEM_E_INITIALIZATION_FAILURE",
    0x80041017: "WBEM_E_INVALID_QUERY",
    0x80041032: "WBEM_E_CALL_CANCELLED",
    0x80041033: "WBEM_E_SHUTTING_DOWN",
    0x80070005: "E_ACCESSDENIED (DCOM launch/activation denied; check event 10036 and the Distributed COM Users group)",
    0x800706BA: "RPC_S_SERVER_UNAVAILABLE",
    0x00000005: "rpc_s_access_denied (NTLM authentication rejected)",
}

log = logging.getLogger("wmic_impacket")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class WmicError(Exception):
    """A failure that maps onto one of wmic's WERR_CHECK messages."""

    def __init__(self, message: str, cause: Optional[BaseException] = None, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.cause = cause
        self.detail = detail


class WatchdogTimeout(BaseException):
    """Raised by the SIGALRM watchdog.

    Deliberately *not* an Exception subclass, so that the broad ``except Exception``
    clauses inside Impacket cannot swallow it.
    """


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------
class UsageError(Exception):
    """Bad command line.  run() turns it into an ``ERROR:`` line on stdout, because
    Observium only looks at stdout and only recognises lines containing ``ERROR:``."""


class EmptyHostError(UsageError):
    """``//`` with nothing after it.  Observium sends exactly that when "Override WMI
    config" is ticked on a device but the WMI hostname field is blank.  run() reports
    it as ``Login to remote object.`` (what the original wmic says when it cannot
    reach a host), because Observium shows a misleading "wmic binary not found"
    message for any ERROR text it does not know."""


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that raises instead of printing and exiting on usage errors."""

    def error(self, message):
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="wmic",
        usage="%(prog)s [OPTIONS] //HOST QUERY",
        description="Query a Windows host over WMI (DCOM) and print the results like Samba's wmic.",
        epilog=(
            "Environment: %s (default for --auth-level), %s (default for --timeout). "
            "Many Samba popt options are accepted and ignored for compatibility."
        )
        % (ENV_AUTH_LEVEL, ENV_TIMEOUT),
        allow_abbrev=False,
        add_help=False,
    )
    p.add_argument("-h", "--help", action="help", help="show this help and exit")
    p.add_argument("-V", "--version", action="store_true", help="print version information and exit")

    p.add_argument("host", nargs="?", metavar="//HOST", help="target host, e.g. //192.0.2.10 or //ncacn_ip_tcp:host[sign]")
    p.add_argument("query", nargs="?", metavar="QUERY", help='WQL query, e.g. "SELECT * FROM Win32_OperatingSystem"')

    auth = p.add_argument_group("authentication")
    auth.add_argument("-U", "--user", metavar="[DOMAIN\\]USER[%PASSWORD]", help="user name, Samba style")
    auth.add_argument("--password", metavar="PASSWORD", help="password")
    auth.add_argument("-N", "--no-pass", action="store_true", help="do not use a password")
    auth.add_argument("-W", "--workgroup", metavar="DOMAIN", help="domain / workgroup")
    auth.add_argument("-A", "--authentication-file", metavar="FILE", help="Samba credentials file (username = / password = / domain =)")

    wmi = p.add_argument_group("wmi")
    wmi.add_argument("--namespace", default=DEFAULT_NAMESPACE, metavar="NS", help="WMI namespace (default %(default)s)")
    wmi.add_argument("--delimiter", default=DEFAULT_DELIMITER, metavar="STR", help="output column delimiter (default '%(default)s')")

    ours = p.add_argument_group("wmic-impacket options")
    ours.add_argument(
        "--auth-level",
        choices=AUTH_LEVELS,
        default=None,
        help="DCOM/RPC authentication level (default: $%s or %s)" % (ENV_AUTH_LEVEL, DEFAULT_AUTH_LEVEL),
    )
    ours.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="hard limit for the whole run, 0 disables (default: $%s or %d)" % (ENV_TIMEOUT, DEFAULT_TIMEOUT),
    )
    ours.add_argument(
        "--split-classes",
        action="store_true",
        help="start a new CLASS/header block whenever the class changes, like the original wmic",
    )

    dbg = p.add_argument_group("debugging")
    dbg.add_argument("-d", "--debuglevel", type=int, default=0, metavar="N", help="debug level; >=1 enables Impacket debug output on stderr")

    # Samba popt options that are accepted and ignored.  Arity matters so that their
    # values are not mistaken for positionals.
    compat = p.add_argument_group("ignored Samba options")
    for flags, kwargs in (
        (("--option",), dict(action="append", default=[], metavar="name=value")),
        (("-O", "--socket-options"), dict(metavar="OPTS")),
        (("-s", "--configfile"), dict(metavar="FILE")),
        (("-l", "--log-basename"), dict(metavar="BASE")),
        (("-R", "--name-resolve"), dict(metavar="ORDER")),
        (("-m", "--maxprotocol"), dict(metavar="PROTO")),
        (("-n", "--netbiosname"), dict(metavar="NAME")),
        (("-S", "--signing"), dict(metavar="on|off|required")),
        (("-k", "--kerberos"), dict(metavar="STRING")),
        (("--realm",), dict(metavar="REALM")),
        (("-i", "--scope"), dict(metavar="SCOPE")),
        (("--simple-bind-dn",), dict(metavar="DN")),
        (("--use-security-mechanisms",), dict(metavar="MECHS")),
        (("-P", "--machine-pass"), dict(action="store_true")),
        (("--debug-stderr",), dict(action="store_true")),
        (("--leak-report",), dict(action="store_true")),
        (("--leak-report-full",), dict(action="store_true")),
    ):
        compat.add_argument(*flags, help=argparse.SUPPRESS, **kwargs)
    return p


def parse_user(spec: Optional[str]) -> Tuple[Optional[str], str, Optional[str]]:
    """Split a Samba-style user spec into (domain, user, password).

    Accepts ``user``, ``DOMAIN\\user``, ``DOMAIN/user`` and ``user@domain``, each
    optionally followed by ``%password`` (split at the first ``%``).
    Missing parts are returned as None.
    """
    if spec is None:
        return None, "", None
    password = None
    if "%" in spec:
        spec, password = spec.split("%", 1)
    domain = None
    user = spec
    if "\\" in spec:
        domain, user = spec.split("\\", 1)
    elif "/" in spec:
        domain, user = spec.split("/", 1)
    elif "@" in spec:
        user, domain = spec.split("@", 1)
    return domain, user, password


def parse_host(spec: str) -> str:
    """Reduce the many accepted host spellings to a plain host name or address.

    ``//host``, ``host``, ``//ncacn_ip_tcp:host[sign]``, ``\\\\host``, ``//[fe80::1]``
    and ``//[fe80::1][sign]`` all work.  A trailing ``[...]`` option block is
    dropped.  IPv6 addresses are returned without brackets, which is what Impacket
    expects in a string binding.
    """
    host = spec.strip()
    while host.startswith("//") or host.startswith("\\\\"):
        host = host[2:]
    if host.lower().startswith("ncacn_ip_tcp:"):
        host = host[len("ncacn_ip_tcp:"):]
    if host.startswith("["):
        # Bracketed IPv6 literal, possibly followed by an option block.
        end = host.find("]")
        if end > 0:
            return host[1:end]
        return host[1:]
    if "[" in host:
        host = host[: host.index("[")]
    return host


def normalize_namespace(ns: Optional[str]) -> str:
    """Convert ``root\\cimv2`` (wmic style) into ``//./root/cimv2`` (what Impacket's
    examples/wmiquery.py passes to IWbemLevel1Login::NTLMLogin)."""
    if not ns:
        ns = DEFAULT_NAMESPACE
    s = ns.replace("\\", "/")
    if s.startswith("//"):
        return s
    return "//./" + s.lstrip("/")


def read_auth_file(path: str) -> Dict[str, str]:
    """Parse a Samba credentials file (``-A``): ``username = x``, ``password = y``,
    ``domain = z``.  Blank lines and ``#`` comments are ignored."""
    result = {}  # type: Dict[str, str]
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            result[key.strip().lower()] = value.strip()
    return result


def _env_default(name: str, fallback):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return fallback
    return value.strip()


def parse_args(argv: List[str]) -> types.SimpleNamespace:
    """Turn the command line into a flat options object.

    Raises UsageError for bad input.  Returns an object with attributes:
    host, query, user, password, domain, namespace (Impacket form), delimiter,
    debuglevel, auth_level, timeout, split_classes, version.
    """
    parser = build_parser()
    ns = parser.parse_intermixed_args(argv)

    opts = types.SimpleNamespace()
    opts.version = ns.version
    opts.debuglevel = ns.debuglevel or 0
    opts.delimiter = ns.delimiter
    opts.namespace = normalize_namespace(ns.namespace)
    opts.split_classes = ns.split_classes
    opts.ignored_options = list(ns.option or [])

    if ns.version:
        return opts

    if not ns.host or ns.query is None:
        parser.error("host (//HOST) and QUERY are required")
    opts.host = parse_host(ns.host)
    if not opts.host:
        raise EmptyHostError(
            "empty host name in %r (in Observium: 'Override WMI config' is enabled "
            "but the WMI hostname is blank)" % ns.host
        )
    opts.query = ns.query

    # Credentials: -A file first, then -U (which may carry DOMAIN and %PASSWORD),
    # then explicit --password / --workgroup / --no-pass override.
    user = ""
    password = None  # type: Optional[str]
    domain = None  # type: Optional[str]
    if ns.authentication_file:
        try:
            creds = read_auth_file(ns.authentication_file)
        except OSError as exc:
            parser.error("cannot read authentication file %s: %s" % (ns.authentication_file, exc))
        user = creds.get("username", user)
        password = creds.get("password", password)
        domain = creds.get("domain", domain)
    u_domain, u_user, u_password = parse_user(ns.user)
    if ns.user is not None:
        user = u_user
    if u_domain is not None:
        domain = u_domain
    if u_password is not None:
        password = u_password
    if ns.workgroup is not None and u_domain is None:
        domain = ns.workgroup
    if ns.password is not None:
        password = ns.password
    if ns.no_pass:
        password = ""
    opts.user = user
    opts.password = password if password is not None else ""
    opts.domain = domain or ""

    auth_level = ns.auth_level or _env_default(ENV_AUTH_LEVEL, DEFAULT_AUTH_LEVEL)
    auth_level = str(auth_level).lower()
    if auth_level not in AUTH_LEVELS:
        parser.error("invalid auth level %r (use %s)" % (auth_level, " or ".join(AUTH_LEVELS)))
    opts.auth_level = auth_level

    timeout = ns.timeout if ns.timeout is not None else _env_default(ENV_TIMEOUT, DEFAULT_TIMEOUT)
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        parser.error("invalid timeout %r" % (timeout,))
    if timeout < 0:
        parser.error("timeout must be >= 0")
    opts.timeout = timeout
    return opts


# ---------------------------------------------------------------------------
# Value formatting (string_CIMVAR in Samba's wmic.c)
# ---------------------------------------------------------------------------
def _clean_text(text: str) -> str:
    """Deliberate deviation from the original: CR/LF inside a value would break
    line-based parsers, so they are replaced with a single space."""
    if "\r" in text or "\n" in text:
        text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return text


def format_scalar(value: Any, cim_type: int) -> str:
    """Format a single (non-array) CIM value the way the original wmic did."""
    if value is None:
        return NULL_SCALAR
    if cim_type == CIM_BOOLEAN:
        # Impacket decodes booleans as the strings 'True'/'False'; be tolerant of
        # real bools and raw 0/0xFFFF too.  Decide by CIM type, not Python type.
        if isinstance(value, str):
            return "True" if value.strip().lower() in ("true", "1", "0xffff", "65535") else "False"
        return "True" if value else "False"
    if cim_type in CIM_INTEGER_TYPES:
        if isinstance(value, bool):
            return str(int(value))
        if isinstance(value, int):
            return str(value)
        return _clean_text(str(value))
    if cim_type in CIM_REAL_TYPES:
        try:
            return "%f" % float(value)
        except (TypeError, ValueError):
            return _clean_text(str(value))
    if cim_type in (CIM_CHAR16, CIM_OBJECT):
        return UNSUPPORTED
    # CIM_STRING, CIM_DATETIME, CIM_REFERENCE and anything unknown: raw text.
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return _clean_text(str(value))


def format_value(value: Any, raw_type: Optional[int]) -> str:
    """Format a property value given Impacket's raw ``type`` field (CimType plus
    the array / inherited flag bits)."""
    if raw_type is None:
        raw_type = CIM_STRING
    cim_type = raw_type & CIM_TYPE_MASK
    is_array = bool(raw_type & CIM_ARRAY_FLAG)
    if is_array:
        if value is None:
            return NULL_ARRAY
        if isinstance(value, (list, tuple)):
            if cim_type in (CIM_CHAR16, CIM_OBJECT):
                return UNSUPPORTED
            return "(" + ",".join(format_scalar(item, cim_type) for item in value) + ")"
        # Impacket stringifies class default values; nothing better to do than
        # to pass that text through.
        return _clean_text(str(value))
    return format_scalar(value, cim_type)


def _is_system_property(name: str) -> bool:
    return name.startswith("__")


class OutputFormatter:
    """Turns WMI objects into wmic-style text blocks.

    Default mode: one ``CLASS:`` line and one header for the whole result set,
    taken from the first object; later objects are printed in that column order
    (missing properties become ``(null)``, extra ones are dropped).  This keeps
    Observium's ``wmi_parse()`` happy when a query returns subclass instances.

    ``split_classes=True`` reproduces the original behaviour: a new ``CLASS:`` and
    header block whenever the class name changes.
    """

    def __init__(self, delimiter: str = DEFAULT_DELIMITER, split_classes: bool = False, fallback_class: str = ""):
        self.delimiter = delimiter
        self.split_classes = split_classes
        self.fallback_class = fallback_class
        self.columns = None  # type: Optional[List[str]]
        self.current_class = None  # type: Optional[str]
        self.rows = 0

    def feed(self, class_name: Optional[str], properties: Any) -> List[str]:
        """Return the output lines for one object."""
        props = _as_property_dict(properties)
        names = [n for n in props if not _is_system_property(n)]
        class_name = (class_name or "").strip() or self.fallback_class or "None"
        lines = []  # type: List[str]

        new_block = self.columns is None or (self.split_classes and class_name != self.current_class)
        if new_block:
            self.columns = names
            self.current_class = class_name
            lines.append("CLASS: %s" % class_name)
            lines.append(self.delimiter.join(names))

        values = []
        for name in self.columns or []:
            prop = props.get(name)
            if prop is None:
                values.append(NULL_SCALAR)
            else:
                values.append(format_value(prop.get("value"), prop.get("type")))
        lines.append(self.delimiter.join(values))
        self.rows += 1
        return lines


def _as_property_dict(properties: Any) -> "OrderedDict[str, Dict[str, Any]]":
    """Impacket returns an OrderedDict name -> {'type', 'value', ...}; it returns an
    empty tuple when the object could not be parsed."""
    if not properties:
        return OrderedDict()
    if isinstance(properties, dict):
        return OrderedDict(properties)
    return OrderedDict(properties)


def class_from_query(query: str) -> str:
    """Best-effort ``FROM <class>`` extraction, used when an object has no class name."""
    m = re.search(r"\bFROM\s+([A-Za-z_][\w]*)", query or "", re.IGNORECASE)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------
def _error_code(exc: BaseException) -> Optional[int]:
    getter = getattr(exc, "get_error_code", None)
    code = None
    if callable(getter):
        try:
            code = getter()
        except Exception:  # pragma: no cover - defensive
            code = None
    if code is None:
        code = getattr(exc, "error_code", None)
    if isinstance(code, int):
        return code & 0xFFFFFFFF
    return None


def classify_exception(exc: BaseException) -> Tuple[str, str]:
    """Map an exception to (NTSTATUS name, friendly text), best effort."""
    text = str(exc)
    low = text.lower()
    code = _error_code(exc)
    err_no = getattr(exc, "errno", None)

    if isinstance(exc, WatchdogTimeout) or isinstance(exc, socket.timeout) or "timed out" in low:
        status = "NT_STATUS_IO_TIMEOUT"
    elif err_no == errno.ECONNREFUSED or "connection refused" in low:
        status = "NT_STATUS_CONNECTION_REFUSED"
    elif err_no in (errno.EHOSTUNREACH, errno.ENETUNREACH) or "unreachable" in low or "no route to host" in low:
        status = "NT_STATUS_HOST_UNREACHABLE"
    elif isinstance(exc, EmptyHostError) or isinstance(exc, socket.gaierror) or "name or service not known" in low or "name resolution" in low \
            or "nodename nor servname" in low or "getaddrinfo failed" in low:
        status = "NT_STATUS_BAD_NETWORK_NAME"
    elif err_no == errno.ECONNRESET or "connection reset" in low or "connection closed by remote host" in low:
        status = "NT_STATUS_CONNECTION_RESET"
    elif code == 0x5 or "rpc_s_access_denied" in low or "status_logon_failure" in low or "logon failure" in low:
        # rpc_s_access_denied at bind time is what Windows returns for a bad
        # user name / password over ncacn_ip_tcp.
        status = "NT_STATUS_LOGON_FAILURE"
    elif code in (0x80070005, 0x80041003) or "access_denied" in low or "accessdenied" in low or "access denied" in low:
        status = "NT_STATUS_ACCESS_DENIED"
    else:
        status = "NT_STATUS_UNSUCCESSFUL"

    friendly = NTSTATUS_TEXT[status]
    if code is not None and code in HRESULT_TEXT:
        friendly = "%s (0x%08x)" % (HRESULT_TEXT[code], code)
    return status, friendly


def _is_s_false(exc: BaseException) -> bool:
    """IEnumWbemClassObject::Next signals the end of the enumeration with
    WBEM_S_FALSE (HRESULT 1), which Impacket raises as an exception."""
    if _error_code(exc) == 1:
        return True
    return "S_FALSE" in str(exc)


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------
class Watchdog:
    """Hard time limit for the whole run, based on SIGALRM.

    The first alarm raises WatchdogTimeout in the main thread, which unwinds
    through Impacket (blocking socket calls are interrupted, PEP 475).  Should
    anything swallow that, a second alarm GRACE seconds later calls the
    ``hard_timeout`` callback, which is expected to report and ``os._exit``.
    """

    GRACE = 5

    def __init__(self, seconds: float, hard_timeout):
        self.seconds = seconds
        self.hard_timeout = hard_timeout
        self.fired = 0
        self._armed = False
        self._previous = None

    def __enter__(self):
        if self.seconds and self.seconds > 0 and hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer"):
            self._previous = signal.signal(signal.SIGALRM, self._handle)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
            self._armed = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # signal.signal() returns None for a handler not installed from Python.
            signal.signal(signal.SIGALRM, self._previous if self._previous is not None else signal.SIG_DFL)
            self._armed = False
        return False

    def _handle(self, signum, frame):
        self.fired += 1
        if self.fired == 1:
            signal.setitimer(signal.ITIMER_REAL, self.GRACE)
            raise WatchdogTimeout("no result after %g seconds" % self.seconds)
        self.hard_timeout()


# ---------------------------------------------------------------------------
# The actual WMI conversation
# ---------------------------------------------------------------------------
def load_impacket() -> types.SimpleNamespace:
    """Import just the Impacket pieces we need (startup time matters on slow boxes)."""
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    return types.SimpleNamespace(
        DCOMConnection=DCOMConnection,
        wmi=wmi,
        NULL=NULL,
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    )


def impacket_version() -> str:
    try:
        from importlib.metadata import version as _pkg_version  # Python 3.8+

        return _pkg_version("impacket")
    except Exception:
        return "unknown"


def _quiet_release(obj, what: str) -> None:
    """RemRelease() is cleanup; a failure there must not turn a good result into an error."""
    try:
        obj.RemRelease()
    except Exception as exc:  # noqa: BLE001 - cleanup
        log.debug("ignoring %s.RemRelease() failure: %s", what, exc)


def run_query(opts: types.SimpleNamespace, out, impacket: Optional[types.SimpleNamespace] = None) -> int:
    """Connect, log in to the namespace, run the query and write the result to ``out``.

    Raises WmicError(MSG_LOGIN) for anything that goes wrong up to and including
    NTLMLogin, and WmicError(MSG_RESULT) for ExecQuery/Next failures.  Always
    disconnects the DCOM connection it managed to open.
    """
    imp = impacket or load_impacket()
    if opts.auth_level == "integrity":
        level = imp.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
    else:
        level = imp.RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    formatter = OutputFormatter(opts.delimiter, opts.split_classes, class_from_query(opts.query))
    dcom = None
    try:
        # --- "Login to remote object." phase -------------------------------
        try:
            log.debug("connecting to %s as %r (domain %r), auth level %s", opts.host, opts.user, opts.domain, opts.auth_level)
            # oxidResolver=False: no keep-alive ping Timer thread is started.  A
            # one-shot query is over long before the server would garbage-collect
            # anything, and it removes a classic source of hangs at exit.
            # authLevel covers the IRemoteSCMActivator (activation) binding, which
            # is exactly the call event 10036 complains about.
            dcom = imp.DCOMConnection(
                opts.host,
                opts.user,
                opts.password,
                opts.domain,
                "",  # lmhash
                "",  # nthash
                None,  # aesKey
                oxidResolver=False,
                doKerberos=False,
                authLevel=level,
            )
            iface = dcom.CoCreateInstanceEx(imp.wmi.CLSID_WbemLevel1Login, imp.wmi.IID_IWbemLevel1Login)
            login = imp.wmi.IWbemLevel1Login(iface)
            log.debug("NTLMLogin to namespace %s", opts.namespace)
            services = login.NTLMLogin(opts.namespace, imp.NULL, imp.NULL)
            # The IWbemServices calls themselves: wmiquery.py sets the level on the
            # existing DCE binding; we also pin it on the class instance so that any
            # further connection Impacket opens for this object uses it too.
            try:
                services.get_dce_rpc().set_auth_level(level)
            except Exception as exc:  # noqa: BLE001 - KeyError if no binding yet
                log.debug("could not set auth level on existing binding: %s", exc)
            try:
                services.get_cinstance().set_auth_level(level)
            except Exception as exc:  # noqa: BLE001
                log.debug("could not set auth level on class instance: %s", exc)
            _quiet_release(login, "IWbemLevel1Login")
        except WatchdogTimeout:
            raise
        except Exception as exc:
            raise WmicError(MSG_LOGIN, exc)

        # --- "Retrieve result data." phase ----------------------------------
        enum = None
        try:
            log.debug("ExecQuery: %s", opts.query)
            enum = services.ExecQuery(opts.query)
            while True:
                try:
                    objects = enum.Next(0xFFFFFFFF, 1)
                except Exception as exc:
                    if _is_s_false(exc):
                        break
                    raise
                if not objects:
                    break
                for obj in objects:
                    for line in formatter.feed(obj.getClassName(), obj.getProperties()):
                        out.write(line + "\n")
        except WatchdogTimeout:
            raise
        except Exception as exc:
            raise WmicError(MSG_RESULT, exc)
        finally:
            if enum is not None:
                _quiet_release(enum, "IEnumWbemClassObject")
        _quiet_release(services, "IWbemServices")
        log.debug("%d row(s)", formatter.rows)
        return 0
    finally:
        if dcom is not None:
            try:
                dcom.disconnect()
            except Exception as exc:  # noqa: BLE001 - nothing useful left to do
                log.debug("disconnect failed: %s", exc)


# ---------------------------------------------------------------------------
# Reporting and entry points
# ---------------------------------------------------------------------------
def report_error(out, err, message: str, exc: Optional[BaseException], debuglevel: int = 0) -> None:
    """Print the wmic-style error: ``ERROR:`` line on stdout (Observium reads it),
    ``NTSTATUS:`` line plus the underlying reason on stderr (humans read it)."""
    out.write("%s ERROR: %s\n" % (TAG, message))
    if exc is not None:
        status, friendly = classify_exception(exc)
        detail = "%s: %s" % (type(exc).__name__, str(exc).strip() or "(no message)")
    else:
        status, friendly = "NT_STATUS_UNSUCCESSFUL", NTSTATUS_TEXT["NT_STATUS_UNSUCCESSFUL"]
        detail = ""
    err.write("NTSTATUS: %s - %s\n" % (status, friendly))
    if detail:
        err.write("%s %s\n" % (TAG, detail))
    if debuglevel >= 1 and exc is not None and exc.__traceback__ is not None:
        err.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))


def configure_logging(debuglevel: int, err) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    if debuglevel >= 1:
        handler = logging.StreamHandler(err)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
    else:
        # Keep Impacket quiet: without a handler, Python's "last resort" handler
        # would print WARNING+ records to stderr.
        root.addHandler(logging.NullHandler())
        root.setLevel(logging.CRITICAL)


def version_string() -> str:
    return "Version %s (wmic-impacket %s, impacket %s)" % (SAMBA_WMIC_VERSION, __version__, impacket_version())


def run(argv: Optional[List[str]] = None, stdout=None, stderr=None, impacket: Optional[types.SimpleNamespace] = None) -> int:
    """Run one wmic invocation; returns the exit code.  Pure enough to be tested:
    ``impacket`` may be a fake namespace, stdout/stderr may be StringIO objects."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    if argv is None:
        argv = sys.argv[1:]

    # Values can contain anything (German service descriptions...), and Observium
    # may run us under the C locale: never fail on encoding.
    for stream in (out, err):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass

    try:
        opts = parse_args(list(argv))
    except EmptyHostError as exc:
        report_error(out, err, MSG_LOGIN, exc)
        return 1
    except UsageError as exc:
        out.write("%s ERROR: %s\n" % (TAG, exc))
        err.write(build_parser().format_usage())
        err.write("%s: error: %s (try --help)\n" % (TAG, exc))
        return 1
    except SystemExit as exc:  # --help prints and exits via argparse
        return exc.code if isinstance(exc.code, int) else 1

    if opts.version:
        out.write(version_string() + "\n")
        return 0

    configure_logging(opts.debuglevel, err)
    for ignored in opts.ignored_options:
        log.debug("ignoring --option %s", ignored)

    def hard_timeout():
        try:
            report_error(out, err, MSG_LOGIN, WatchdogTimeout("watchdog: still running %g s after the timeout" % Watchdog.GRACE))
            out.flush()
            err.flush()
        finally:
            os._exit(1)

    # Anything Impacket print()s (resp.dump(), hexdumps in debug mode) must not
    # land in the stream Observium parses.
    saved_stdout = sys.stdout
    sys.stdout = err
    code = 1
    try:
        with Watchdog(opts.timeout, hard_timeout):
            code = run_query(opts, out, impacket)
    except WmicError as exc:
        report_error(out, err, exc.message, exc.cause, opts.debuglevel)
        code = 1
    except WatchdogTimeout as exc:
        report_error(out, err, MSG_LOGIN, exc, opts.debuglevel)
        code = 1
    except KeyboardInterrupt:
        err.write("%s interrupted\n" % TAG)
        code = 1
    except Exception as exc:  # noqa: BLE001 - e.g. Impacket missing or an internal bug
        # Still produce the ERROR: line so Observium sees a failure, not "no rows".
        report_error(out, err, MSG_LOGIN, exc, opts.debuglevel)
        code = 1
    finally:
        sys.stdout = saved_stdout
    return code


def main(argv: Optional[List[str]] = None) -> None:
    """Console entry point.  Ends with os._exit() so that a stray non-daemon thread
    (Impacket's DCOM ping timer, should one ever be started) cannot keep the process
    alive after we are done."""
    code = 1
    try:
        code = run(argv)
    except BrokenPipeError:
        code = 1
    finally:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:  # noqa: BLE001
                pass
        os._exit(code)


if __name__ == "__main__":
    main()
