"""Offline tests for wmic_impacket.

No Windows host is needed: the Impacket objects are replaced by small fakes that
behave like DCOMConnection / IWbemLevel1Login / IWbemServices /
IEnumWbemClassObject, and the Observium side is exercised with the real PHP
wmi_parse() function (tests/observium_wmi_parse.php) when ``php`` is installed.

Run with:  python -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from collections import OrderedDict
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import wmic_impacket as w  # noqa: E402

PHP = shutil.which("php")
PHP_SCRIPT = os.path.join(HERE, "observium_wmi_parse.php")

# What Observium's includes/wmi.inc.php builds (shell quoting already removed by
# the shell, as it would be when external_exec() runs the command).
OBSERVIUM_CMD = (
    r"""--user='wmi' --password='Secret%42' --workgroup='WORKGROUP' --delimiter=## """
    r"""--namespace='root\CIMV2' //192.0.2.10 "SELECT Name,State FROM Win32_Service" """
)


# ---------------------------------------------------------------------------
# Fakes standing in for Impacket
# ---------------------------------------------------------------------------
class FakeSessionError(Exception):
    """Looks like impacket's DCERPCSessionError / DCERPCException."""

    def __init__(self, error_code, text=None, packet=None):
        Exception.__init__(self)
        self.error_code = error_code
        self._text = text
        self.packet = packet

    def get_error_code(self):
        return self.error_code

    def get_packet(self):
        return self.packet

    def __str__(self):
        if self._text:
            return self._text
        if self.error_code == 1:
            return "WMI Session Error: code: 0x1 - WBEM_S_FALSE"
        return "WMI Session Error: code: 0x%x" % self.error_code


def S(value):
    return {"type": w.CIM_STRING, "value": value}


def U32(value):
    return {"type": w.CIM_UINT32, "value": value}


def B(value):
    return {"type": w.CIM_BOOLEAN, "value": value}


class FakeObj:
    def __init__(self, class_name, props):
        self._class = class_name
        self._props = OrderedDict(props)

    def getClassName(self):
        return self._class

    def getProperties(self):
        return self._props


class _FakeObjRegistry:
    """Round-trips a FakeObj through the real tool's byte path: the tool joins
    ``item['abData']`` into raw bytes and rebuilds the object with
    imp.INTERFACE / imp.wmi.IWbemClassObject, so the fakes hand it a token it can
    hand back."""

    _store = {}  # type: dict
    _n = 0

    @classmethod
    def encode(cls, obj):
        cls._n += 1
        token = b"FAKEOBJ:%d;" % cls._n
        cls._store[token] = obj
        return token

    @classmethod
    def decode(cls, raw):
        return cls._store[raw]


class FakePacket:
    """Stands in for a decoded IEnumWbemClassObject_NextResponse carried by the
    WBEM_S_FALSE exception: holds the objects of the final short batch, encoded
    the way a real NextResponse carries them (apObjects[i]['abData'] = bytes)."""

    def __init__(self, objects, returned=None):
        self._data = {
            "apObjects": [{"abData": [_FakeObjRegistry.encode(o)]} for o in objects],
            "puReturned": len(objects) if returned is None else returned,
        }

    def __getitem__(self, key):
        return self._data[key]


class FakeINTERFACE:
    """Stand-in for dcomrt.INTERFACE: keeps the raw object bytes the tool joins."""

    def __init__(self, cinstance, raw, ipid, oxid=None, target=None):
        self.raw = raw


class FakeWbemClassObject:
    """Stand-in for wmi.IWbemClassObject: returns the FakeObj the token maps to."""

    def __new__(cls, interface, services=None):
        return _FakeObjRegistry.decode(interface.raw)


# Two real-world server behaviours for ending an enumeration; the tool must
# cope with both:
#   "short": the reply that returns the final, short batch also carries
#            WBEM_S_FALSE, so Impacket raises and the objects live only in the
#            exception's packet (the case --batch-size exercises).
#   "empty": available objects come back as WBEM_S_NO_ERROR; a final empty reply
#            carries WBEM_S_FALSE (the classic one-object-per-call loop).
S_FALSE_SHORT = "short"
S_FALSE_EMPTY = "empty"


class FakeEnum:
    """Models a semi-synchronous IEnumWbemClassObject: Next(timeout, count)
    returns up to ``count`` objects per call."""

    def __init__(self, objects, fail_after=None, sleep=0, noisy=False, s_false=S_FALSE_SHORT, no_packet=False):
        self._objects = list(objects)
        self._fail_after = fail_after
        self._sleep = sleep
        self._noisy = noisy
        self._s_false = s_false
        self._no_packet = no_packet  # simulate a reply Impacket could not decode
        self.calls = 0
        self.max_count = 0
        self.released = False

    def get_cinstance(self):
        return self

    def get_ipidRemUnknown(self):
        return None

    def get_oxid(self):
        return None

    def get_target(self):
        return "192.0.2.10"

    def Next(self, timeout, count):
        self.calls += 1
        self.max_count = max(self.max_count, count)
        if self._sleep:
            time.sleep(self._sleep)
        if self._noisy:
            print("stray print from inside impacket")
        if self._fail_after is not None and self.calls > self._fail_after:
            raise FakeSessionError(0x80041010, "WMI Session Error: code: 0x80041010 - WBEM_E_INVALID_CLASS")
        batch = self._objects[:count]
        del self._objects[:count]
        packet = None if self._no_packet else FakePacket(batch)
        if self._s_false == S_FALSE_SHORT:
            # A reply carries WBEM_S_FALSE as soon as it returns fewer than asked.
            if len(batch) < count:
                raise FakeSessionError(1, packet=packet)
            return batch
        # S_FALSE_EMPTY: full replies are WBEM_S_NO_ERROR, then one trailing reply
        # carries WBEM_S_FALSE with an empty but decodable NextResponse.
        if batch:
            return batch
        raise FakeSessionError(1, packet=(None if self._no_packet else FakePacket([])))

    def RemRelease(self):
        self.released = True


class FakeDce:
    def __init__(self):
        self.auth_level = None

    def set_auth_level(self, level):
        self.auth_level = level


class FakeServices:
    def __init__(self, fab):
        self._fab = fab
        self.dce = FakeDce()
        self.cinstance = FakeDce()
        self.queries = []
        self.released = False
        self.enum = None

    def get_dce_rpc(self):
        return self.dce

    def get_cinstance(self):
        return self.cinstance

    def ExecQuery(self, query):
        self.queries.append(query)
        if self._fab.fail_at == "query":
            raise FakeSessionError(0x80041017, "WMI Session Error: code: 0x80041017 - WBEM_E_INVALID_QUERY")
        self.enum = FakeEnum(
            self._fab.objects,
            fail_after=0 if self._fab.fail_at == "next" else self._fab.fail_after,
            sleep=self._fab.sleep,
            noisy=self._fab.noisy,
            s_false=self._fab.s_false,
            no_packet=self._fab.no_packet,
        )
        return self.enum

    def RemRelease(self):
        self.released = True


class FakeLogin:
    def __init__(self, iface):
        self._fab = iface.fab
        self.released = False
        self.namespaces = []

    def NTLMLogin(self, namespace, locale, ctx):
        self.namespaces.append(namespace)
        if self._fab.fail_at == "login":
            raise FakeSessionError(0x80041003, "WMI Session Error: code: 0x80041003 - WBEM_E_ACCESS_DENIED")
        self._fab.login = self
        self._fab.services = FakeServices(self._fab)
        return self._fab.services

    def RemRelease(self):
        self.released = True


class FakeDCOM:
    """Stands in for impacket.dcerpc.v5.dcomrt.DCOMConnection."""

    def __init__(self, fab, target, username, password, domain, lmhash, nthash, aesKey, **kwargs):
        self.fab = fab
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.kwargs = kwargs
        self.disconnected = False
        fab.dcom = self
        if fab.fail_at == "connect":
            raise FakeSessionError(None, "DCERPC Runtime Error: Could not connect: [Errno 111] Connection refused")
        if fab.fail_at == "logon":
            raise FakeSessionError(0x5, "DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied ")

    def CoCreateInstanceEx(self, clsid, iid):
        self.activated = (clsid, iid)
        if self.fab.fail_at == "activate":
            raise FakeSessionError(0x80070005, "DCERPC Runtime Error: unknown error code: 0x80070005")
        return types.SimpleNamespace(fab=self.fab)

    def disconnect(self):
        self.disconnected = True


class Fabric:
    """Builds a fake impacket namespace and records what happened."""

    def __init__(self, objects=(), fail_at=None, fail_after=None, sleep=0, noisy=False, s_false=S_FALSE_SHORT, no_packet=False):
        self.objects = list(objects)
        self.fail_at = fail_at
        self.fail_after = fail_after
        self.sleep = sleep
        self.noisy = noisy
        self.s_false = s_false
        self.no_packet = no_packet
        self.dcom = None
        self.login = None
        self.services = None
        fab = self

        class DCOM(FakeDCOM):
            def __init__(self, *args, **kwargs):
                FakeDCOM.__init__(self, fab, *args, **kwargs)

        self.impacket = types.SimpleNamespace(
            DCOMConnection=DCOM,
            INTERFACE=FakeINTERFACE,
            wmi=types.SimpleNamespace(
                CLSID_WbemLevel1Login="CLSID",
                IID_IWbemLevel1Login="IID",
                IWbemLevel1Login=FakeLogin,
                IWbemClassObject=FakeWbemClassObject,
                DCERPCSessionError=FakeSessionError,
            ),
            NULL=None,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY=5,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY=6,
        )


def run_fake(argv, fab):
    out, err = io.StringIO(), io.StringIO()
    code = w.run(shlex.split(argv) if isinstance(argv, str) else argv, out, err, impacket=fab.impacket)
    return code, out.getvalue(), err.getvalue()


SERVICES = [
    FakeObj("Win32_Service", [("Name", S("Spooler")), ("State", S("Running")), ("Started", B("True"))]),
    FakeObj("Win32_Service", [("Name", S("Fax")), ("State", S("Stopped")), ("Started", B("False"))]),
]

MIXED = [
    FakeObj("Win32_Service", [("Name", S("Spooler")), ("State", S("Running")), ("ProcessId", U32(1234))]),
    FakeObj("Win32_TerminalService", [("Name", S("TermService")), ("State", S("Running")), ("ProcessId", U32(0)), ("TotalSessions", U32(3))]),
    FakeObj("Win32_Service", [("Name", S("Fax")), ("State", S("Stopped"))]),  # ProcessId missing
]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
class TestParseUser(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(w.parse_user("wmi"), (None, "wmi", None))
        self.assertEqual(w.parse_user("DOM\\user"), ("DOM", "user", None))
        self.assertEqual(w.parse_user("DOM/user"), ("DOM", "user", None))
        self.assertEqual(w.parse_user("user@dom.local"), ("dom.local", "user", None))
        self.assertEqual(w.parse_user("DOM\\user%pw"), ("DOM", "user", "pw"))
        self.assertEqual(w.parse_user("user%p%w"), (None, "user", "p%w"))
        self.assertEqual(w.parse_user("user%"), (None, "user", ""))
        self.assertEqual(w.parse_user(None), (None, "", None))
        self.assertEqual(w.parse_user(""), (None, "", None))


class TestParseHost(unittest.TestCase):
    def test_forms(self):
        cases = {
            "//192.0.2.10": "192.0.2.10",
            "192.0.2.10": "192.0.2.10",
            "//winhost": "winhost",
            "\\\\winhost": "winhost",
            "//ncacn_ip_tcp:host.domain.local[sign]": "host.domain.local",
            "ncacn_ip_tcp:host[sign,seal]": "host",
            "//NCACN_IP_TCP:1.2.3.4": "1.2.3.4",
            "//host[sign]": "host",
            "//[fe80::1]": "fe80::1",
            "//[fe80::1][sign]": "fe80::1",
            "//ncacn_ip_tcp:[2001:db8::5]": "2001:db8::5",
            "fe80::1": "fe80::1",
            "  //host  ": "host",
        }
        for spec, expected in cases.items():
            self.assertEqual(w.parse_host(spec), expected, spec)


class TestNamespace(unittest.TestCase):
    def test_conversion(self):
        cases = {
            "root\\cimv2": "//./root/cimv2",
            "root\\CIMV2": "//./root/CIMV2",
            "root/cimv2": "//./root/cimv2",
            "\\\\.\\root\\cimv2": "//./root/cimv2",
            "//./root/cimv2": "//./root/cimv2",
            "\\\\server\\root\\default": "//server/root/default",
            "/root/wmi": "//./root/wmi",
            "": "//./root/cimv2",
            None: "//./root/cimv2",
        }
        for spec, expected in cases.items():
            self.assertEqual(w.normalize_namespace(spec), expected, repr(spec))


class TestArgs(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.pop(k, None) for k in (w.ENV_AUTH_LEVEL, w.ENV_TIMEOUT, w.ENV_OUTPUT_STYLE, w.ENV_BATCH_SIZE)}

    def tearDown(self):
        for k, v in self._env.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

    def check_observium(self, opts):
        self.assertEqual(opts.host, "192.0.2.10")
        self.assertEqual(opts.query, "SELECT Name,State FROM Win32_Service")
        self.assertEqual(opts.user, "wmi")
        self.assertEqual(opts.domain, "WORKGROUP")
        self.assertEqual(opts.delimiter, "##")
        self.assertEqual(opts.namespace, "//./root/CIMV2")
        self.assertEqual(opts.auth_level, "privacy")
        self.assertEqual(opts.timeout, 30.0)
        self.assertEqual(opts.output_style, "per-object")
        self.assertFalse(opts.split_classes)

    def test_observium_command_line(self):
        opts = w.parse_args(shlex.split(OBSERVIUM_CMD))
        self.check_observium(opts)
        self.assertEqual(opts.password, "Secret%42")
        self.assertEqual(opts.debuglevel, 0)

    def test_observium_command_line_debug(self):
        cmd = OBSERVIUM_CMD.replace("//192.0.2.10", "-d2 //192.0.2.10")
        opts = w.parse_args(shlex.split(cmd))
        self.check_observium(opts)
        self.assertEqual(opts.debuglevel, 2)

    def test_observium_command_line_no_pass(self):
        cmd = OBSERVIUM_CMD.replace("--password='Secret%42' ", "--no-pass ")
        opts = w.parse_args(shlex.split(cmd))
        self.check_observium(opts)
        self.assertEqual(opts.password, "")

    def test_observium_extra_flags_appended_to_binary_path(self):
        # $config['wmic'] = '/opt/wmic-impacket/bin/wmic --timeout 20 --auth-level integrity';
        opts = w.parse_args(shlex.split("--timeout 20 --auth-level integrity " + OBSERVIUM_CMD))
        self.assertEqual(opts.timeout, 20.0)
        self.assertEqual(opts.auth_level, "integrity")

    def test_options_after_positionals(self):
        opts = w.parse_args(["//host", "select * from x", "-U", "u%p", "-d", "1"])
        self.assertEqual((opts.host, opts.user, opts.password, opts.debuglevel), ("host", "u", "p", 1))

    def test_user_forms(self):
        opts = w.parse_args(["-U", "DOM\\user%pw", "//h", "q"])
        self.assertEqual((opts.domain, opts.user, opts.password), ("DOM", "user", "pw"))
        opts = w.parse_args(["-U", "DOM/user", "--password", "x", "//h", "q"])
        self.assertEqual((opts.domain, opts.user, opts.password), ("DOM", "user", "x"))
        opts = w.parse_args(["-U", "user@dom.local", "//h", "q"])
        self.assertEqual((opts.domain, opts.user, opts.password), ("dom.local", "user", ""))
        opts = w.parse_args(["--user=wmi", "-W", "WG", "//h", "q"])
        self.assertEqual((opts.domain, opts.user), ("WG", "wmi"))
        # the domain inside -U wins over -W, like Samba
        opts = w.parse_args(["-U", "DOM\\u", "-W", "WG", "//h", "q"])
        self.assertEqual(opts.domain, "DOM")
        # explicit --password overrides %password
        opts = w.parse_args(["-U", "u%a", "--password", "b", "//h", "q"])
        self.assertEqual(opts.password, "b")
        # -N clears the password
        opts = w.parse_args(["-U", "u%a", "-N", "//h", "q"])
        self.assertEqual(opts.password, "")

    def test_authentication_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".auth", delete=False) as fh:
            fh.write("# samba style\nusername = wmi\npassword = p = q\ndomain=WG\n\n")
            path = fh.name
        try:
            opts = w.parse_args(["-A", path, "//h", "q"])
            self.assertEqual((opts.user, opts.password, opts.domain), ("wmi", "p = q", "WG"))
            # command line overrides the file
            opts = w.parse_args(["-A", path, "-U", "other", "//h", "q"])
            self.assertEqual((opts.user, opts.password, opts.domain), ("other", "p = q", "WG"))
        finally:
            os.unlink(path)
        with self.assertRaises(w.UsageError):
            w.parse_args(["-A", path + ".missing", "//h", "q"])

    def test_ignored_samba_options(self):
        argv = shlex.split(
            "-s /etc/samba/smb.conf -l /tmp/log -R lmhosts -m NT1 -n NB -S off -k no --realm R -i SC "
            "-P --simple-bind-dn cn=x -O TCP_NODELAY --option='client ntlmv2 auth'=yes --option=foo=bar "
            "--debug-stderr --leak-report --use-security-mechanisms ntlmssp "
            "-U u //host 'select 1'"
        )
        opts = w.parse_args(argv)
        self.assertEqual((opts.host, opts.query, opts.user), ("host", "select 1", "u"))
        self.assertEqual(opts.ignored_options, ["client ntlmv2 auth=yes", "foo=bar"])

    def test_env_defaults(self):
        os.environ[w.ENV_AUTH_LEVEL] = "integrity"
        os.environ[w.ENV_TIMEOUT] = "7.5"
        opts = w.parse_args(["//h", "q"])
        self.assertEqual((opts.auth_level, opts.timeout), ("integrity", 7.5))
        opts = w.parse_args(["--auth-level", "privacy", "--timeout", "0", "//h", "q"])
        self.assertEqual((opts.auth_level, opts.timeout), ("privacy", 0.0))
        os.environ[w.ENV_AUTH_LEVEL] = "bogus"
        with self.assertRaises(w.UsageError):
            w.parse_args(["//h", "q"])

    def test_usage_errors(self):
        for argv in (["//h"], [], ["--bogus", "//h", "q"], ["--auth-level", "none", "//h", "q"], ["--timeout", "-1", "//h", "q"], ["//", "q"]):
            with self.assertRaises(w.UsageError, msg=argv):
                w.parse_args(argv)

    def test_output_style(self):
        self.assertEqual(w.parse_args(["//h", "q"]).output_style, "per-object")
        self.assertEqual(w.parse_args(["--output-style", "single", "//h", "q"]).output_style, "single")
        self.assertEqual(w.parse_args(["--output-style=split", "//h", "q"]).output_style, "split")
        self.assertEqual(w.parse_args(["--split-classes", "//h", "q"]).output_style, "split")
        # an explicit --output-style beats --split-classes
        self.assertEqual(w.parse_args(["--split-classes", "--output-style", "single", "//h", "q"]).output_style, "single")
        os.environ[w.ENV_OUTPUT_STYLE] = "Single"
        self.assertEqual(w.parse_args(["//h", "q"]).output_style, "single")
        self.assertEqual(w.parse_args(["--output-style", "per-object", "//h", "q"]).output_style, "per-object")
        os.environ[w.ENV_OUTPUT_STYLE] = "bogus"
        with self.assertRaises(w.UsageError):
            w.parse_args(["//h", "q"])
        with self.assertRaises(w.UsageError):
            w.parse_args(["--output-style", "bogus", "//h", "q"])

    def test_batch_size(self):
        self.assertEqual(w.parse_args(["//h", "q"]).batch_size, w.DEFAULT_BATCH_SIZE)
        self.assertEqual(w.parse_args(["--batch-size", "1", "//h", "q"]).batch_size, 1)
        self.assertEqual(w.parse_args(["--batch-size", "500", "//h", "q"]).batch_size, 500)
        os.environ[w.ENV_BATCH_SIZE] = "250"
        self.assertEqual(w.parse_args(["//h", "q"]).batch_size, 250)
        self.assertEqual(w.parse_args(["--batch-size", "1", "//h", "q"]).batch_size, 1)
        for bad in ("0", "-5", str(w.MAX_BATCH_SIZE + 1), "x"):
            with self.assertRaises(w.UsageError, msg=bad):
                w.parse_args(["--batch-size", bad, "//h", "q"])
        os.environ[w.ENV_BATCH_SIZE] = "nonsense"
        with self.assertRaises(w.UsageError):
            w.parse_args(["//h", "q"])

    def test_version_and_split(self):
        self.assertTrue(w.parse_args(["-V"]).version)
        self.assertTrue(w.parse_args(["--split-classes", "//h", "q"]).split_classes)
        self.assertIn("4.0.0tp4-SVN-build-UNKNOWN", w.version_string())
        self.assertIn("wmic-impacket %s" % w.__version__, w.version_string())


# ---------------------------------------------------------------------------
# Value formatting
# ---------------------------------------------------------------------------
class TestFormatting(unittest.TestCase):
    def test_integers(self):
        for t in (w.CIM_SINT8, w.CIM_UINT8, w.CIM_SINT16, w.CIM_UINT16, w.CIM_SINT32, w.CIM_UINT32, w.CIM_SINT64):
            self.assertEqual(w.format_value(-5 if t in (w.CIM_SINT8, w.CIM_SINT16, w.CIM_SINT32, w.CIM_SINT64) else 5, t), "-5" if t in (w.CIM_SINT8, w.CIM_SINT16, w.CIM_SINT32, w.CIM_SINT64) else "5")
        self.assertEqual(w.format_value(2 ** 64 - 1, w.CIM_UINT64), "18446744073709551615")
        self.assertEqual(w.format_value(0, w.CIM_UINT32), "0")
        # inherited flag must not change the type
        self.assertEqual(w.format_value(123, w.CIM_SINT32 | w.CIM_INHERITED_FLAG), "123")
        # stringified class default passes through
        self.assertEqual(w.format_value("7", w.CIM_UINT32), "7")

    def test_booleans_by_cim_type(self):
        self.assertEqual(w.format_value("True", w.CIM_BOOLEAN), "True")
        self.assertEqual(w.format_value("False", w.CIM_BOOLEAN), "False")
        self.assertEqual(w.format_value(True, w.CIM_BOOLEAN), "True")
        self.assertEqual(w.format_value(0, w.CIM_BOOLEAN), "False")
        self.assertEqual(w.format_value(0xFFFF, w.CIM_BOOLEAN), "True")
        self.assertEqual(w.format_value(None, w.CIM_BOOLEAN), "(null)")
        # a Python bool with an integer CIM type is still a number
        self.assertEqual(w.format_value(True, w.CIM_UINT16), "1")

    def test_reals(self):
        self.assertEqual(w.format_value(1.5, w.CIM_REAL32), "1.500000")
        self.assertEqual(w.format_value(2.0, w.CIM_REAL64), "2.000000")
        self.assertEqual(w.format_value(3, w.CIM_REAL64), "3.000000")
        self.assertEqual(w.format_value("x", w.CIM_REAL64), "x")

    def test_strings_datetime_reference(self):
        self.assertEqual(w.format_value("Hello", w.CIM_STRING), "Hello")
        self.assertEqual(w.format_value("20231005123456.000000+120", w.CIM_DATETIME), "20231005123456.000000+120")
        self.assertEqual(w.format_value('\\\\PC\\root\\cimv2:Win32_Service.Name="x"', w.CIM_REFERENCE), '\\\\PC\\root\\cimv2:Win32_Service.Name="x"')
        self.assertEqual(w.format_value(None, w.CIM_STRING), "(null)")
        self.assertEqual(w.format_value("", w.CIM_STRING), "")
        self.assertEqual(w.format_value("Ärger", w.CIM_STRING), "Ärger")
        self.assertEqual(w.format_value(b"bytes", w.CIM_STRING), "bytes")
        self.assertEqual(w.format_value("x", None), "x")

    def test_newlines_replaced(self):
        self.assertEqual(w.format_value("line1\r\nline2\nline3\rend", w.CIM_STRING), "line1 line2 line3 end")
        self.assertEqual(w.format_value(["a\nb", "c"], w.CIM_STRING | w.CIM_ARRAY_FLAG), "(a b,c)")

    def test_unsupported(self):
        self.assertEqual(w.format_value(65, w.CIM_CHAR16), "Unsupported")
        self.assertEqual(w.format_value(object(), w.CIM_OBJECT), "Unsupported")
        self.assertEqual(w.format_value([object()], w.CIM_OBJECT | w.CIM_ARRAY_FLAG), "Unsupported")

    def test_arrays(self):
        self.assertEqual(w.format_value([1, 2, 3], w.CIM_UINT32 | w.CIM_ARRAY_FLAG), "(1,2,3)")
        self.assertEqual(w.format_value(["a", "b"], w.CIM_STRING | w.CIM_ARRAY_FLAG), "(a,b)")
        self.assertEqual(w.format_value(["True", "False"], w.CIM_BOOLEAN | w.CIM_ARRAY_FLAG), "(True,False)")
        self.assertEqual(w.format_value([1.0], w.CIM_REAL32 | w.CIM_ARRAY_FLAG), "(1.000000)")
        self.assertEqual(w.format_value([None, "x"], w.CIM_STRING | w.CIM_ARRAY_FLAG), "((null),x)")
        self.assertEqual(w.format_value([], w.CIM_STRING | w.CIM_ARRAY_FLAG), "()")
        self.assertEqual(w.format_value(None, w.CIM_STRING | w.CIM_ARRAY_FLAG), "NULL")
        self.assertEqual(w.format_value(None, w.CIM_UINT8 | w.CIM_ARRAY_FLAG | w.CIM_INHERITED_FLAG), "NULL")
        self.assertEqual(w.format_value((1, 2), w.CIM_SINT16 | w.CIM_ARRAY_FLAG), "(1,2)")

    def test_class_from_query(self):
        self.assertEqual(w.class_from_query("SELECT * FROM Win32_Service WHERE x=1"), "Win32_Service")
        self.assertEqual(w.class_from_query("select name from win32_bios"), "win32_bios")
        self.assertEqual(w.class_from_query("ASSOCIATORS OF {x}"), "")


# ---------------------------------------------------------------------------
# Block layout
# ---------------------------------------------------------------------------
class TestOutputFormatter(unittest.TestCase):
    def render(self, objects, **kwargs):
        f = w.OutputFormatter(**kwargs)
        lines = []
        for obj in objects:
            lines.extend(f.feed(obj.getClassName(), obj.getProperties()))
        return lines

    def test_per_object_default(self):
        lines = self.render(MIXED, delimiter="##")
        self.assertEqual(
            lines,
            [
                "CLASS: Win32_Service",
                "Name##State##ProcessId",
                "Spooler##Running##1234",
                "CLASS: Win32_TerminalService",
                "Name##State##ProcessId##TotalSessions",
                "TermService##Running##0##3",
                "CLASS: Win32_Service",
                "Name##State",
                "Fax##Stopped",
            ],
        )
        # same class twice: still one block per object
        lines = self.render(SERVICES)
        self.assertEqual(lines.count("CLASS: Win32_Service"), 2)
        self.assertEqual(lines.count("Name|State|Started"), 2)

    def test_unknown_style_rejected(self):
        with self.assertRaises(ValueError):
            w.OutputFormatter(style="bogus")

    def test_single_block(self):
        lines = self.render(MIXED, style="single")
        self.assertEqual(
            lines,
            [
                "CLASS: Win32_Service",
                "Name|State|ProcessId",
                "Spooler|Running|1234",
                "TermService|Running|0",  # TotalSessions dropped
                "Fax|Stopped|(null)",  # missing ProcessId filled
            ],
        )

    def test_split_classes(self):
        lines = self.render(MIXED, delimiter="##", split_classes=True)
        self.assertEqual(
            lines,
            [
                "CLASS: Win32_Service",
                "Name##State##ProcessId",
                "Spooler##Running##1234",
                "CLASS: Win32_TerminalService",
                "Name##State##ProcessId##TotalSessions",
                "TermService##Running##0##3",
                "CLASS: Win32_Service",
                "Name##State",
                "Fax##Stopped",
            ],
        )

    def test_system_properties_excluded_and_fallback_class(self):
        obj = FakeObj("", [("__PATH", S("x")), ("__CLASS", S("Win32_Foo")), ("Name", S("n"))])
        f = w.OutputFormatter(fallback_class="Win32_Bar")
        self.assertEqual(f.feed(obj.getClassName(), obj.getProperties()), ["CLASS: Win32_Bar", "Name", "n"])
        self.assertEqual(w.OutputFormatter().feed(None, ()), ["CLASS: None", "", ""])

    def test_empty_result_prints_nothing(self):
        code, out, err = run_fake("-U u%p //h 'select * from Win32_Nothing'", Fabric(objects=[]))
        self.assertEqual((code, out, err), (0, "", ""))


# ---------------------------------------------------------------------------
# End-to-end with fakes
# ---------------------------------------------------------------------------
class TestRun(unittest.TestCase):
    def test_success_path(self):
        fab = Fabric(objects=list(SERVICES))
        code, out, err = run_fake(OBSERVIUM_CMD, fab)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            out,
            "CLASS: Win32_Service\n"
            "Name##State##Started\n"
            "Spooler##Running##True\n"
            "CLASS: Win32_Service\n"
            "Name##State##Started\n"
            "Fax##Stopped##False\n",
        )
        self.assertEqual(err, "")
        # what reached "Impacket"
        self.assertEqual(fab.dcom.target, "192.0.2.10")
        self.assertEqual((fab.dcom.username, fab.dcom.password, fab.dcom.domain), ("wmi", "Secret%42", "WORKGROUP"))
        self.assertEqual(fab.dcom.kwargs["authLevel"], 6)  # PKT_PRIVACY on the activation binding
        self.assertIs(fab.dcom.kwargs["oxidResolver"], False)
        self.assertIs(fab.dcom.kwargs["doKerberos"], False)
        self.assertEqual(fab.dcom.activated, ("CLSID", "IID"))
        self.assertEqual(fab.login.namespaces, ["//./root/CIMV2"])
        self.assertEqual(fab.services.dce.auth_level, 6)
        self.assertEqual(fab.services.cinstance.auth_level, 6)
        self.assertEqual(fab.services.queries, ["SELECT Name,State FROM Win32_Service"])
        self.assertTrue(fab.login.released)
        self.assertTrue(fab.services.enum.released)
        self.assertTrue(fab.services.released)
        self.assertTrue(fab.dcom.disconnected)

    def test_auth_level_integrity(self):
        fab = Fabric(objects=list(SERVICES))
        code, out, err = run_fake("--auth-level integrity -U u%p //h 'select 1'", fab)
        self.assertEqual(code, 0)
        self.assertEqual(fab.dcom.kwargs["authLevel"], 5)
        self.assertEqual(fab.services.dce.auth_level, 5)

    def test_output_styles_end_to_end(self):
        def blocks(args, objects):
            code, out, _ = run_fake(args + " -U u%p //h 'select * from Win32_Service'", Fabric(objects=list(objects)))
            self.assertEqual(code, 0)
            return out.count("CLASS:")

        self.assertEqual(blocks("", SERVICES), 2)
        self.assertEqual(blocks("", MIXED), 3)
        self.assertEqual(blocks("--output-style single", SERVICES), 1)
        self.assertEqual(blocks("--output-style single", MIXED), 1)
        self.assertEqual(blocks("--output-style split", SERVICES), 1)
        self.assertEqual(blocks("--split-classes", MIXED), 3)

    def test_batching_returns_every_row(self):
        # Every batch size, and both server end-of-enumeration behaviours, must
        # yield all 250 rows exactly once and in order (Observium's winservices
        # module deletes any service missing from the result).
        objs = [FakeObj("Win32_Service", [("Name", S("Svc%03d" % i)), ("State", S("Running"))]) for i in range(250)]
        expected = ["Svc%03d##Running" % i for i in range(250)]
        for s_false in (S_FALSE_SHORT, S_FALSE_EMPTY):
            for bs in ("1", "7", "100", "250", "1000"):
                fab = Fabric(objects=list(objs), s_false=s_false)
                code, out, err = run_fake(
                    "--output-style single --delimiter=## --batch-size %s -U u%%p //h 'select * from Win32_Service'" % bs,
                    fab,
                )
                self.assertEqual(code, 0, err)
                data = [ln for ln in out.splitlines() if ln.startswith("Svc")]
                self.assertEqual(data, expected, "bs=%s s_false=%s" % (bs, s_false))
                self.assertEqual(fab.services.enum.max_count, int(bs))  # asked for the configured size

    def test_batching_round_trip_count(self):
        objs = [FakeObj("Win32_Service", [("Name", S("S%d" % i))]) for i in range(10)]
        fab = Fabric(objects=list(objs), s_false=S_FALSE_SHORT)
        run_fake("--batch-size 4 -U u%p //h 'select * from Win32_Service'", fab)
        # 10 objects, 4 per round trip: [4][4][2←S_FALSE] = 3 calls
        self.assertEqual(fab.services.enum.calls, 3)

    def test_empty_result_with_batching(self):
        for s_false in (S_FALSE_SHORT, S_FALSE_EMPTY):
            code, out, err = run_fake("--batch-size 100 -U u%p //h 'select * from x'", Fabric(objects=[], s_false=s_false))
            self.assertEqual((code, out, err), (0, "", ""), s_false)

    def test_undecodable_final_batch_fails_rather_than_dropping_rows(self):
        # S_FALSE whose reply Impacket could not decode: with a batch size > 1 we
        # cannot know how many objects it carried, so fail loudly.
        fab = Fabric(objects=list(SERVICES), s_false=S_FALSE_SHORT, no_packet=True)
        code, out, err = run_fake("--batch-size 100 -U u%p //h 'select * from Win32_Service'", fab)
        self.assertEqual(code, 1)
        self.assertEqual(out, "[wmic-impacket] ERROR: Retrieve result data.\n")
        self.assertIn("batch-size 1", err)
        # batch size 1 can never lose rows this way, so it degrades gracefully
        fab1 = Fabric(objects=list(SERVICES), s_false=S_FALSE_SHORT, no_packet=True)
        code, out, err = run_fake("--batch-size 1 -U u%p //h 'select * from Win32_Service'", fab1)
        self.assertEqual(code, 0, err)

    def assert_login_error(self, fab, ntstatus, detail_fragment):
        code, out, err = run_fake("-U wmi%pw -W WORKGROUP //192.0.2.10 'select * from Win32_BIOS'", fab)
        self.assertEqual(code, 1)
        self.assertEqual(out, "[wmic-impacket] ERROR: Login to remote object.\n")
        self.assertIn("NTSTATUS: %s - " % ntstatus, err.splitlines()[0])
        self.assertIn(detail_fragment, err)
        return err

    def test_error_connect_refused(self):
        fab = Fabric(fail_at="connect")
        self.assert_login_error(fab, "NT_STATUS_CONNECTION_REFUSED", "Connection refused")
        # DCOMConnection() itself raised, so there is no object to disconnect
        self.assertFalse(fab.dcom.disconnected)

    def test_error_bad_credentials(self):
        self.assert_login_error(Fabric(fail_at="logon"), "NT_STATUS_LOGON_FAILURE", "rpc_s_access_denied")

    def test_error_activation_denied(self):
        fab = Fabric(fail_at="activate")
        err = self.assert_login_error(fab, "NT_STATUS_ACCESS_DENIED", "0x80070005")
        self.assertIn("event 10036", err)
        self.assertTrue(fab.dcom.disconnected)

    def test_error_namespace_login_denied(self):
        fab = Fabric(fail_at="login")
        self.assert_login_error(fab, "NT_STATUS_ACCESS_DENIED", "WBEM_E_ACCESS_DENIED")
        self.assertTrue(fab.dcom.disconnected)

    def test_error_on_execquery(self):
        fab = Fabric(fail_at="query")
        code, out, err = run_fake("-U u%p //h 'select * from Nope'", fab)
        self.assertEqual(code, 1)
        self.assertEqual(out, "[wmic-impacket] ERROR: Retrieve result data.\n")
        self.assertIn("NTSTATUS: NT_STATUS_UNSUCCESSFUL - WBEM_E_INVALID_QUERY (0x80041017)", err)
        self.assertTrue(fab.dcom.disconnected)

    def test_error_on_next(self):
        fab = Fabric(objects=list(SERVICES), fail_at="next")
        code, out, err = run_fake("-U u%p //h 'select * from Win32_Nope'", fab)
        self.assertEqual(code, 1)
        self.assertEqual(out, "[wmic-impacket] ERROR: Retrieve result data.\n")
        self.assertIn("WBEM_E_INVALID_CLASS (0x80041010)", err)
        self.assertTrue(fab.services.enum.released)
        self.assertTrue(fab.dcom.disconnected)

    def test_error_on_next_after_some_rows_still_flags_error(self):
        # One object per round trip: first Next succeeds, second raises mid-stream.
        fab = Fabric(objects=list(SERVICES), fail_after=1)
        code, out, err = run_fake("--batch-size 1 -U u%p //h 'select * from Win32_Service'", fab)
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("CLASS: Win32_Service\n"))
        self.assertTrue(out.endswith("[wmic-impacket] ERROR: Retrieve result data.\n"))

    def test_disconnect_called_on_every_path(self):
        for fail_at in (None, "activate", "login", "query", "next"):
            fab = Fabric(objects=list(SERVICES), fail_at=fail_at)
            run_fake("-U u%p //h 'select * from Win32_Service'", fab)
            self.assertTrue(fab.dcom.disconnected, "disconnect() not called when failing at %r" % fail_at)

    def test_debug_output_goes_to_stderr_only(self):
        fab = Fabric(objects=list(SERVICES))
        code, out, err = run_fake("-d2 -U u%p //h 'select * from Win32_Service'", fab)
        self.assertEqual(code, 0)
        self.assertEqual(out.count("\n"), 6)  # 2 objects x (CLASS, header, row)
        self.assertNotIn("DEBUG", out)
        self.assertIn("DEBUG wmic_impacket: connecting to h", err)
        # level 0: silent
        code, out, err = run_fake("-U u%p //h 'select * from Win32_Service'", fab.__class__(objects=list(SERVICES)))
        self.assertEqual(err, "")
        # traceback on error when debugging
        code, out, err = run_fake("-d1 -U u%p //h 'select * from Win32_Service'", Fabric(fail_at="login"))
        self.assertIn("Traceback", err)

    def test_stray_prints_from_impacket_do_not_reach_stdout(self):
        fab = Fabric(objects=list(SERVICES), noisy=True)
        code, out, err = run_fake("-U u%p //h 'select * from Win32_Service'", fab)
        self.assertEqual(code, 0)
        self.assertNotIn("stray print", out)
        self.assertIn("stray print from inside impacket", err)
        self.assertIs(sys.stdout, sys.__stdout__)

    def test_version(self):
        code, out, err = run_fake("-V", Fabric())
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("Version 4.0.0tp4-SVN-build-UNKNOWN (wmic-impacket %s, impacket " % w.__version__), out)

    def test_usage_error_is_visible_to_observium(self):
        code, out, err = run_fake("--user=wmi //host", Fabric())
        self.assertEqual(code, 1)
        self.assertIn("ERROR:", out)
        self.assertIn("usage:", err)

    def test_empty_host_is_a_login_error(self):
        # A caller that built "//$hostname" from an empty variable.
        fab = Fabric()
        code, out, err = run_fake(
            "--user='' --no-pass --delimiter=## --namespace='root\\CIMV2' // 'SELECT Name FROM Win32_ComputerSystem'",
            fab,
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "[wmic-impacket] ERROR: Login to remote object.\n")
        self.assertIn("NTSTATUS: NT_STATUS_BAD_NETWORK_NAME", err)
        self.assertIn("empty host name", err)
        self.assertIsNone(fab.dcom, "must not try to connect anywhere")

    def test_help(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = w.run(["--help"], io.StringIO(), io.StringIO())
        self.assertEqual(code, 0)
        self.assertIn("--auth-level", buf.getvalue())
        self.assertIn("--split-classes", buf.getvalue())
        self.assertIn("--output-style", buf.getvalue())

    @unittest.skipUnless(hasattr(w.signal, "SIGALRM"), "SIGALRM not available")
    def test_watchdog_timeout(self):
        fab = Fabric(objects=list(SERVICES), sleep=5)
        started = time.monotonic()
        code, out, err = run_fake("--timeout 0.5 -U u%p //h 'select * from Win32_Service'", fab)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3)
        self.assertEqual(code, 1)
        self.assertEqual(out, "[wmic-impacket] ERROR: Login to remote object.\n")
        self.assertIn("NTSTATUS: NT_STATUS_IO_TIMEOUT", err)
        self.assertTrue(fab.dcom.disconnected)
        # the alarm must be disarmed again
        self.assertEqual(w.signal.getitimer(w.signal.ITIMER_REAL), (0.0, 0.0))

    def test_main_uses_os_exit(self):
        with mock.patch.object(w.os, "_exit") as fake_exit, contextlib.redirect_stdout(io.StringIO()):
            w.main(["-V"])
        fake_exit.assert_called_once_with(0)
        with mock.patch.object(w.os, "_exit") as fake_exit, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            w.main(["//h"])
        fake_exit.assert_called_once_with(1)


class TestClassify(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(w.classify_exception(w.WatchdogTimeout("x"))[0], "NT_STATUS_IO_TIMEOUT")
        self.assertEqual(w.classify_exception(w.socket.timeout("timed out"))[0], "NT_STATUS_IO_TIMEOUT")
        self.assertEqual(w.classify_exception(Exception("Could not connect: [Errno 111] Connection refused"))[0], "NT_STATUS_CONNECTION_REFUSED")
        self.assertEqual(w.classify_exception(OSError(w.errno.ECONNREFUSED, "x"))[0], "NT_STATUS_CONNECTION_REFUSED")
        self.assertEqual(w.classify_exception(OSError(w.errno.EHOSTUNREACH, "x"))[0], "NT_STATUS_HOST_UNREACHABLE")
        self.assertEqual(w.classify_exception(w.socket.gaierror(-2, "Name or service not known"))[0], "NT_STATUS_BAD_NETWORK_NAME")
        self.assertEqual(w.classify_exception(FakeSessionError(0x5, "DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied "))[0], "NT_STATUS_LOGON_FAILURE")
        self.assertEqual(w.classify_exception(FakeSessionError(0x80070005))[0], "NT_STATUS_ACCESS_DENIED")
        self.assertEqual(w.classify_exception(FakeSessionError(0x80041003))[0], "NT_STATUS_ACCESS_DENIED")
        status, friendly = w.classify_exception(FakeSessionError(0x80041010))
        self.assertEqual(status, "NT_STATUS_UNSUCCESSFUL")
        self.assertIn("WBEM_E_INVALID_CLASS", friendly)
        self.assertEqual(w.classify_exception(RuntimeError("boom"))[0], "NT_STATUS_UNSUCCESSFUL")


# ---------------------------------------------------------------------------
# Real Impacket decoding of a WMI object (no network): the sample instance that
# ships inside impacket/dcerpc/v5/dcom/wmi.py.  Verifies our type handling
# against genuine Impacket property dictionaries (Inherited flag on Id, array
# flag on Array, NULL string in Data2).
# ---------------------------------------------------------------------------
SAMPLE_INSTANCE = (
    b"xV4\x12\xd3\x01\x00\x00\x06\x00DPRAVAT-DEV\x00\x00ROOT\x00v\x01\x00\x00\x00\x00\x00\x00"
    b"\x00\x11\x00\x00\x00\x0e\x00\x00\x00\x00Base\x00\x06\x00\x00\x00\x11\x00\x00\x00\t\x00\x00"
    b"\x00\x00\x08\x00\x00\x00\x16\x00\x00\x00\x04\x00\x00\x00'\x00\x00\x00.\x00\x00\x00U\x00\x00"
    b"\x00\\\x00\x00\x00\x99\x00\x00\x00\xa0\x00\x00\x00\xc7\x00\x00\x00\xcb\x00\x00\x00G\xff\xff"
    b"\xff\xff\xff\xff\xff\xff\xfd\x00\x00\x00\xff\xff\xff\xff\x11\x01\x00\x80\x00MyClass\x00\x00"
    b"Description\x00\x00MyClass Example\x00\x00Array\x00\x13 \x00\x00\x03\x00\x0c\x00\x00\x00"
    b"\x01\x00\x00\x00\x11\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00M\x00\x00\x00\x00uint3"
    b"2\x00\x00Data1\x00\x08\x00\x00\x00\x01\x00\x04\x00\x00\x00\x01\x00\x00\x00'\x00\x00\x00\n"
    b"\x00\x00\x80\x03\x08\x00\x00\x00\x91\x00\x00\x00\x03\x00\x00\x80\x00\x0b\x00\x00\x00\xff"
    b"\xff\x04\x00\x00\x80\x00\x0b\x00\x00\x00\xff\xff\x00string\x00\x00Data2\x00\x08\x00\x00\x00"
    b"\x02\x00\x08\x00\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00"
    b"\xbf\x00\x00\x00\x00string\x00\x00Id\x00\x03@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xf5\x00\x00\x00\x01\x00\x00\x803\x0b"
    b"\x00\x00\x00\xff\xff\x00sint32\x00\x00defaultValue\x00\x00\x00\x00\x00\x00\x00I\x00\x00\x00"
    b"\x00\x00\x00\x00\x00 {\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x04\x00"
    b"\x00\x00\x01&\x00\x00\x80\x00MyClass\x00\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00"
    b"\x03\x00\x00\x00\x00StringField\x00"
)


def _have_impacket():
    try:
        import importlib.util

        return importlib.util.find_spec("impacket.dcerpc.v5.dcom.wmi") is not None
    except Exception:
        return False


@unittest.skipUnless(_have_impacket(), "impacket not installed")
class TestRealImpacketDecoding(unittest.TestCase):
    def decode(self):
        from impacket.dcerpc.v5.dcom import wmi

        unit = wmi.ENCODING_UNIT(SAMPLE_INSTANCE)
        block = unit["ObjectBlock"]
        block.parseObject()
        # Same expressions IWbemClassObject.getClassName()/getProperties() use.
        class_name = block["InstanceType"]["CurrentClass"].getClassName().split(" ")[0]
        return class_name, block.ctCurrent["properties"]

    def test_sample_instance(self):
        class_name, props = self.decode()
        self.assertEqual(class_name, "MyClass")
        self.assertEqual(list(props), ["Id", "Data1", "Data2", "Array"])
        self.assertTrue(props["Id"]["type"] & w.CIM_INHERITED_FLAG)
        self.assertTrue(props["Array"]["type"] & w.CIM_ARRAY_FLAG)
        lines = w.OutputFormatter().feed(class_name, props)
        self.assertEqual(lines, ["CLASS: MyClass", "Id|Data1|Data2|Array", "123|StringField|(null)|(1,2,3)"])

    def test_load_impacket_namespace(self):
        imp = w.load_impacket()
        self.assertTrue(callable(imp.DCOMConnection))
        self.assertEqual(imp.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, 5)
        self.assertEqual(imp.RPC_C_AUTHN_LEVEL_PKT_PRIVACY, 6)
        self.assertTrue(hasattr(imp.wmi, "IWbemLevel1Login"))
        self.assertNotEqual(w.impacket_version(), "unknown")

    def test_real_s_false_detection(self):
        from impacket.dcerpc.v5.dcom import wmi

        self.assertTrue(w._is_s_false(wmi.DCERPCSessionError(error_code=1)))
        self.assertFalse(w._is_s_false(wmi.DCERPCSessionError(error_code=0x80041010)))

    def _objref_bytes(self):
        from impacket.dcerpc.v5.dcom import wmi
        from impacket.dcerpc.v5 import dcomrt

        objref = dcomrt.OBJREF_CUSTOM()
        objref["iid"] = wmi.IID_IWbemClassObject
        objref["clsid"] = b"\x00" * 16
        objref["cbExtension"] = 0
        objref["ObjectReferenceSize"] = len(SAMPLE_INSTANCE)
        objref["pObjectData"] = SAMPLE_INSTANCE
        return objref.getData()

    def test_final_batch_rebuilds_objects_from_exception_packet(self):
        """The novel part of batching: when the enumeration ends with WBEM_S_FALSE
        carrying objects, recover them from the exception's packet and decode them
        with real Impacket, exactly as IEnumWbemClassObject.Next() decodes a
        normal reply."""
        from impacket.dcerpc.v5.dcom import wmi
        from impacket.dcerpc.v5 import dcomrt

        raw = self._objref_bytes()
        # 'abData' as the NDR layer yields it to IEnumWbemClassObject.Next():
        # an iterable of single bytes that b''.join() concatenates back to 'raw'.
        ab = [raw[i:i + 1] for i in range(len(raw))]

        class Packet:
            def __init__(self, items, returned):
                self._d = {"apObjects": items, "puReturned": returned}

            def __getitem__(self, key):
                return self._d[key]

        exc = wmi.DCERPCSessionError(error_code=1)
        exc.packet = Packet([{"abData": ab}, {"abData": ab}], 2)

        class StubEnum:
            def get_cinstance(self):
                return dcomrt.CLASS_INSTANCE(None, None)

            def get_ipidRemUnknown(self):
                return None

            def get_oxid(self):
                return None

            def get_target(self):
                return "192.0.2.10"

        imp = w.load_impacket()
        objs = w._final_batch(exc, StubEnum(), None, imp)
        self.assertEqual(len(objs), 2)
        for obj in objs:
            self.assertEqual(obj.getClassName(), "MyClass")
            self.assertEqual(list(obj.getProperties()), ["Id", "Data1", "Data2", "Array"])

    def test_final_batch_count_mismatch_raises(self):
        from impacket.dcerpc.v5.dcom import wmi

        class Packet:
            def __getitem__(self, key):
                return {"apObjects": [{"abData": [b"x"]}], "puReturned": 5}[key]

        exc = wmi.DCERPCSessionError(error_code=1)
        exc.packet = Packet()
        with self.assertRaises(w.BatchDecodeError):
            w._final_batch(exc, None, None, w.load_impacket())

    def test_final_batch_without_packet_returns_none(self):
        from impacket.dcerpc.v5.dcom import wmi

        self.assertIsNone(w._final_batch(wmi.DCERPCSessionError(error_code=1), None, None, w.load_impacket()))


# ---------------------------------------------------------------------------
# Observium compatibility: feed our output through the real wmi_parse()
# ---------------------------------------------------------------------------
@unittest.skipUnless(PHP, "php not installed")
class TestObserviumOldParser(unittest.TestCase):
    """The older wmi_parse() (tests/observium_wmi_parse.php) needs --output-style single."""

    SINGLE = "--output-style single "

    def php(self, text, delimiter="##", ret_single=False, ret_val=""):
        proc = subprocess.run(
            [PHP, "-d", "display_errors=stderr", "-d", "error_reporting=E_ALL", PHP_SCRIPT, delimiter, "1" if ret_single else "0", ret_val],
            input=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60,
        )
        return proc

    def parse(self, text, **kwargs):
        proc = self.php(text, **kwargs)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")
        return json.loads(proc.stdout)

    def test_services(self):
        _, out, _ = run_fake(self.SINGLE + OBSERVIUM_CMD, Fabric(objects=list(SERVICES)))
        self.assertEqual(
            self.parse(out),
            [
                {"Name": "Spooler", "State": "Running", "Started": "True"},
                {"Name": "Fax", "State": "Stopped", "Started": "False"},
            ],
        )

    def test_null_and_pipe_delimiter(self):
        objs = [FakeObj("Win32_OperatingSystem", [("Caption", S("Microsoft Windows 11 Pro")), ("Organization", S(None)), ("Umlaut", S("Zürich"))])]
        _, out, _ = run_fake("--delimiter '|' -U u%p //h 'select * from Win32_OperatingSystem'", Fabric(objects=objs))
        self.assertEqual(self.parse(out, delimiter="|"), [{"Caption": "Microsoft Windows 11 Pro", "Organization": "", "Umlaut": "Zürich"}])
        # ret_single / ret_val as Observium uses them for single-row classes
        self.assertEqual(self.parse(out, delimiter="|", ret_single=True), {"Caption": "Microsoft Windows 11 Pro", "Organization": "", "Umlaut": "Zürich"})
        self.assertEqual(self.parse(out, delimiter="|", ret_single=True, ret_val="Caption"), "Microsoft Windows 11 Pro")

    def test_mixed_classes_single_block_parses(self):
        _, out, _ = run_fake(self.SINGLE + "--delimiter=## -U u%p //h 'select * from Win32_Service'", Fabric(objects=list(MIXED)))
        self.assertEqual(
            self.parse(out),
            [
                {"Name": "Spooler", "State": "Running", "ProcessId": "1234"},
                {"Name": "TermService", "State": "Running", "ProcessId": "0"},
                {"Name": "Fax", "State": "Stopped", "ProcessId": ""},
            ],
        )

    def test_mixed_classes_split_breaks_old_parser(self):
        """Documents OBS-4409: the original per-class output makes the old wmi_parse()
        treat 'CLASS: ...' as a data row, which on PHP 8 is a fatal array_combine()."""
        _, out, _ = run_fake("--split-classes --delimiter=## -U u%p //h 'select * from Win32_Service'", Fabric(objects=list(MIXED)))
        proc = self.php(out)
        broken = proc.returncode != 0 or proc.stderr != ""
        if not broken:
            broken = json.loads(proc.stdout) != [
                {"Name": "Spooler", "State": "Running", "ProcessId": "1234"},
                {"Name": "TermService", "State": "Running", "ProcessId": "0", "TotalSessions": "3"},
                {"Name": "Fax", "State": "Stopped"},
            ]
        self.assertTrue(broken, "expected the old parser to choke on per-class blocks")

    def test_error_output_is_recognised(self):
        _, out, _ = run_fake("-U u%p //h 'select * from x'", Fabric(fail_at="login"))
        self.assertIsNone(self.parse(out))
        _, out, _ = run_fake("-U u%p //h 'select * from x'", Fabric(fail_at="query"))
        self.assertIsNone(self.parse(out))

    def test_empty_result(self):
        _, out, _ = run_fake("-U u%p //h 'select * from x'", Fabric(objects=[]))
        self.assertEqual(self.parse(out), [])


OBSERVIUM_DIR = os.environ.get("OBSERVIUM_DIR", "")
CURRENT_PHP_SCRIPT = os.path.join(HERE, "observium_current_parse.php")


@unittest.skipUnless(
    PHP and OBSERVIUM_DIR and os.path.isfile(os.path.join(OBSERVIUM_DIR, "includes", "wmi.inc.php")),
    "set OBSERVIUM_DIR to an Observium install (and install php) to test against its own wmi_parse()",
)
class TestObserviumInstalledParser(unittest.TestCase):
    """Runs the wmi_parse() of the Observium install in $OBSERVIUM_DIR, e.g.
    OBSERVIUM_DIR=/opt/observium python -m unittest discover -s tests"""

    def parse(self, text, ret_single=False):
        proc = subprocess.run(
            [PHP, "-d", "display_errors=stderr", "-d", "error_reporting=E_ALL", CURRENT_PHP_SCRIPT, "##", "1" if ret_single else "0"],
            input=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60,
            env=dict(os.environ, OBSERVIUM_DIR=OBSERVIUM_DIR),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout), proc.stderr

    def test_default_style_keeps_every_row(self):
        _, out, _ = run_fake(OBSERVIUM_CMD, Fabric(objects=list(SERVICES)))
        rows, err = self.parse(out)
        self.assertEqual(err, "")
        self.assertEqual(
            rows,
            [
                {"Name": "Spooler", "State": "Running", "Started": "True"},
                {"Name": "Fax", "State": "Stopped", "Started": "False"},
            ],
        )

    def test_default_style_mixed_classes(self):
        _, out, _ = run_fake("--delimiter=## -U u%p //h 'select * from Win32_Service'", Fabric(objects=list(MIXED)))
        rows, err = self.parse(out)
        self.assertEqual(err, "")
        self.assertEqual(
            rows,
            [
                {"Name": "Spooler", "State": "Running", "ProcessId": "1234"},
                {"Name": "TermService", "State": "Running", "ProcessId": "0", "TotalSessions": "3"},
                {"Name": "Fax", "State": "Stopped"},
            ],
        )

    def test_single_row_ret_single(self):
        objs = [FakeObj("Win32_ComputerSystem", [("Name", S("WINHOST"))])]
        _, out, _ = run_fake(OBSERVIUM_CMD, Fabric(objects=objs))
        rows, _ = self.parse(out, ret_single=True)
        self.assertEqual(rows, {"Name": "WINHOST"})

    def test_errors_give_null(self):
        for fail_at in ("login", "query"):
            _, out, _ = run_fake(OBSERVIUM_CMD, Fabric(fail_at=fail_at))
            rows, _ = self.parse(out)
            self.assertIsNone(rows, fail_at)

    def test_single_style_loses_rows_on_current_parser(self):
        """Documents why per-object is the default: a parser that resets after
        each row keeps only the first row of a single-block result."""
        _, out, _ = run_fake("--output-style single " + OBSERVIUM_CMD, Fabric(objects=list(SERVICES)))
        rows, _ = self.parse(out)
        if len(rows) == 2:
            self.skipTest("this Observium's wmi_parse() handles single blocks; --output-style single is fine here")
        self.assertEqual(rows, [{"Name": "Spooler", "State": "Running", "Started": "True"}])


if __name__ == "__main__":
    unittest.main()
