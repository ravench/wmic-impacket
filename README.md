# wmic-impacket

A drop-in replacement for the old Samba-based Linux `wmic` binary
(`Version 4.0.0tp4-SVN-build-UNKNOWN`, wmi-1.3.x), written in Python on top of
[Impacket](https://github.com/fortra/impacket). Same command line, same output
format, so [Observium](https://www.observium.org/) (and anything else that shells
out to `wmic`) keeps polling Windows hosts over WMI.

## Why

Microsoft's DCOM hardening (KB5004442, CVE-2021-26414) has been enforced since
March 2023. Windows now refuses DCOM activation requests below
`RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. With the old `wmic` the Security log shows a
successful NTLM logon (event 4624), immediately followed by System event **10036**:

> The server-side authentication level policy does not allow the user
> HOST\user ... to activate DCOM server. Please raise the activation
> authentication level at least to RPC_C_AUTHN_LEVEL_PKT_INTEGRITY in client
> application.

The 2008-vintage Samba WMI client cannot do packet integrity; Impacket can.
wmic-impacket runs both the DCOM activation (`IRemoteSCMActivator`) and the
`IWbemServices` calls at `PKT_PRIVACY` (default) or `PKT_INTEGRITY`.

## Install

### Dependencies

System packages:

| Package | Why |
| --- | --- |
| `python3` (3.8 or newer) | runtime |
| `python3-venv` | Debian ships the `venv`/`ensurepip` modules separately |
| `git` | `pip install git+https://...` clones the repository |

Python packages, installed by pip into the venv (nothing system-wide):

* `impacket` >= 0.12.0, which in turn pulls in `pyasn1`, `pyasn1_modules`,
  `pycryptodomex`, `pyOpenSSL` / `cryptography`, `six`, `charset_normalizer`,
  `ldap3`, `ldapdomaindump` and `flask` (the last three are Impacket
  dependencies that wmic-impacket never uses).

### Debian / Ubuntu

Debian 11 (bullseye) or newer, Ubuntu 20.04 or newer. Debian 10 ships Python 3.7,
which is too old.

```sh
sudo apt update
sudo apt install python3 python3-venv git

sudo python3 -m venv /opt/wmic-impacket
sudo /opt/wmic-impacket/bin/pip install --upgrade pip
sudo /opt/wmic-impacket/bin/pip install git+https://github.com/ravench/wmic-impacket

/opt/wmic-impacket/bin/wmic --version
```

Upgrading pip first matters on older releases: the pip bundled with Debian 11 may
not recognise the current prebuilt wheels for `cryptography`, `cffi` and
`pycryptodomex` and would try to compile them from source. Prebuilt wheels exist
for amd64 and arm64. On other architectures (i386, armhf) pip has to compile,
which needs `sudo apt install build-essential python3-dev libffi-dev libssl-dev`
plus a Rust toolchain for `cryptography`.

To update later, run the last `pip install` again with `--upgrade`.

## Observium configuration

In `config.php`:

```php
$config['wmic'] = '/opt/wmic-impacket/bin/wmic';
```

Extra flags can be appended, Observium concatenates the string into the command:

```php
$config['wmic'] = '/opt/wmic-impacket/bin/wmic --timeout 20 --auth-level integrity';
```

Alternatively replace the system binary and keep the original around:

```sh
mv /usr/bin/wmic /usr/bin/wmic.orig
ln -s /opt/wmic-impacket/bin/wmic /usr/bin/wmic
```

Device-side settings (WMI hostname like `ncacn_ip_tcp:host.domain.local[sign]`,
user, password, domain) need no change; those spellings are understood.

Observium releases whose `wmi_parse()` was written for the original wmic need
`--output-style single` appended to `$config['wmic']`; see
[Output style](#output-style).

### Observium's bundled `scripts/wmic`

Recent Observium releases ship their own Impacket-based client,
`scripts/wmic` (a copy of py-wmi-client). Observium switches to it
automatically only when `$config['wmic']` is left at its default `/bin/wmic` and
that file does not exist; it then needs Impacket importable by the system
`python3` to actually work. If that works for you, you may not need this
project. Differences, as of the copy reviewed:

| | bundled `scripts/wmic` | wmic-impacket |
| --- | --- | --- |
| Install | Impacket for the system `python3` (on Debian 12+ pip refuses system-wide installs, PEP 668) | own venv |
| NULL values | printed as `None` (or `0` for uint32/uint64) | `(null)`, which Observium turns into an empty string |
| Errors | Python traceback on stderr, nothing on stdout | wmic-style `ERROR:` line on stdout, NTSTATUS and cause on stderr |
| Hung host | no time limit | `--timeout`, default 30 s |
| Command line | `-U`, `-A`, `--delimiter`, `--namespace` only | full Samba wmic option set |
| Older Observium parsers | per-object layout only | `--output-style single` |

## Quick manual test

```sh
/opt/wmic-impacket/bin/wmic -U 'wmi%secret' -W WORKGROUP --delimiter='##' \
    --namespace='root\CIMV2' //192.0.2.10 "SELECT Caption,Version FROM Win32_OperatingSystem"
```

Expected:

```
CLASS: Win32_OperatingSystem
Caption##Version
Microsoft Windows 11 Pro##10.0.26100
```

Add `-d1` to see Impacket's debug output on stderr.

## Windows-side setup

The polled account needs: membership in *Distributed COM Users* and *Performance
Monitor Users*, *Enable Account* + *Remote Enable* on the WMI namespace, the
*Windows Management Instrumentation (WMI)* firewall rule group, and, for
`Win32_Service` (Observium's service list), remote list access to the Service
Control Manager, which Windows grants only to administrators by default. The script
[`windows/Grant-WmiAccess.ps1`](windows/Grant-WmiAccess.ps1) does all of that
idempotently; run it in an elevated **Windows PowerShell 5.1** on the target:

```powershell
New-LocalUser -Name wmi -Password (Read-Host -AsSecureString) -PasswordNeverExpires -UserMayNotChangePassword
powershell.exe -ExecutionPolicy Bypass -File .\Grant-WmiAccess.ps1 -User wmi -RemoteAddress 192.0.2.5
```

`-Namespace` defaults to `root\cimv2`; `-RemoteAddress` scopes the inbound firewall
rules to your monitoring host (omit it to leave the scope untouched, `Any` to reset).
The Service Control Manager step adds `(A;;CCLCRPRC;;;<user SID>)` (connect,
enumerate, query lock status, read control) and prints the previous descriptor
for `sc.exe sdset scmanager "<old SDDL>"`; `-SkipServiceManager` leaves it alone.
`-WhatIf` shows what would change.

## Options

Positional: `//HOST` (also `HOST`, `//ncacn_ip_tcp:HOST[sign]`, `//[IPv6]`) and the WQL query.

| Option | Meaning |
| --- | --- |
| `-U, --user USER` | `user`, `DOMAIN\user`, `DOMAIN/user`, `user@domain`, optionally `%password` appended |
| `--password PW` | password (overrides `%password`) |
| `-N, --no-pass` | no password |
| `-W, --workgroup DOMAIN` | domain / workgroup (a domain inside `-U` wins) |
| `-A, --authentication-file FILE` | Samba credentials file: `username = `, `password = `, `domain = ` |
| `--namespace NS` | WMI namespace, default `root\cimv2`; converted to Impacket's `//./root/cimv2` |
| `--delimiter STR` | column delimiter, default `\|` |
| `-d, --debuglevel N` | `-d1`/`-d2`: debug output on **stderr** (Impacket logger at DEBUG) |
| `-V, --version` | `Version 4.0.0tp4-SVN-build-UNKNOWN (wmic-impacket X, impacket Y)` |
| `--auth-level {integrity,privacy}` | RPC authentication level for activation and WMI calls; default `privacy`, or `$WMIC_IMPACKET_AUTH_LEVEL` |
| `--timeout SECONDS` | hard limit for the whole run (SIGALRM watchdog); default 30, or `$WMIC_IMPACKET_TIMEOUT`; `0` disables |
| `--output-style {per-object,single,split}` | how rows are grouped into `CLASS:`/header blocks, see [Output compatibility](#output-compatibility); default `per-object`, or `$WMIC_IMPACKET_OUTPUT_STYLE` |
| `--split-classes` | same as `--output-style split` |
| `--option=name=value`, `-O`, `-s`, `-l`, `-R`, `-m`, `-n`, `-S`, `-k`, `--realm`, `-i`, `-P`, `--simple-bind-dn`, ... | Samba popt options, accepted and ignored |

Kerberos, pass-the-hash and `ncacn_np` transports are not implemented; NTLM over
`ncacn_ip_tcp` (port 135 plus a dynamic port) is what Observium needs.

## Output compatibility

Format of the original `wmic`:

```
CLASS: Win32_Service
Name|State|Started
Spooler|Running|True
```

* integers decimal, booleans `True`/`False`, reals `%f` (`1.500000`), strings /
  datetimes / references raw, NULL string `(null)` (Observium strips it), arrays
  `(a,b,c)`, NULL array `NULL`, `char16` and embedded objects `Unsupported`.
* system properties (`__PATH`, `__CLASS`, ...) are not printed.
* no rows: no output, exit code 0.
* errors: `[wmic-impacket] ERROR: Login to remote object.` or
  `[wmic-impacket] ERROR: Retrieve result data.` on **stdout** (Observium's
  `wmi_parse()` looks for `ERROR:` there), an `NTSTATUS: NT_STATUS_... - text`
  line plus the Impacket exception on stderr, exit code 1.

### Output style

Observium's `wmi_parse()` has changed over the years, and the two generations
need different layouts for multi-row results (CPUs, disks, services, MSSQL
instances):

| `--output-style` | Layout | Use with |
| --- | --- | --- |
| `per-object` (default) | `CLASS:` line and header before **every** row | Current Observium releases. Their parser resets after each row (it was written for the Impacket-based `scripts/wmic` Observium now bundles), so with any other layout only the first row survives. |
| `single` | one `CLASS:` line and header, then all rows; the header comes from the first row, missing properties become `(null)`, extra ones are dropped | Older Observium releases, whose parser treats every line after the header as a data row and dies in `array_combine()` on PHP 8 when it meets a second `CLASS:` line (OBS-4409). |
| `split` | a new block whenever the class changes, e.g. a `Win32_TerminalService` row in `SELECT ... FROM Win32_Service` | Exactly what the original Samba `wmic` printed. |

Not sure which one your Observium has? Check `includes/wmi.inc.php`: if
`wmi_parse()` sets `$wmi_class = NULL` again after storing a row, keep the
default; otherwise append `--output-style single` to `$config['wmic']`. A
single-row test such as `SELECT Name FROM Win32_ComputerSystem` works with every
style, so it does not tell them apart.

### Other deliberate deviations

1. **CR/LF inside values become a space.** Some `Description` fields contain line
   breaks, which break every line-based parser.
2. A NULL of any scalar type prints as `(null)`, not just NULL strings.

## Troubleshooting

| Symptom | Meaning |
| --- | --- |
| `ERROR: Login to remote object.` + `NT_STATUS_CONNECTION_REFUSED` / `NT_STATUS_IO_TIMEOUT` / `NT_STATUS_HOST_UNREACHABLE` / `NT_STATUS_BAD_NETWORK_NAME` | Host down, port 135 or the dynamic RPC port filtered, name does not resolve. Check the firewall rule group on the Windows side. |
| `Login to remote object.` + `NT_STATUS_LOGON_FAILURE` (`rpc_s_access_denied`) | Wrong user name / password / domain. Windows Security log: event **4625**. |
| `Login to remote object.` + `NT_STATUS_ACCESS_DENIED` with `0x80070005` | NTLM logon fine (event **4624**) but DCOM activation denied: user not in *Distributed COM Users*, or auth level too low (System event **10036**, should no longer happen with this tool). |
| `Login to remote object.` + `NT_STATUS_ACCESS_DENIED` with `WBEM_E_ACCESS_DENIED` (`0x80041003`) | DCOM fine, but no *Enable Account* / *Remote Enable* on the namespace. |
| `Login to remote object.` + `WBEM_E_INVALID_NAMESPACE` | `--namespace` typo. |
| `ERROR: Retrieve result data.` + `WBEM_E_INVALID_CLASS` / `WBEM_E_INVALID_QUERY` | Class does not exist on that host / WQL syntax error. |
| `ERROR: Retrieve result data.` + `WBEM_E_ACCESS_DENIED`, only for `Win32_Service` | Non-admin user without remote access to the Service Control Manager. Run `Grant-WmiAccess.ps1` (step 4) on the target. |
| `Login to remote object.` + `NT_STATUS_IO_TIMEOUT` after `--timeout` seconds | Packets are dropped, usually by the Windows firewall (WMI rule group disabled, or the network is in the *Public* profile). A rejected connection gives `NT_STATUS_CONNECTION_REFUSED` instead. |
| `Login to remote object.` + `NT_STATUS_BAD_NETWORK_NAME`, stderr says `empty host name in '//'` | The caller passed `//` with no host name after it. |
| Observium's device WMI page says "The wmic binary (or script) was not found at the configured path", although the path is right | Observium prints that for *any* failure of its `wmi_cmd()`, including an empty WMI username (wmic is then never run). With *Override WMI Config* ticked, fill in at least the username (a blank hostname falls back to the device hostname); otherwise untick it and set `$config['wmi']['user']` / `['pass']` / `['domain']` globally. |
| Observium only shows the first CPU / disk / service | The output style does not match your Observium's parser. Current releases need the default `per-object`; releases whose `wmi_parse()` does not reset after each row need `--output-style single` (append it to `$config['wmic']`). |
| Observium shows the device as having no WMI data | Run the exact command from `includes/wmi.inc.php` by hand with `-d1`. |

Impacket is also a well-known penetration-testing toolkit. Its DCOM/WMI traffic
is byte-for-byte what `wmiexec.py`/`wmiquery.py` send, so EDR or IDS products may
flag the monitoring host. Whitelist it.

Each call starts a Python interpreter, imports Impacket and performs a full DCOM
handshake (portmapper, activation, NTLM, namespace login, enumeration, one round
trip per returned instance). That is a few hundred milliseconds of overhead on a
desktop and noticeably more on a small low-power box; the old
static binary was faster. Keep `--timeout` comfortably above your slowest query.

## Development

```sh
sudo apt install python3 python3-venv git php-cli   # php-cli only for the Observium compatibility test
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The tests run offline against fakes of the Impacket objects, decode a genuine
Impacket-encoded WMI instance, and pipe generated output through Observium's
older `wmi_parse()` (`tests/observium_wmi_parse.php`; skipped if `php` is not on
the PATH).

To check the output against the parser of the Observium you actually run, point
`OBSERVIUM_DIR` at the install; `tests/observium_current_parse.php` loads its
`includes/wmi.inc.php` at run time (nothing from it is copied into this repo):

```sh
OBSERVIUM_DIR=/opt/observium .venv/bin/python -m unittest discover -s tests -v
```

## License

MIT, see [LICENSE](LICENSE).
