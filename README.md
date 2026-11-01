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
Monitor Users*, *Enable Account* + *Remote Enable* on the WMI namespace, and the
*Windows Management Instrumentation (WMI)* firewall rule group. The script
[`windows/Grant-WmiAccess.ps1`](windows/Grant-WmiAccess.ps1) does all of that
idempotently; run it in an elevated **Windows PowerShell 5.1** on the target:

```powershell
New-LocalUser -Name wmi -Password (Read-Host -AsSecureString) -PasswordNeverExpires -UserMayNotChangePassword
powershell.exe -ExecutionPolicy Bypass -File .\Grant-WmiAccess.ps1 -User wmi -RemoteAddress 192.0.2.5
```

`-Namespace` defaults to `root\cimv2`; `-RemoteAddress` scopes the inbound firewall
rules to your monitoring host (omit it to leave the scope untouched, `Any` to reset).
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
| `--split-classes` | original behaviour: new `CLASS:`/header block whenever the class changes |
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

Deliberate deviations:

1. **One block per query (default).** The original starts a new `CLASS:` line and
   header whenever the class of a returned instance changes, e.g. a
   `Win32_TerminalService` row in `SELECT ... FROM Win32_Service`. Observium's older
   `wmi_parse()` treats that second `CLASS:` line as a data row and dies in
   `array_combine()` on PHP 8 (OBS-4409). wmic-impacket prints a single `CLASS:`
   line (class of the first instance, or the `FROM` class) and a single header
   taken from the first instance; later rows follow that column order, missing
   properties become `(null)`, extra ones are dropped. `--split-classes` restores
   the original layout.
2. **CR/LF inside values become a space.** Some `Description` fields contain line
   breaks, which break every line-based parser.
3. A NULL of any scalar type prints as `(null)`, not just NULL strings.

## Troubleshooting

| Symptom | Meaning |
| --- | --- |
| `ERROR: Login to remote object.` + `NT_STATUS_CONNECTION_REFUSED` / `NT_STATUS_IO_TIMEOUT` / `NT_STATUS_HOST_UNREACHABLE` / `NT_STATUS_BAD_NETWORK_NAME` | Host down, port 135 or the dynamic RPC port filtered, name does not resolve. Check the firewall rule group on the Windows side. |
| `Login to remote object.` + `NT_STATUS_LOGON_FAILURE` (`rpc_s_access_denied`) | Wrong user name / password / domain. Windows Security log: event **4625**. |
| `Login to remote object.` + `NT_STATUS_ACCESS_DENIED` with `0x80070005` | NTLM logon fine (event **4624**) but DCOM activation denied: user not in *Distributed COM Users*, or auth level too low (System event **10036**, should no longer happen with this tool). |
| `Login to remote object.` + `NT_STATUS_ACCESS_DENIED` with `WBEM_E_ACCESS_DENIED` (`0x80041003`) | DCOM fine, but no *Enable Account* / *Remote Enable* on the namespace. |
| `Login to remote object.` + `WBEM_E_INVALID_NAMESPACE` | `--namespace` typo. |
| `ERROR: Retrieve result data.` + `WBEM_E_INVALID_CLASS` / `WBEM_E_INVALID_QUERY` | Class does not exist on that host / WQL syntax error. |
| `Login to remote object.` + `NT_STATUS_BAD_NETWORK_NAME`, stderr says `empty host name in '//'` | Observium sent no host name: *Override WMI config* is ticked on the device but the WMI hostname is blank. Untick the override (the device hostname and the global `$config['wmi']` credentials are then used) or fill in every field. Older builds of this tool printed `ERROR: empty host name`, which Observium reported as "The wmic binary (or script) was not found". |
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
Impacket-encoded WMI instance, and pipe generated output through Observium's real
`wmi_parse()` (`tests/observium_wmi_parse.php`; skipped if `php` is not on the PATH).

## License

MIT, see [LICENSE](LICENSE).
