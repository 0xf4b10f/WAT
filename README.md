# WAT — Windows ADS Triage

**WAT** is a forensic command-line tool for enumerating and triaging NTFS Alternate Data Streams (ADS) on Windows systems. It surfaces hidden stream data, optionally computes Shannon entropy, flags recently modified files, and exports results to CSV for downstream analysis.

WAT is part of the **XTT toolchain family**. For Linux/macOS extended-attribute triage, see [XTT](https://github.com/0xf4b10f/XTT).

---

## Background

NTFS Alternate Data Streams allow additional data to be attached to a file without altering its visible size or name. They are used legitimately by Windows (e.g., `Zone.Identifier` to track web-downloaded files) but are also abused by malware to conceal payloads, configuration data, or scripts alongside innocuous host files.

Key ADS of forensic interest:

| Stream | Purpose |
|---|---|
| `:Zone.Identifier:$DATA` | Mark of the Web — records download origin (`ZoneId`, `HostUrl`, `ReferrerUrl`) |
| `:SmartScreen:$DATA` | SmartScreen reputation metadata |
| `:encryptable:$DATA` | BitLocker or EFS encryption marker |
| Custom named streams | Malware staging, hidden config, secondary payloads |

> **Note on mtime:** WAT reports the host file's data mtime (`::$DATA`). Windows does not expose individual ADS write times via the `FindFirstStream` / `FindNextStream` API — there is no reliable way to timestamp individual stream modifications without raw MFT parsing.

---

## Requirements

- Windows (NTFS volume)
- Python 3.10+
- No third-party dependencies — stdlib only

---

## Installation

```
git clone https://github.com/0xf4b10/WAT.git
cd WAT
python wat.py --help
```

No `pip install` step required.

---

## Usage

```
usage: wat [-h] [--version] (-d DIRECTORY | -f FILE) [-e] [-t] [--skew-days N] [-w FILE] [-v]
```

### Options

| Flag | Description |
|---|---|
| `-d, --directory DIRECTORY` | Recursive scan of a directory |
| `-f, --file FILE` | Scan a single file |
| `-e, --entropy` | Calculate Shannon entropy per ADS |
| `-t, --time-skew` | Flag files whose mtime is within `--skew-days` of scan time |
| `--skew-days N` | Mtime-skew window in days (default: `3`). Requires `-t` |
| `-w, --write FILE` | Export results to CSV |
| `-v, --verbose` | Enable DEBUG logging |
| `--version` | Show version and exit |
| `-h, --help` | Show help and exit |

`-d` and `-f` are mutually exclusive. One is required.

---

## Examples

**Scan a single file and compute entropy:**
```
python wat.py -f C:\Users\victim\Downloads\invoice.exe -e
```

**Recursively scan a directory, flag recently modified files:**
```
python wat.py -d C:\Users\victim -t --skew-days 7
```

**Full triage — entropy, time-skew, and CSV export:**
```
python wat.py -d C:\Users\victim -e -t -w results.csv
```

---

## Output

### Console

WAT prints a summary table to stdout. Columns are shown or hidden based on active flags — `Entropy` only appears when `-e` is passed; `MTime (UTC)` only when `-t` is passed.

```
WAT v1.0.0 — Windows ADS Triage

File                                                     Stream                          Size   Entropy  MTime (UTC)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Users\victim\Downloads\invoice.exe                    :Zone.Identifier:$DATA            87    3.2941  2026-03-25T14:32:01+00:00 ⚑ MTIME-SKEW
    >> [ZoneTransfer] | ZoneId=3 | HostUrl=https://malicious.example/invoice.exe | ReferrerUrl=https://malicious.example/
C:\Users\victim\AppData\Roaming\svchost.dll              :config:$DATA                    512    7.9912  2026-03-24T09:11:44+00:00 ⚑ MTIME-SKEW
    >> HEX:4d5a9000030000000400000...

Total streams: 2  |  MTIME-SKEW: 2
```

`⚑ MTIME-SKEW` marks files whose host-file mtime falls within the skew window. Read errors surface inline with `!!` rather than being silently dropped.

### CSV (`-w`)

The CSV export includes all fields:

| Column | Description |
|---|---|
| `file_path` | Absolute path of the host file |
| `stream_name` | Full ADS name (e.g., `:Zone.Identifier:$DATA`) |
| `stream_size` | Stream size in bytes |
| `file_mtime` | ISO-8601 UTC mtime of the host file |
| `mtime_skewed` | `True` if within skew window, else `False` |
| `entropy` | Shannon entropy (bits/byte); `0.0` if `-e` not passed |
| `content_preview` | Zone.Identifier text or hex preview of stream content |
| `read_error` | Error message if stream could not be read; empty otherwise |

---

## Forensic Notes

### Entropy interpretation

| Range | Likely content |
|---|---|
| 0.0 – 2.0 | Sparse or highly repetitive data |
| 3.5 – 6.0 | Plaintext, structured data |
| 6.0 – 7.2 | Compressed or obfuscated content |
| 7.2 – 8.0 | Encrypted or packed data — high suspicion |

### Zone.Identifier (Mark of the Web)

`Zone.Identifier` streams are decoded as UTF-8 (not UTF-16) and displayed as plain text. Key fields:

```ini
[ZoneTransfer]
ZoneId=3
HostUrl=https://example.com/payload.exe
ReferrerUrl=https://example.com/
```

`ZoneId=3` means the file originated from the Internet zone. `ZoneId=4` indicates a Restricted Sites origin.

### ADS and detection evasion

Adversaries commonly use ADS to:
- Stage secondary payloads hidden alongside benign files
- Store encoded/encrypted configuration
- Persist scripts that are executed via `wscript` or `powershell` with the stream path as argument (e.g., `powershell -c "Get-Content file.txt:hidden | iex"`)

High entropy in a non-`Zone.Identifier` stream on a recently modified file is a strong indicator of suspicious activity.

---

## Limitations

- **Windows only.** ADS is an NTFS feature; WAT will exit with an error on Linux or macOS.
- **ADS write time is not available.** The Win32 `FindFirstStream` / `FindNextStream` API does not expose per-stream timestamps. The mtime shown is for `::$DATA` (the host file's primary data stream). Raw MFT parsing (outside WAT's scope) is required for stream-level timestamps.
- **Directory scans are always recursive.** Use `-f` for single-file examination.
- **Streams are read in full.** Very large streams will be read entirely into memory.

---

## Related Tools

| Tool | Platform | Focus |
|---|---|---|
| [XTT](https://github.com/0xf4b10f/XTT) | macOS / Linux | Extended attribute triage (`com.apple.quarantine`, xattrs) |
| WAT | Windows | NTFS Alternate Data Stream triage |

---

## Changelog

### v1.0.1
- Improved stream content preview: WAT now attempts UTF-8 decoding for all streams, falling back to hex only when the content is not valid UTF-8. Plain-text streams (scripts, config files, readable payloads) now surface as text rather than hex regardless of stream name.

### v1.0.0
- Initial release
- `-d / -f` mutually exclusive target group
- Opt-in `-e / --entropy` (Shannon entropy per stream)
- Opt-in `-t / --time-skew` with configurable `--skew-days` window
- `-w / --write` CSV export
- Dynamic console table (columns shown only when relevant flag is active)
- `Zone.Identifier` decoded as UTF-8 (correct encoding — not UTF-16)
- `WIN32_FIND_STREAM_DATA.cStreamName` buffer sized to 296 (correct — not 260)
- 64-bit safe `INVALID_HANDLE_VALUE` comparison via `ctypes.c_void_p`
- Explicit `argtypes` / `restype` on all Kernel32 bindings
- Structured `StreamRecord` dataclass; read errors captured per-record, never silently dropped

---

## License

MIT — see [LICENSE](LICENSE).
