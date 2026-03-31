"""
wat.py — WAT: Windows ADS Triage
Enumerate, inspect, and triage NTFS Alternate Data Streams.

Part of the XTT toolchain family (Windows-only module).
See also: XTT (Linux/macOS extended-attribute triage)
"""

__version__ = "1.0.1"
__tool__ = "WAT"

import ctypes
import ctypes.wintypes
import csv
import argparse
import sys
import math
import logging
import os
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value  # platform-safe sentinel
ERROR_HANDLE_EOF = 38  # FindFirstStreamW: no ADS present

# ---------------------------------------------------------------------------
# Win32 structures & bindings
# ---------------------------------------------------------------------------
class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    """
    Matches the Windows SDK definition:
        LARGE_INTEGER StreamSize;
        WCHAR         cStreamName[MAX_PATH + 36];  → 296 chars total
    """
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", ctypes.c_wchar * 296),
    ]


# Explicitly declare argtypes/restype so ctypes doesn't truncate on 64-bit
_FindFirstStreamW = ctypes.windll.kernel32.FindFirstStreamW
_FindFirstStreamW.restype = ctypes.c_void_p
_FindFirstStreamW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_uint,
    ctypes.c_void_p,
    ctypes.c_uint,
]

_FindNextStreamW = ctypes.windll.kernel32.FindNextStreamW
_FindNextStreamW.restype = ctypes.c_bool
_FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_FindClose = ctypes.windll.kernel32.FindClose
_FindClose.restype = ctypes.c_bool
_FindClose.argtypes = [ctypes.c_void_p]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class StreamRecord:
    file_path: str
    stream_name: str
    stream_size: int
    file_mtime: str          # ISO-8601 mtime of the *host file* (not the stream)
    mtime_skewed: bool       # True if mtime is within skew_days of scan time
    entropy: float
    content_preview: str
    read_error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core utilities
# ---------------------------------------------------------------------------
def calculate_entropy(data: bytes) -> float:
    """Shannon entropy (bits per byte) for a byte sequence."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)


def get_file_mtime(path: str) -> datetime:
    """Return the mtime of *path* as a UTC-aware datetime."""
    ts = os.stat(path).st_mtime
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def is_mtime_skewed(mtime: datetime, skew_days: int) -> bool:
    """True if *mtime* falls within the last *skew_days* days from now."""
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=skew_days)
    return mtime >= cutoff


def _read_stream(
    full_path: str,
    stream_name: str,
    calc_entropy: bool,
) -> tuple[float, str, Optional[str]]:
    """
    Read stream content; optionally compute entropy and build a preview.

    Returns (entropy, content_preview, error_message_or_None).
    """
    try:
        with open(full_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return 0.0, "", f"OSError: {exc}"

    entropy = calculate_entropy(data) if calc_entropy else 0.0

    # Try UTF-8 for all streams; fall back to hex only for true binary content.
    # Zone.Identifier and other text-based streams surface readable content.
    # Encrypted, packed, or arbitrary binary streams get a hex preview.
    try:
        text = data[:256].decode("utf-8").strip()
        preview = text.replace("\r\n", " | ").replace("\n", " | ")
    except (UnicodeDecodeError, ValueError):
        hex_bytes = data[:64].hex()
        suffix = "..." if len(data) > 64 else ""
        preview = f"HEX:{hex_bytes}{suffix}"

    return entropy, preview, None


def get_ads_streams(file_path: str) -> list[dict]:
    """
    Enumerate NTFS Alternate Data Streams for *file_path* via Kernel32.

    Returns a list of dicts: {'name': str, 'size': int}.
    Returns [] when no ADS are present.
    Raises OSError on real Win32 failures.
    """
    find_data = WIN32_FIND_STREAM_DATA()
    handle = _FindFirstStreamW(file_path, 0, ctypes.byref(find_data), 0)

    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.GetLastError()
        if err == ERROR_HANDLE_EOF:
            return []
        raise OSError(
            f"FindFirstStreamW failed on '{file_path}': Win32 error {err}"
        )

    streams: list[dict] = []
    try:
        while True:
            name = find_data.cStreamName
            if name != "::$DATA":  # skip the default unnamed data stream
                streams.append({"name": name, "size": find_data.StreamSize})
            if not _FindNextStreamW(handle, ctypes.byref(find_data)):
                break
    finally:
        _FindClose(handle)

    return streams


# ---------------------------------------------------------------------------
# File processor
# ---------------------------------------------------------------------------
def process_file(
    path: str,
    calc_entropy: bool,
    check_skew: bool,
    skew_days: int,
) -> list[StreamRecord]:
    """
    Enumerate and read all non-default ADS for *path*.

    Returns a (possibly empty) list of StreamRecord objects.
    Never raises — errors are captured in StreamRecord.read_error.
    """
    records: list[StreamRecord] = []

    try:
        streams = get_ads_streams(path)
    except OSError as exc:
        log.warning("ADS enumeration failed for '%s': %s", path, exc)
        return records

    if not streams:
        return records

    # Resolve mtime once per host file
    try:
        mtime = get_file_mtime(path)
        mtime_iso = mtime.isoformat()
        skewed = is_mtime_skewed(mtime, skew_days) if check_skew else False
    except OSError as exc:
        log.warning("Could not stat '%s': %s", path, exc)
        mtime_iso = "unknown"
        skewed = False

    for s in streams:
        full_stream_path = f"{path}{s['name']}"
        entropy, preview, error = _read_stream(full_stream_path, s["name"], calc_entropy)

        if error:
            log.warning("Could not read stream '%s': %s", full_stream_path, error)

        records.append(
            StreamRecord(
                file_path=path,
                stream_name=s["name"],
                stream_size=s["size"],
                file_mtime=mtime_iso,
                mtime_skewed=skewed,
                entropy=entropy,
                content_preview=preview,
                read_error=error,
            )
        )

    return records


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def scan_logic(
    target: str,
    calc_entropy: bool = False,
    check_skew: bool = False,
    skew_days: int = 3,
    output_file: Optional[str] = None,
) -> list[StreamRecord]:
    """
    Walk *target* (file or directory) and collect ADS records.

    Args:
        target:       Path to a file or directory (directory scan is always recursive).
        calc_entropy: Compute Shannon entropy per stream.
        check_skew:   Flag streams whose host file mtime is within skew_days.
        skew_days:    Number of days for mtime-skew window (default 3).
        output_file:  Optional CSV path for results.

    Returns a list of StreamRecord objects.
    """
    target_path = Path(target).resolve()
    all_records: list[StreamRecord] = []

    if target_path.is_file():
        candidates = [str(target_path)]
    elif target_path.is_dir():
        candidates = [str(p) for p in target_path.rglob("*") if p.is_file()]
    else:
        log.error("Target '%s' is neither a file nor a directory.", target)
        return all_records

    log.info("[WAT] Scanning %d file(s) under '%s'", len(candidates), target_path)

    for file_path in candidates:
        records = process_file(
            file_path,
            calc_entropy=calc_entropy,
            check_skew=check_skew,
            skew_days=skew_days,
        )
        all_records.extend(records)
        if records:
            log.info(
                "  [+] %s — %d ADS stream(s)", file_path, len(records)
            )

    log.info("[WAT] Scan complete. %d stream record(s) collected.", len(all_records))

    if output_file:
        _write_csv(all_records, output_file)

    return all_records


def _write_csv(records: list[StreamRecord], output_file: str) -> None:
    if not records:
        log.info("No records to write.")
        return
    fieldnames = list(records[0].to_dict().keys())
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(r.to_dict() for r in records)
        log.info("Results written to '%s'.", output_file)
    except OSError as exc:
        log.error("Failed to write CSV '%s': %s", output_file, exc)


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
SKEW_MARKER = " ⚑ MTIME-SKEW"

def print_results(records: list[StreamRecord], check_skew: bool, calc_entropy: bool) -> None:
    if not records:
        print("No ADS streams found.")
        return

    col = {"file": 55, "stream": 30, "size": 10, "entropy": 8, "mtime": 26}

    header_parts = [
        f"{'File':<{col['file']}}",
        f"{'Stream':<{col['stream']}}",
        f"{'Size':>{col['size']}}",
    ]
    if calc_entropy:
        header_parts.append(f"{'Entropy':>{col['entropy']}}")
    if check_skew:
        header_parts.append(f"{'MTime (UTC)':<{col['mtime']}}")

    header = "  ".join(header_parts)
    print(f"\n{__tool__} v{__version__} — Windows ADS Triage\n")
    print(header)
    print("─" * len(header))

    for r in records:
        fp = ("…" + r.file_path[-(col['file']-1):]) if len(r.file_path) > col['file'] else r.file_path
        sn = r.stream_name[:col['stream']]

        row_parts = [
            f"{fp:<{col['file']}}",
            f"{sn:<{col['stream']}}",
            f"{r.stream_size:>{col['size']}}",
        ]
        if calc_entropy:
            row_parts.append(f"{r.entropy:>{col['entropy']}}")
        if check_skew:
            mtime_str = r.file_mtime
            if r.mtime_skewed:
                mtime_str += SKEW_MARKER
            row_parts.append(f"{mtime_str:<{col['mtime']}}")

        print("  ".join(row_parts))

        if r.read_error:
            print(f"    !! {r.read_error}")
        else:
            print(f"    >> {r.content_preview[:120]}")

    skewed_count = sum(1 for r in records if r.mtime_skewed)
    print(f"\nTotal streams: {len(records)}", end="")
    if check_skew and skewed_count:
        print(f"  |  {SKEW_MARKER.strip()}: {skewed_count}", end="")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wat",
        description=(
            "WAT — Windows ADS Triage\n"
            "Enumerate and inspect NTFS Alternate Data Streams.\n"
            "Part of the XTT toolchain family."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  wat -f suspicious.exe -e\n"
            "  wat -d C:\\Users\\target -e -t --skew-days 7\n"
            "  wat -d C:\\Downloads -e -w results.csv\n\n"
            "NOTE: --time-skew reflects the host file's data mtime,\n"
            "      not the ADS write time (unavailable via Win32 API)."
        ),
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )

    # Target (mutually exclusive: file or directory)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-d", "--directory", metavar="DIRECTORY",
        help="Recursive scan of a directory.",
    )
    target_group.add_argument(
        "-f", "--file", metavar="FILE",
        help="Scan a single file.",
    )

    # Analysis options
    parser.add_argument(
        "-e", "--entropy", action="store_true",
        help="Calculate Shannon entropy per ADS.",
    )
    parser.add_argument(
        "-t", "--time-skew", action="store_true",
        help=(
            "Flag files whose mtime is within --skew-days (default: 3). "
            "NOTE: reflects file data mtime, not ADS write time."
        ),
    )
    parser.add_argument(
        "--skew-days", type=int, default=3, metavar="N",
        help="Number of days for mtime-skew window (default: 3). Used with -t.",
    )

    # Output
    parser.add_argument(
        "-w", "--write", metavar="FILE",
        help="Export results to CSV.",
    )

    # Verbosity
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable DEBUG logging.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if sys.platform != "win32":
        log.error(
            "WAT requires Windows — NTFS ADS is a Windows-only feature.\n"
            "For Linux/macOS extended attribute triage, use XTT."
        )
        sys.exit(1)

    target = args.file or args.directory

    records = scan_logic(
        target=target,
        calc_entropy=args.entropy,
        check_skew=args.time_skew,
        skew_days=args.skew_days,
        output_file=args.write,
    )

    print_results(records, check_skew=args.time_skew, calc_entropy=args.entropy)


if __name__ == "__main__":
    main()
