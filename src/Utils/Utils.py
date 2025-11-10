# Utils/Utils.py
import os
import sys
import json
import hashlib
import datetime
import asyncio
import platform
from typing import List, Dict, Optional, Tuple

# Try optional imports
try:
    import yara
except Exception:
    yara = None

# psutil is cross-platform and used as fallback for process listing on non-Windows
try:
    import psutil
except Exception:
    psutil = None

# wmi is Windows-only; only import if available
try:
    import wmi
except Exception:
    wmi = None

# =========================
#  HASHING (sync)
# =========================
def sha256_hash(path: str) -> Optional[str]:
    """Compute SHA-256 of a file. Return hex digest or None on error."""
    try:
        sha256 = hashlib.sha256()
        BUF_SIZE = 65536
        with open(path, "rb") as f:
            while True:
                chunk = f.read(BUF_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        # Could be permission, not a file, etc.
        # print(f"[Utils] sha256_hash error for {path}: {e}")
        return None


# =========================
#  RUNNING PROCESS (sync) - cross-platform
# =========================
def get_running_process_sync() -> Tuple[set, set]:
    """
    Return (set_of_sha256_hashes, set_of_paths) for running executable processes.
    On Windows will try wmi if available; otherwise psutil.
    """
    paths = set()
    hashes = set()

    system = platform.system()
    # If on Windows and wmi is available, prefer it (gives ExecutablePath)
    if system == "Windows" and wmi is not None:
        try:
            f = wmi.WMI()
            for proc in f.Win32_Process():
                try:
                    path = proc.ExecutablePath
                    if not path:
                        continue
                    paths.add(path)
                    h = sha256_hash(path)
                    if h:
                        hashes.add(h)
                except Exception:
                    continue
        except Exception:
            pass

    # Fallback: use psutil if available (works Linux/Windows/Mac)
    elif psutil is not None:
        for proc in psutil.process_iter(['exe']):
            try:
                exe = proc.info.get('exe')
                if not exe:
                    continue
                paths.add(exe)
                h = sha256_hash(exe)
                if h:
                    hashes.add(h)
            except Exception:
                continue
    else:
        # No supported method available
        pass

    return hashes, paths


async def get_running_process() -> Tuple[set, set]:
    """Async wrapper around get_running_process_sync using thread executor."""
    return await asyncio.to_thread(get_running_process_sync)


# =========================
#  SCAN DIRECTORY (sync)
# =========================
def scan_from_directory_sync(directory: str, deepScan: bool = False) -> Dict[str, str]:
    """
    Walk directory and compute sha256 for files.
    Returns dict {abs_path: sha256}.
    deepScan True -> include all sizes; False -> skip files >= 10MB by default.
    Note: does NOT include running processes (call get_running_process separately).
    """
    sha256s = []
    absPaths = []

    count = 0
    for root, _, files in os.walk(directory):
        for fname in files:
            try:
                path = os.path.join(root, fname)
                # skip yara rules or our own artifacts by name
                if 'rule' in path.lower() or path.endswith('.yar') or path.endswith('.yara'):
                    continue

                size = os.path.getsize(path)
                if not deepScan and size >= 10_000_000:
                    # skip large files in quick mode
                    continue

                h = sha256_hash(path)
                if h:
                    sha256s.append(h)
                    absPaths.append(path)
                count += 1
            except Exception:
                # ignore unreadable files, permission errors, etc.
                continue

    # Build dict; if lengths mismatch, zip uses min length
    res = dict(zip(absPaths, sha256s))
    # print(f"[Utils] scanned {count} files, found {len(res)} hashes")
    return res


async def scan_from_directory(directory: str, deepScan: bool = False) -> Dict[str, str]:
    """
    Async wrapper that also includes running process hashes (if any).
    Returns dict {abs_path: sha256}
    """
    # get running processes in background
    running_hashes, running_paths = await get_running_process()

    # scan filesystem in background
    fs_map = await asyncio.to_thread(scan_from_directory_sync, directory, deepScan)

    # include running processes (paths -> hashes) where available
    result = dict(fs_map)  # copy
    for p in running_paths:
        h = sha256_hash(p)
        if h:
            result[p] = h

    return result


# =========================
#  YARA DIAGNOSTIC (sync)
# =========================
def list_all_rule(rule_dir: str = None) -> Dict[str, str]:
    """
    Return dict mapping namespace -> filepath for all .yar/.yara files under rule_dir.
    If rule_dir is None, default to ./yara_rules relative to this file.
    """
    if rule_dir is None:
        rule_dir = os.path.join(os.path.dirname(__file__), "..", "..", "yara_rules", "rules")
    result = {}
    if not os.path.isdir(rule_dir):
        return result

    # Tìm tất cả file .yar và .yara trong thư mục và subdirectories
    for root, dirs, files in os.walk(rule_dir):
        for fname in sorted(files):
            if fname.lower().endswith((".yar", ".yara")):
                # Tạo namespace từ đường dẫn tương đối
                rel_path = os.path.relpath(os.path.join(root, fname), rule_dir)
                ns = os.path.splitext(rel_path.replace(os.sep, "_"))[0]
                result[ns] = os.path.join(root, fname)
    
    return result


def diagnostic_with_yara_sync(filepaths: List[str], rule_dir: str = None, timeout: int = 10) -> Dict[str, List[str]]:
    """
    Scan given files with compiled YARA rules from rule_dir.
    Returns dict {filepath: [rule_name, ...]} for files that matched.
    Requires yara-python installed. If yara not available or compile fails -> returns {}.
    """
    if yara is None:
        # yara-python not installed
        print("[Utils] yara-python not available")
        return {}

    rules_map = list_all_rule(rule_dir)
    if not rules_map:
        # no rules found
        return {}

    try:
        rules = yara.compile(filepaths=rules_map)
    except Exception as e:
        print(f"[Utils] YARA compile error: {e}")
        return {}

    matches = {}
    for f in filepaths:
        try:
            if not os.path.isfile(f) or os.path.getsize(f) == 0:
                continue
            m = rules.match(f, timeout=timeout)
            if m:
                matches[f] = [match.rule for match in m]
        except yara.TimeoutError:
            print(f"[Utils] YARA timeout for {f}")
            continue
        except Exception as e:
            print(f"[Utils] YARA error for {f}: {e}")
            continue

    return matches


async def diagnostic_with_yara(filepaths: List[str], rule_dir: str = None, timeout: int = 10) -> Dict[str, List[str]]:
    """Async wrapper to run yara diagnostic in a thread."""
    return await asyncio.to_thread(diagnostic_with_yara_sync, filepaths, rule_dir, timeout)


# =========================
#  JSON DB reader
# =========================
def read_json_data_sync(json_path: str = "./Database/Malware.json") -> Optional[dict]:
    try:
        if not os.path.isfile(json_path):
            return None
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Utils] read_json_data error: {e}")
        return None


async def read_json_data(json_path: str = "./Database/Malware.json") -> Optional[dict]:
    return await asyncio.to_thread(read_json_data_sync, json_path)


# =========================
#  WRITE LOG
# =========================
def write_log_sync(path: str, data: List[str]) -> Optional[str]:
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = path if path else os.getcwd()
        os.makedirs(log_dir, exist_ok=True)
        out = os.path.join(log_dir, f"{now}.txt")
        with open(out, "w", encoding="utf-8") as f:
            for line in data:
                f.write(line)
        return out
    except Exception as e:
        print(f"[Utils] write_log error: {e}")
        return None


async def write_log(path: str, data: List[str]) -> Optional[str]:
    return await asyncio.to_thread(write_log_sync, path, data)


# =========================
#  UTILS
# =========================
def remove_dict_key(d: dict, key):
    r = dict(d)
    if key in r:
        del r[key]
    return r
