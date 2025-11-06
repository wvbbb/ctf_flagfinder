#!/usr/bin/env python3
"""
CTF Flag Finder - High-performance tool for finding CTF flags across filesystems
Supports Windows, Linux, and macOS
"""

import os
import re
import sys
import argparse
import mimetypes
import mmap
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple
import threading
import multiprocessing

__version__ = "0.1.0"
__author__ = "wvbbb"
__license__ = "MIT"

COMMON_PREFIXES = [
    'HTB', 'THM', 'FLAG', 'CTF', 'flag', 'picoCTF', 'DUCTF', 
    'CSCG', 'TMCTF', 'SECCON', 'RCTF', 'BCTF', 'WCTF', 'DEFCON',
    'user', 'local', 'proof'
]

SKIP_EXTENSIONS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff', '.tif',
    '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.flv', '.wmv', '.wav', '.flac', '.ogg',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.iso', '.dmg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pyc', '.pyo', '.class', '.o', '.a', '.lib', '.obj',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.node', '.deb', '.rpm', '.msi', '.pkg',
    '.rlib', '.rmeta',
}

BINARY_SIGNATURES = [
    b'\x7fELF',
    b'MZ',
    b'\x89PNG',
    b'\xff\xd8\xff',
    b'GIF8',
    b'PK\x03\x04',
    b'\x1f\x8b',
    b'BM',
    b'\x00\x00\x01\x00',
]

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("[WARNING] tqdm not installed. Install with 'pip install tqdm' for progress bars.")

DEBUG_MODE = False

def is_valid_flag(flag: str) -> Tuple[bool, str]:
    match = re.match(r'([A-Za-z0-9_-]+)\{(.+)\}', flag)
    if not match:
        return False, "Failed to parse flag format"
    
    prefix, content = match.groups()
    
    # Filter out CSS variables
    if prefix.lower() == 'root':
        return False, "CSS variable (root{...})"
    
    if len(content) < 3:
        return False, f"Content too short ({len(content)} chars)"
    if len(content) > 200:
        return False, f"Content too long ({len(content)} chars)"
    
    # Check for mostly printable ASCII
    printable_count = sum(1 for c in content if c.isprintable())
    printable_ratio = printable_count / len(content)
    if printable_ratio < 0.9:
        return False, f"Too many non-printable chars ({printable_ratio:.1%} printable)"
    
    # Filter out binary corruption
    allowed_special = set('_-!@#$%^&*()+=[]{}|;:,.<>?/~` "\'')
    special_chars = sum(1 for c in content if not c.isalnum() and c not in allowed_special)
    special_ratio = special_chars / len(content)
    if special_ratio > 0.3:
        return False, f"Too many special chars ({special_ratio:.1%})"
    
    # Filter out CSS and code blocks
    newline_count = content.count('\n')
    space_ratio = content.count(' ') / len(content) if len(content) > 0 else 0
    if newline_count > 5:
        return False, f"Too many newlines ({newline_count})"
    if space_ratio > 0.5:
        return False, f"Too many spaces ({space_ratio:.1%})"
    
    return True, "Valid"


def search_file_worker(args: Tuple[str, List[str], int, bool]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str, bool, str]]]:
    file_path, prefixes, max_file_size, verbose = args
    
    prefix_pattern = '|'.join(re.escape(p) for p in prefixes)
    pattern = re.compile(
        rf'({prefix_pattern})\{{([A-Za-z0-9_\-!@#$%^&*()+=\[\]{{}}|;:,.<>?/~` "\'\n]+)\}}',
        re.IGNORECASE
    )
    
    results = []
    debug_info = []
    
    try:
        file_path = Path(file_path)
        
        file_size = file_path.stat().st_size
        if file_size > max_file_size:
            return results, debug_info
        
        # Quick binary check using magic bytes
        with open(file_path, 'rb') as f:
            header = f.read(8)
            for sig in BINARY_SIGNATURES:
                if header.startswith(sig):
                    return results, debug_info
            
            if b'\x00' in header:
                return results, debug_info
        
        # Use memory-mapped I/O for large files (>1MB)
        if file_size > 1024 * 1024:
            with open(file_path, 'r+b') as f:
                try:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                        content = mmapped.read().decode('utf-8', errors='ignore')
                        matches = pattern.finditer(content)
                        for match in matches:
                            flag = match.group(0)
                            is_valid, reason = is_valid_flag(flag)
                            if DEBUG_MODE:
                                debug_info.append((flag, str(file_path), is_valid, reason))
                            if is_valid:
                                results.append((flag, str(file_path)))
                except (ValueError, OSError):
                    pass
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                matches = pattern.finditer(content)
                for match in matches:
                    flag = match.group(0)
                    is_valid, reason = is_valid_flag(flag)
                    if DEBUG_MODE:
                        debug_info.append((flag, str(file_path), is_valid, reason))
                    if is_valid:
                        results.append((flag, str(file_path)))
    
    except (OSError, PermissionError, UnicodeDecodeError):
        pass
    
    return results, debug_info


class FlagFinder:
    def __init__(self, prefixes: List[str], search_path: str, max_workers: int = None, 
                 max_file_size: int = 10 * 1024 * 1024, verbose: bool = False,
                 aggressive_mode: bool = False, use_multiprocessing: bool = True):
        self.prefixes = prefixes
        self.search_path = Path(search_path).resolve()
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.max_file_size = max_file_size
        self.verbose = verbose
        self.aggressive_mode = aggressive_mode
        self.use_multiprocessing = use_multiprocessing
        self.flags_found: Set[Tuple[str, str]] = set()
        self.debug_matches = []
        self.files_scanned = 0
        self.dirs_skipped = 0
        self.lock = threading.Lock()
        
        prefix_pattern = '|'.join(re.escape(p) for p in prefixes)
        self.pattern = re.compile(
            rf'({prefix_pattern})\{{([A-Za-z0-9_\-!@#$%^&*()+=\[\]{{}}|;:,.<>?/~` "\'\n]+)\}}',
            re.IGNORECASE
        )
    
    def should_skip_directory(self, dir_name: str) -> bool:
        # Always skip these for performance
        if dir_name in {'node_modules', '.git', '.svn', '__pycache__', 'venv', 'env',
                       '.venv', 'site-packages', 'dist-packages', '.npm', '.cache'}:
            return True
        
        if self.aggressive_mode:
            return False
        
        # Skip system directories in safe mode
        if dir_name in {'Windows', 'System32', 'SysWOW64', 'WinSxS',
                       'Program Files', 'Program Files (x86)', 
                       'ProgramData', '$Recycle.Bin', 'Recovery',
                       'System Volume Information', 'Boot', 'PerfLogs'} or dir_name.startswith('.'):
            return True
        
        return False
    
    def should_skip_file(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            return True
        
        try:
            if file_path.stat().st_size > self.max_file_size:
                if self.verbose:
                    print(f"[SKIP] File too large: {file_path}")
                return True
        except (OSError, PermissionError):
            return True
        
        return False
    
    def walk_directory(self) -> List[Path]:
        files_to_scan = []
        
        def scan_dir(path):
            try:
                with os.scandir(path) as entries:
                    dirs_to_scan = []
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if not self.should_skip_directory(entry.name):
                                    dirs_to_scan.append(entry.path)
                                else:
                                    with self.lock:
                                        self.dirs_skipped += 1
                            elif entry.is_file(follow_symlinks=False):
                                file_path = Path(entry.path)
                                if not self.should_skip_file(file_path):
                                    files_to_scan.append(file_path)
                        except (OSError, PermissionError):
                            pass
                    
                    for dir_path in dirs_to_scan:
                        scan_dir(dir_path)
            
            except (OSError, PermissionError) as e:
                if self.verbose:
                    print(f"[ERROR] Cannot access {path}: {e}")
        
        scan_dir(str(self.search_path))
        return files_to_scan
    
    def search(self) -> Set[Tuple[str, str]]:
        print(f"[*] Starting flag search in: {self.search_path}")
        print(f"[*] Looking for prefixes: {', '.join(self.prefixes)}")
        print(f"[*] Using {self.max_workers} worker {'processes' if self.use_multiprocessing else 'threads'}")
        print(f"[*] Mode: {'AGGRESSIVE (scanning all directories)' if self.aggressive_mode else 'SAFE (skipping system directories)'}")
        if DEBUG_MODE:
            print(f"[*] DEBUG MODE: Will show all matches and validation results")
        print()
        
        print("[*] Collecting files to scan...")
        files_to_scan = self.walk_directory()
        print(f"[*] Found {len(files_to_scan)} files to scan (skipped {self.dirs_skipped} directories)")
        print()
        
        if not files_to_scan:
            print("[!] No files to scan")
            return self.flags_found
        
        print("[*] Scanning files for flags...")
        
        if TQDM_AVAILABLE:
            pbar = tqdm(
                total=len(files_to_scan),
                desc="Scanning files",
                unit="file",
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
            )
        
        if self.use_multiprocessing:
            worker_args = [
                (str(file_path), self.prefixes, self.max_file_size, self.verbose)
                for file_path in files_to_scan
            ]
            
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(search_file_worker, args) for args in worker_args]
                
                for future in as_completed(futures):
                    results, debug_info = future.result()
                    self.files_scanned += 1
                    
                    if DEBUG_MODE and debug_info:
                        self.debug_matches.extend(debug_info)
                    
                    if results:
                        self.flags_found.update(results)
                        if TQDM_AVAILABLE:
                            pbar.write("")
                        for flag, path in results:
                            msg = f"[+] FLAG FOUND: {flag}\n    Location: {path}"
                            if TQDM_AVAILABLE:
                                pbar.write(msg)
                            else:
                                print(f"\n{msg}")
                    
                    if TQDM_AVAILABLE:
                        pbar.update(1)
                        pbar.set_postfix({'flags': len(self.flags_found)}, refresh=False)
        else:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                worker_args = [
                    (str(file_path), self.prefixes, self.max_file_size, self.verbose)
                    for file_path in files_to_scan
                ]
                
                futures = [executor.submit(search_file_worker, args) for args in worker_args]
                
                for future in as_completed(futures):
                    results, debug_info = future.result()
                    self.files_scanned += 1
                    
                    if DEBUG_MODE and debug_info:
                        self.debug_matches.extend(debug_info)
                    
                    if results:
                        self.flags_found.update(results)
                        if TQDM_AVAILABLE:
                            pbar.write("")
                        for flag, path in results:
                            msg = f"[+] FLAG FOUND: {flag}\n    Location: {path}"
                            if TQDM_AVAILABLE:
                                pbar.write(msg)
                            else:
                                print(f"\n{msg}")
                    
                    if TQDM_AVAILABLE:
                        pbar.update(1)
                        pbar.set_postfix({'flags': len(self.flags_found)}, refresh=False)
        
        if TQDM_AVAILABLE:
            pbar.close()
        
        print(f"\n[*] Scan complete! Scanned {self.files_scanned} files")
        return self.flags_found


def main():
    global DEBUG_MODE
    
    parser = argparse.ArgumentParser(
        description='CTF Flag Finder - Search filesystem for CTF flags',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python flag_finder.py
  python flag_finder.py -d ~ --aggressive
  python flag_finder.py -p HTB -d /path/to/search
  python flag_finder.py -p HTB THM FLAG -d /home/user
  python flag_finder.py -v -w 20 -d /opt --aggressive
  python flag_finder.py --debug -p HTB
        """
    )
    
    parser.add_argument('-p', '--prefix', nargs='+',
        help='Flag prefix(es) to search for (e.g., HTB THM FLAG)')
    parser.add_argument('-d', '--directory', default='.',
        help='Directory to search (default: current directory)')
    parser.add_argument('-w', '--workers', type=int, default=None,
        help=f'Number of worker processes (default: {multiprocessing.cpu_count()})')
    parser.add_argument('-s', '--max-size', type=int, default=10 * 1024 * 1024,
        help='Maximum file size to scan in bytes (default: 10MB)')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Enable verbose output')
    parser.add_argument('-a', '--aggressive', action='store_true',
        help='Scan system directories and hidden directories')
    parser.add_argument('--no-multiprocessing', action='store_true',
        help='Use threading instead of multiprocessing')
    parser.add_argument('--debug', action='store_true',
        help='Show all matches and validation results')
    parser.add_argument('--list-common', action='store_true',
        help='List common CTF flag prefixes and exit')
    
    args = parser.parse_args()
    DEBUG_MODE = args.debug
    
    if args.list_common:
        print("Common CTF Flag Prefixes:")
        for prefix in COMMON_PREFIXES:
            print(f"  - {prefix}")
        sys.exit(0)
    
    prefixes = args.prefix if args.prefix else COMMON_PREFIXES
    search_path = Path(os.path.expanduser(args.directory))
    
    if not search_path.exists():
        print(f"[ERROR] Directory does not exist: {search_path}")
        sys.exit(1)
    
    if not search_path.is_dir():
        print(f"[ERROR] Path is not a directory: {search_path}")
        sys.exit(1)
    
    finder = FlagFinder(
        prefixes=prefixes,
        search_path=str(search_path),
        max_workers=args.workers,
        max_file_size=args.max_size,
        verbose=args.verbose,
        aggressive_mode=args.aggressive,
        use_multiprocessing=not args.no_multiprocessing
    )
    
    try:
        flags = finder.search()
        
        if DEBUG_MODE and finder.debug_matches:
            print("\n" + "="*60)
            print(f"DEBUG: All matches found ({len(finder.debug_matches)} total)")
            print("="*60)
            for flag, path, is_valid, reason in finder.debug_matches:
                status = "[VALID]" if is_valid else "[REJECTED]"
                print(f"\n{status} {flag}")
                print(f"  File: {path}")
                print(f"  Reason: {reason}")
        
        print("\n" + "="*60)
        print(f"SUMMARY: Found {len(flags)} unique flag(s)")
        print("="*60)
        
        if flags:
            print("\nAll flags found:")
            for flag, path in sorted(flags):
                print(f"  {flag}")
                print(f"    → {path}")
                print()
        else:
            print("\nNo flags found. Try:")
            print("  - Using different prefixes with -p")
            print("  - Searching a different directory with -d")
            print("  - Using --aggressive mode to scan system directories")
            print("  - Using --debug mode to see all matches")
    
    except KeyboardInterrupt:
        print("\n\n[!] Search interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        if DEBUG_MODE:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
