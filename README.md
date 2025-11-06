# CTF Flag Finder 🚩
<p align="left">
  <img src="https://img.shields.io/badge/python-3.0+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg" alt="Platform">
</p>

```A fast, professional web enumeration tool written in Rust for security professionals and penetration testers.```
Lightweight, cross-platform Python tool to quickly find CTF-style flags (`PREFIX{...}`) on filesystems — ideal for HackTheBox, TryHackMe, picoCTF, and local labs.

## Highlights
- Fast, multi-threaded scanning (configurable workers)  
- Smart filtering (skips binaries, common large folders, and oversized files)  
- Safe (default) and Aggressive modes — scan hidden/system dirs when needed  
- Supports multiple custom prefixes and built-in common prefixes  
- Progress reporting and deduplication

## Quick install
Requires Python 3.7+.

```bash
git clone https://github.com/wvbbb/ctf_flagfinder.git
cd ctf_flagfinder
chmod +x ctf_flagfinder.py   # Linux/macOS
python ctf_flagfinder.py
````

## Common usage
Scan current directory (default prefixes):

```bash
python ctf_flagfinder.py
```

Scan a directory aggressively:

```bash
python ctf_flagfinder.py -d /home/user --aggressive
```

Search specific prefixes:

```bash
python ctf_flagfinder.py -p HTB THM picoCTF -d /path/to/search
```

Increase speed / verbosity:

```bash
python ctf_flagfinder.py -w 20 -v -d /var/www
```

List built-in prefixes:

```bash
python ctf_flagfinder.py --list-common
```

## CLI options (short)
* `-p, --prefix` — prefixes to search (multiple allowed)
* `-d, --directory` — directory to scan (default: `.`)
* `-w, --workers` — worker threads (default: 10)
* `-s, --max-size` — max file size in bytes (default: 10MB)
* `-v, --verbose` — verbose output
* `-a, --aggressive` — include system/hidden dirs

## Built-in prefixes
Common ones include: `HTB`, `THM`, `FLAG`, `CTF`, `picoCTF`, `root`, `user`.

## Safety & ethics
Use only on machines you own or have explicit permission to test. Aggressive scans may require elevated privileges and can be resource-heavy.

## License
MIT — use for learning and authorized testing.

Happy hunting! 🚩
