# JunkStick

JunkStick is a command-line tool written in Python to help catalog and track the content of external drives (like USB flash drives, external hard drives, etc.), often colloquially referred to as "junk sticks".

It aims to provide quick insights into what's on a drive (version one focuses on top level dir). Browse, track changes over time, and assist with basic organization through tagging and prefix reporting.

Developed with photographers, media managers, security researchers, and anyone managing multiple external drives in mind.  Assumes user's drives have distinct label names.

## Features (Version 1)

* **Scan Drive Content:** Performs a scan of the top-level directory of a specified volume.
* **Track Volumes:** Stores scan results in `junkdrives.json`, keyed by volume name (or potentially UUID in future versions).
* **Change Detection:** Calculates a content hash (based on top-level, non-hidden file/folder names, sizes, types, modification times) to detect changes between scans.
* **Archiving:** Automatically archives the previous scan data to `junkdrives-archive.json` when content changes are detected.
* **Logging:** Logs scan events (start, finish, errors, archiving) to `scan.log`.
* **Content Analysis:** Tracks basic top-level content info: directory names, file counts by extension, files matching a default prefix pattern (`[a-zA-Z]*-`), and years found in filenames.
* **Custom Prefixes:** Supports a user-defined `custom_prefixes.txt` file to track counts of files/folders matching specific naming schemes.
* **Tagging System:** Allows adding, removing, and listing descriptive tags associated with volumes.
* **Reporting:** Various commands to list tracked drives, folders, tags, scan history, archives, duplicate content hashes, prefix counts, and detailed scan data.
* **OS Profiles:** Supports basic OS-specific commands (primarily for volume detection) via `--os {macos,linux,windows}` flag (defaults based on the current system).
* **Dry Run & Verbosity:** Offers a `--dry-run` mode for scans and a `-v`/`--verbose` flag for detailed output.
* **Colorized Output:** Uses basic terminal colors for improved readability in some commands.

## Requirements

* **Python:** Python 3.8 or higher recommended (developed with 3.11.1).
* **Standard Libraries:** Relies only on standard Python libraries included in a typical installation (os, pathlib, json, hashlib, subprocess, argparse, datetime, uuid, re, pprint). No external `pip` packages are needed for V1.
* **OS Commands:** The tool may internally use OS-specific commands depending on the `--os` profile selected, primarily for volume detection and disk usage estimates:
    * macOS: `du`
    * Linux: `du`, `lsblk`
    * Windows: `wmic`
    These commands should ideally be available in the system's PATH for full functionality on the respective OS profile.

## Setup

1.  **Get the Code:** Clone or download the project files.
    ```bash
    # git clone <repository_url> # Or download ZIP
    cd junkstick
    ```
2.  **Create Virtual Environment (Recommended):**
    ```bash
    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

    # Windows (cmd/powershell)
    python -m venv venv
    .\venv\Scripts\activate
    ```
3.  **Dependencies:** No external packages to install via `pip` for Version 1.
4.  **Custom Prefixes (Optional):** If you want to track custom file/folder prefixes, create a file named `custom_prefixes.txt` in the same directory as `junkstick.py`. Add one prefix per line. Lines starting with `#` are ignored.
    ```
    # Example custom_prefixes.txt
    docs-
    media-img-
    proj-
    ```

## Usage

The tool is run from the command line.

**General Syntax:**

```bash
python junkstick.py [global options] <command> [command options]
```


## Code assistance
Gemini 2.5 Pro (experimental) coding model