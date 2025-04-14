#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import uuid
from pathlib import Path
import pprint # For pretty printing the dry run data

# --- Constants ---
# DEFAULT_OS = 'macos' # Defaulted during argparse setup now
SUPPORTED_OS = ['macos', 'linux', 'windows']
JUNKDRIVES_FILE = Path("junkdrives.json")
ARCHIVE_FILE = Path("junkdrives-archive.json")
LOG_FILE = Path("scan.log")
CUSTOM_PREFIXES_FILE = Path("custom_prefixes.txt")
FILE_PREFIX_PATTERN = re.compile(r"^[a-zA-Z]+-")
YEAR_PATTERN = re.compile(r'\b(19[89]\d|20\d\d)\b') # Matches years 1980-2099


# ANSI Color Codes
COLOR_GREEN = '\033[92m'
COLOR_ORANGE = '\033[93m'
COLOR_GRAY = '\033[90m'  # Bright Black often appears as gray
COLOR_RESET = '\033[0m'

# --- Helper Functions ---
def load_custom_prefixes(filepath=CUSTOM_PREFIXES_FILE):
    """Loads custom prefixes from a text file (one prefix per line)."""
    prefixes = []
    if filepath.exists() and filepath.is_file():
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    prefix = line.strip()
                    if prefix and not prefix.startswith('#'): # Ignore empty lines and comments
                        prefixes.append(prefix)
            print_verbose(f"Loaded {len(prefixes)} custom prefixes from {filepath}", True) # Always print this? Maybe check verbose flag later.
        except IOError as e:
            print_error(f"Could not read custom prefixes file {filepath}: {e}")
    else:
        print_verbose(f"Custom prefixes file not found: {filepath}", True) # Info message
    return prefixes

def print_verbose(message, verbose=True):
    """Prints message only if verbose is True."""
    if verbose:
        print(message)

def print_error(message):
    """Prints an error message to stderr."""
    print(f"Error: {message}", file=sys.stderr)

def log_event(message):
    """Appends a timestamped message to the log file."""
    now = datetime.datetime.now().isoformat()
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{now} - {message}\n")
    except IOError as e:
        print_error(f"Could not write to log file {LOG_FILE}: {e}")

def load_json_data(filepath):
    """Loads data from a JSON file."""
    if not filepath.exists():
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print_error(f"Could not read or parse {filepath}: {e}")
        return {} # Return empty dict on error

def save_json_data(filepath, data):
    """Saves data to a JSON file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, sort_keys=True)
    except IOError as e:
        print_error(f"Could not write to {filepath}: {e}")

def get_disk_usage(path, target_os, verbose=True):
    """Gets disk usage for the given path based on the OS."""
    path_str = str(path)
    total_size = -1 # Default to -1 to indicate error/unknown
    timeout_seconds = 60 # Wait up to 60 seconds for the command

    print_verbose(f"Calculating disk usage for: {path} (timeout={timeout_seconds}s)", verbose)
    try:
        if target_os in ['macos', 'linux']:
            # Use 'du -sk' for kilobytes consistently
            result = subprocess.run(
                ['du', '-sk', path_str],
                capture_output=True, text=True, check=True, encoding='utf-8',
                timeout=timeout_seconds
            )
            match = re.match(r'^(\d+)', result.stdout)
            if match:
                total_size = int(match.group(1)) * 1024 # Convert KB to Bytes
            else:
                print_verbose(f"Warning: Could not parse size from 'du -sk' output: {result.stdout}", verbose)
                # Keep total_size as -1

        elif target_os == 'windows':
             # If using wmic or other command here, add timeout too
             # Current implementation sums file sizes - less likely to hang, but could be slow.
             print_verbose("Calculating disk usage on Windows by summing top-level file sizes.", verbose)
             # This part doesn't use subprocess, so no timeout here unless we change method
             # Add try/except around the summation for robustness?
             try:
                 total_size = sum(entry.stat().st_size for entry in path.iterdir() if entry.is_file())
             except OSError as e:
                 print_verbose(f"Warning: Error summing file sizes on Windows for {path_str}: {e}", verbose)
                 total_size = -1


    except subprocess.TimeoutExpired:
        print_error(f"Command timed out after {timeout_seconds}s while getting disk usage for {path_str}")
        total_size = -1 # Indicate timeout
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
        print_verbose(f"Warning: Could not get disk usage for {path_str} on {target_os}: {e}", verbose)
        total_size = -1 # Indicate error
    # No need for final fallback summation if we default total_size to -1

    print_verbose(f"Disk usage calculated: {total_size if total_size != -1 else 'Error'} bytes", verbose)
    return total_size

def get_dir_listing_details(path, target_os, verbose=True):
    """Gets detailed directory listing (name, type, size, mod_time) for hashing, IGNORING hidden files."""
    listing = []
    print_verbose(f"Getting listing details for: {path} (ignoring hidden)", verbose)
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                # --- Add check for hidden files/directories ---
                if entry.name.startswith('.'):
                    print_verbose(f"Skipping hidden entry for hashing: {entry.name}", verbose)
                    continue # Skip this entry entirely

                try:
                    # Follow symlinks for stat to get info about the target
                    stat_result = entry.stat(follow_symlinks=True)
                    item_type = 'dir' if entry.is_dir(follow_symlinks=True) else 'file'
                    listing.append({
                        "name": entry.name,
                        "type": item_type,
                        "size": stat_result.st_size,
                        "modified": stat_result.st_mtime
                    })
                except FileNotFoundError:
                     print_verbose(f"Warning: Skipping broken symlink {entry.name}", verbose)
                     continue # Skip broken symlinks
                except OSError as e:
                    print_verbose(f"Warning: Could not stat entry {entry.name}: {e}", verbose)
                    continue # Skip files we can't access

    except (FileNotFoundError, PermissionError, OSError) as e:
        print_error(f"Could not access directory {path}: {e}")
        return None # Indicate error

    # Sort for consistent hashing
    listing.sort(key=lambda x: x['name'])
    print_verbose(f"Found {len(listing)} non-hidden items in top-level listing.", verbose)
    return listing

def calculate_hash(data):
    """Calculates SHA-256 hash of the canonical JSON representation of data."""
    if data is None:
        return None
    try:
        # Ensure consistent serialization: sort keys, handle floats precisely
        # Using separators=(',', ':') ensures minimal whitespace
        data_string = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    except TypeError as e:
        print_error(f"Could not serialize data for hashing: {e}")
        return None

def analyze_content(path, target_os, custom_prefixes, verbose=True):
    """Analyzes the top-level content of the directory, including custom prefixes."""
    directories = []
    file_extensions = {}
    prefix_matches = {} # For the original [a-zA-Z]*- pattern
    years = set()
    # Initialize counts for custom prefixes provided
    custom_prefix_counts = {prefix: 0 for prefix in custom_prefixes}

    print_verbose(f"Analyzing content in: {path}", verbose)
    print_verbose(f"Checking for custom prefixes: {custom_prefixes}", verbose)
    try:
        for entry in path.iterdir():
            entry_name = entry.name

            # --- Custom Prefix Check (applies to both files and dirs) ---
            for prefix in custom_prefixes:
                if entry_name.startswith(prefix):
                    custom_prefix_counts[prefix] += 1
                    # Decide if we stop after first match or allow multiple?
                    # Current logic counts for all matches (e.g. "media-img-" matches "media-" and "media-img-")
                    # If only longest/first match desired, add a 'break' here and ensure prefixes are sorted appropriately.

            # Extract years from names
            found_years = YEAR_PATTERN.findall(entry_name)
            years.update(found_years)

            if entry.is_dir():
                directories.append(entry_name)
            elif entry.is_file():
                suffix = entry.suffix.lower()
                if suffix:
                    file_extensions[suffix] = file_extensions.get(suffix, 0) + 1
                else:
                    # Check for original prefix pattern if no extension
                    match = FILE_PREFIX_PATTERN.match(entry_name)
                    if match:
                        prefix = match.group(0) # The matched prefix like "pics-"
                        prefix_matches[prefix] = prefix_matches.get(prefix, 0) + 1
                    else:
                        # Count files with no extension and no matching prefix
                         no_ext_key = "[no_extension_no_prefix]"
                         file_extensions[no_ext_key] = file_extensions.get(no_ext_key, 0) + 1
            # Skip symlinks for this analysis? Or analyze the link itself? Currently skips.

    except (FileNotFoundError, PermissionError, OSError) as e:
        print_error(f"Could not fully analyze content in {path}: {e}")
        # Return potentially partial results

    # Combine original prefix counts into file_extensions for a single view
    for prefix, count in prefix_matches.items():
         key = f"[prefix:{prefix}]" # Distinguish this from custom prefixes
         file_extensions[key] = count

    print_verbose(f"Analysis complete: {len(directories)} dirs, {len(file_extensions)} file types, {len(years)} years, {sum(custom_prefix_counts.values())} custom prefixes found.", verbose)
    # Return the new counts dictionary
    return sorted(directories), file_extensions, sorted(list(years)), custom_prefix_counts

def detect_mounted_volumes(target_os, verbose=True):
    """Detects potentially external mounted volumes based on OS."""
    volumes = {} # Store as {name: path_object}
    print_verbose(f"Detecting volumes for OS profile: {target_os}", verbose)

    if target_os == 'macos':
        volumes_path = Path('/Volumes')
        exclude_names = {'Macintosh HD', 'Preboot', 'Recovery', 'VM', 'Mobile Backups'}
        try:
            for entry in volumes_path.iterdir():
                if entry.is_dir() and entry.name not in exclude_names:
                    try:
                        # Check if it's a mount point and seems accessible
                        if entry.is_mount() and any(entry.iterdir()):
                             volumes[entry.name] = entry
                        elif entry.is_mount():
                            print_verbose(f"Volume {entry.name} is a mount point but appears empty or inaccessible, skipping.", verbose)
                        else:
                            print_verbose(f"Skipping non-mount point directory in /Volumes: {entry.name}", verbose)
                    except PermissionError:
                         print_verbose(f"Permission denied checking contents of {entry.name}, skipping.", verbose)
                    except OSError as e:
                        print_verbose(f"Error checking contents of {entry.name}: {e}, skipping.", verbose)
        except FileNotFoundError:
            print_error(f"Cannot find volumes directory: {volumes_path}")
        except OSError as e:
            print_error(f"Could not list volumes in {volumes_path}: {e}")

    elif target_os == 'linux':
        print_verbose("Attempting volume detection on Linux using 'lsblk'", verbose)
        try:
            result = subprocess.run(
                ['lsblk', '-o', 'NAME,MOUNTPOINT,RM,TYPE', '-n', '-l'],
                capture_output=True, text=True, check=True, encoding='utf-8'
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                # Ensure MOUNTPOINT is present and RM is '1'
                if len(parts) >= 3 and parts[1] and parts[2] == '1':
                    mountpoint = parts[1]
                    if mountpoint != '/': # Exclude root filesystem
                        mount_path = Path(mountpoint)
                        if mount_path.exists() and mount_path.is_dir():
                             volume_name = mount_path.name
                             volumes[volume_name] = mount_path
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            print_error(f"Could not use 'lsblk' for volume detection: {e}. Manual specification needed.")
        except Exception as e:
            print_error(f"An unexpected error occurred during Linux volume detection: {e}")

    elif target_os == 'windows':
        print_verbose("Attempting volume detection on Windows using 'wmic'", verbose)
        try:
            command = 'wmic logicaldisk where DriveType=2 get Caption,VolumeName /format:csv'
            result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True, encoding='oem', errors='ignore')
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]: # Skip header
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        node, caption, volume_name = parts[0], parts[1], parts[2] if len(parts) > 2 else ""
                        drive_letter = caption.strip()
                        if not drive_letter: continue # Skip if drive letter is missing
                        path_obj = Path(drive_letter + '\\')
                        vol_key = volume_name.strip() if volume_name.strip() else drive_letter
                        if path_obj.exists() and path_obj.is_dir():
                            volumes[vol_key] = path_obj
                        else:
                             print_verbose(f"Detected Windows drive {vol_key} ({drive_letter}) but path seems invalid.", verbose)

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            print_error(f"Could not use 'wmic' for volume detection: {e}. Manual specification needed.")
        except Exception as e:
            print_error(f"An unexpected error occurred during Windows volume detection: {e}")

    print_verbose(f"Detected volumes: {list(volumes.keys())}", verbose)
    return volumes

# --- Command Functions ---
def report_prefix_counts(verbose=True):
    """Reports the latest custom prefix counts for all tracked volumes and provides an overall summary."""
    print("--- Custom Prefix Counts Report ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)

    if not junk_drives_data:
        print(f"No scan data found in {JUNKDRIVES_FILE} to report.")
        return

    # --- Initialize dictionary to hold overall totals ---
    overall_prefix_totals = {}

    # --- Iterate through each volume's data ---
    for volume_name, scan_data in sorted(junk_drives_data.items()): # Sort by volume name
        print(f"\nVolume: {volume_name}")

        content_hash = scan_data.get("content_hash", "N/A")
        # Truncate hash for display
        display_hash = content_hash[:12] + "..." if content_hash != "N/A" else "N/A"
        print(f"  Hash: {display_hash}")

        print(f"  Prefix Counts:")
        custom_counts = scan_data.get("custom_prefix_counts") # Get the dict

        if custom_counts and isinstance(custom_counts, dict) and custom_counts: # Check if exists, is dict, and not empty
            for prefix, count in sorted(custom_counts.items()): # Sort prefixes alphabetically for display
                print(f"    {prefix}: {count}")
                # --- Aggregate totals ---
                overall_prefix_totals[prefix] = overall_prefix_totals.get(prefix, 0) + count
        else:
            print("    (No custom prefixes found or tracked in last scan)")

    print("\n--- End Report ---")

    # --- Add Overall Summary Section ---
    print("\n--- Overall Prefix Summary ---")
    if not overall_prefix_totals:
        print("No custom prefixes found across any tracked volumes.")
    else:
        print("Total counts across all volumes:")
        # Sort the final summary alphabetically by prefix
        for prefix, total_count in sorted(overall_prefix_totals.items()):
            print(f"  {prefix}: {total_count}")
    print("--- End Summary ---")

def check_duplicates(verbose=True):
    """Checks for duplicate content hashes among tracked drives."""
    print("--- Checking for Duplicate Scans (Based on Content Hash) ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)

    if not junk_drives_data:
        print(f"No scan data found in {JUNKDRIVES_FILE} to check.")
        return

    hashes_to_volumes = {}
    for volume_name, scan_data in junk_drives_data.items():
        content_hash = scan_data.get("content_hash")
        if not content_hash:
            print_verbose(f"Skipping volume '{volume_name}' due to missing content hash.", verbose)
            continue

        if content_hash not in hashes_to_volumes:
            hashes_to_volumes[content_hash] = []
        hashes_to_volumes[content_hash].append({
            "name": volume_name,
            "scan_time": scan_data.get("scan_time", "N/A"),
            "scan_id": scan_data.get("scan_id", "N/A")
            })

    found_duplicates = False
    print("\nChecking for identical content hashes across different volume entries...")
    for content_hash, volumes_list in hashes_to_volumes.items():
        if len(volumes_list) > 1:
            found_duplicates = True
            print(f"\n[DUPLICATE CONTENT DETECTED] Hash: {content_hash[:12]}...")
            for vol_info in volumes_list:
                 print(f"  - Volume: '{vol_info['name']}' (Scan Time: {vol_info['scan_time']}, Scan ID: ...{vol_info['scan_id'][-6:]})")

    if not found_duplicates:
        print("\nNo volumes found with identical content hashes in their latest scans.")
    else:
        print("\nNote: This detects drives whose *last scan* resulted in the same content hash.")
        print("      It may indicate clones, backups, or identically named drives overwriting each other's records.")
        print("      For true physical drive distinction, Version 2 may introduce UUID tracking.")

def show_scan_data(target_os, verbose=True):
    """Shows the latest scan data for currently connected and tracked drives."""
    print("--- Show Latest Scan Data ---")
    print("Checking for connected volumes...")
    # Use verbose=False for detection unless main verbose is on? Let's pass it through.
    detected_volumes = detect_mounted_volumes(target_os, verbose) # dict {name: path}

    if not detected_volumes:
        print("No external volumes detected or accessible.")
        return

    junk_drives_data = load_json_data(JUNKDRIVES_FILE)
    if not junk_drives_data:
         print("No drives are currently tracked in {JUNKDRIVES_FILE}.")
         # Still list detected but untracked drives below? Yes.
         # return # Exit early if nothing tracked? Or show detected below? Let's show detected.
         pass # Continue to show detected untracked volumes

    found_tracked = False
    print("\n--- Status of Detected Volumes ---")
    for name, path in detected_volumes.items():
        print(f"\nVolume: {name} ({path})")
        if name in junk_drives_data:
            found_tracked = True
            print(f"{COLOR_GREEN}[Tracked]{COLOR_RESET} - Displaying latest scan data:")
            scan_data = junk_drives_data[name]
            # Pretty print the scan data dictionary
            # Use json.dumps for consistent formatting that matches the file
            print(json.dumps(scan_data, indent=4, sort_keys=True))
        else:
            print(f"{COLOR_ORANGE}[Untracked]{COLOR_RESET} - No scan data available.")
            print_verbose("Run 'scan' command or 'detect --scan-untracked' to track this volume.", verbose)

    if not found_tracked and junk_drives_data:
         print("\nNone of the currently connected volumes are tracked in {JUNKDRIVES_FILE}.")
    elif not found_tracked and not junk_drives_data:
         print(f"\nNo volumes detected, and no volumes tracked in {JUNKDRIVES_FILE}.")

def perform_scan(volume_path, target_os, verbose=True, dry_run=False):
    """Performs the scan, updates data, archives if needed, and logs."""
    # --- [Existing initial print statements and path setup] ---
    print(f"--- Starting Scan Operation ---")
    print(f"Volume: {volume_path}")
    print(f"OS Profile: {target_os}")
    print(f"Verbose: {verbose}")
    print(f"Dry Run: {dry_run}")
    print(f"------------------------------")

    volume_path = Path(volume_path)

    if not volume_path.is_dir() or not volume_path.exists():
        print_error(f"Volume path '{volume_path}' does not exist or is not a directory.")
        return False # Indicate failure

    # Derive volume name consistently
    # --- [Existing volume_name derivation logic] ---
    volume_name = volume_path.name
    if not volume_name and str(volume_path).endswith(':\\'): # Handle Windows root path 'E:\' -> name 'E:'
        volume_name = str(volume_path).split(':')[0] + ':'
    elif target_os == 'windows' and volume_name == '': # Fallback if name is empty
         volume_name = str(volume_path).rstrip('\\')

    print_verbose(f"Derived volume name for scan: {volume_name}", verbose)

    # --- Load Custom Prefixes ---
    custom_prefixes = load_custom_prefixes() # Uses default CUSTOM_PREFIXES_FILE

    # 1. Get directory listing (required for both dry run and actual scan)
    listing_details = get_dir_listing_details(volume_path, target_os, verbose)

    # --- [Existing handling if listing_details is None] ---
    if listing_details is None:
       print_error(f"Scan failed for {volume_name}: Could not get directory listing.")
       if not dry_run:
            scan_id_fail = str(uuid.uuid4())
            log_event(f"SCAN FAILED (Listing): Volume: {volume_name}, Path: {volume_path}, ScanID: {scan_id_fail}")
       return False

    # --- Dry Run Logic ---
    if dry_run:
        # --- [Existing dry run logic - no changes needed here] ---
        print("\n--- DRY RUN MODE ---")
        print("Showing data that would be used to generate the content hash:")
        pprint.pprint(listing_details)
        print("--- END DRY RUN ---")
        return True

    # --- Actual Scan Logic (if not dry_run) ---
    print_verbose("Proceeding with full scan...", verbose)

    # 2. Calculate hash
    content_hash = calculate_hash(listing_details)
    # --- [Existing handling if content_hash is None] ---
    if content_hash is None:
         print_error(f"Scan failed for {volume_name}: Could not calculate content hash.")
         scan_id_fail = str(uuid.uuid4())
         log_event(f"SCAN FAILED (Hashing): Volume: {volume_name}, Path: {volume_path}, ScanID: {scan_id_fail}")
         return False

    print_verbose(f"Content Hash: {content_hash}", verbose)

    # 3. Perform other analyses (passing custom_prefixes)
    scan_id = str(uuid.uuid4())
    scan_time = datetime.datetime.now().isoformat()
    disk_usage = get_disk_usage(volume_path, target_os, verbose)
    # Pass custom_prefixes and receive custom_prefix_counts
    directories, file_types, years, custom_prefix_counts = analyze_content(
        volume_path, target_os, custom_prefixes, verbose
    )

    new_scan_data = {
        "scan_id": scan_id,
        "scan_time": scan_time,
        "os_profile": target_os,
        "content_hash": content_hash,
        "disk_usage_bytes": disk_usage,
        "top_level_dirs": directories,
        "top_level_file_types": file_types,
        "found_years": years,
        "custom_prefix_counts": custom_prefix_counts, # Add the new data
    }

    # --- [Existing logic for loading data, checking changes, archiving, saving, logging] ---
    # 4. Load existing data
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)
    archive_data = load_json_data(ARCHIVE_FILE)

    # 5. Check for changes and archive if necessary
    archived = False
    change_detected = False
    is_new = False
    if volume_name in junk_drives_data:
        old_scan_data = junk_drives_data[volume_name]
        old_hash = old_scan_data.get("content_hash")
        if old_hash != content_hash:
            print_verbose(f"Change detected for volume '{volume_name}'. Archiving previous scan (ID: {old_scan_data.get('scan_id', 'N/A')}).", verbose)
            change_detected = True
            if volume_name not in archive_data:
                archive_data[volume_name] = []
            archive_data[volume_name].append(old_scan_data)
            save_json_data(ARCHIVE_FILE, archive_data)
            log_event(f"ARCHIVED: Volume: {volume_name}, Previous ScanID: {old_scan_data.get('scan_id', 'N/A')}")
            archived = True
        else:
            print_verbose(f"No content changes detected for volume '{volume_name}' based on hash.", verbose)
            # Keep old ID and hash, update time/usage/prefix counts
            new_scan_data["scan_id"] = old_scan_data.get("scan_id", scan_id)
            new_scan_data["content_hash"] = old_hash
            new_scan_data["scan_time"] = scan_time
            new_scan_data["disk_usage_bytes"] = disk_usage
            # Update prefix counts even if hash didn't change, as the list might have
            new_scan_data["custom_prefix_counts"] = custom_prefix_counts
            # Should we also update dirs/files/years if hash matches? Probably not necessary.
    else:
        print_verbose(f"Volume '{volume_name}' is newly tracked.", verbose)
        is_new = True
        change_detected = True # Treat new as a change

    # 6. Update main data file if changed or new, or if only metadata updated
    # Always save the latest new_scan_data which includes potentially updated time, usage, or prefix counts
    junk_drives_data[volume_name] = new_scan_data
    save_json_data(JUNKDRIVES_FILE, junk_drives_data)
    if change_detected:
         print_verbose(f"Scan data for '{volume_name}' saved to {JUNKDRIVES_FILE}.", verbose)
    else:
         print_verbose(f"Updated metadata (scan time, usage, prefix counts) for '{volume_name}' in {JUNKDRIVES_FILE}.", verbose)


    # 7. Log the scan event
    status = "COMPLETED"
    if is_new:
        status += " (New Drive)"
    elif archived:
        status += " (Change Detected)"
    else:
         status += " (No Change)"

    log_event(f"SCAN {status}: Volume: {volume_name}, Path: {volume_path}, ScanID: {scan_id}, Hash: {content_hash}")
    print(f"Scan {status.lower()} for volume '{volume_name}'.")
    return True # Indicate success

def list_drives(verbose=True):
    """Lists the volumes tracked in junkdrives.json."""
    print("--- Tracked Drives ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)
    if not junk_drives_data:
        print("No drives tracked yet.")
        return
    for i, volume_name in enumerate(sorted(junk_drives_data.keys()), 1):
        last_scan_time = junk_drives_data[volume_name].get("scan_time", "N/A")
        print(f"{i}. {volume_name} (Last Scan: {last_scan_time})")

def list_scans(volume_filter=None, verbose=True):
    """Lists scan events from scan.log, optionally filtering by volume name."""
    print(f"--- Scan Log ({LOG_FILE}) ---")
    if not LOG_FILE.exists():
        print("Scan log file not found.")
        return
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            scan_count = 0
            displayed_count = 0
            log_lines = f.readlines() # Read all lines first

            print_verbose(f"Read {len(log_lines)} lines from log file.", verbose)

            # Iterate in reverse to show newest first
            for line in reversed(log_lines):
                scan_count +=1
                line = line.strip()
                if not line:
                    continue

                # Basic filtering
                display_this_line = False
                if volume_filter:
                    # Make filter check slightly more robust (e.g., "Volume: <name>,", "Volume: <name} ")
                    if f"Volume: {volume_filter}," in line or f"Volume: {volume_filter} " in line:
                         display_this_line = True
                else: # No filter, display all
                    display_this_line = True

                if display_this_line:
                    print(line)
                    displayed_count += 1

            if displayed_count == 0:
                 if volume_filter:
                     print(f"No scan log entries found matching volume '{volume_filter}'.")
                 else:
                     print("Scan log is empty or contains no valid entries.")
            elif volume_filter and displayed_count > 0 :
                 print(f"\nDisplayed {displayed_count} log entries for volume '{volume_filter}'.")
            else: # No filter, displayed all
                 print(f"\nDisplayed {displayed_count} total log entries.")

    except IOError as e:
        print_error(f"Could not read log file {LOG_FILE}: {e}")

def list_archives(volume_filter, verbose=True):
    """Lists archived scan records for a specific volume."""
    print(f"--- Archive Records for Volume: {volume_filter} ---")
    archive_data = load_json_data(ARCHIVE_FILE)

    if volume_filter not in archive_data or not archive_data[volume_filter]:
        print(f"No archive records found for volume '{volume_filter}'.")
        return

    volume_archives = archive_data[volume_filter]
    print(f"Found {len(volume_archives)} archive entries.")
    for i, record in enumerate(reversed(volume_archives), 1): # Show newest archived record first
        scan_id = record.get("scan_id", "N/A")
        scan_time = record.get("scan_time", "N/A")
        content_hash = record.get("content_hash", "N/A")[:10] # Show partial hash
        print(f"\nArchive Entry {i} (Oldest is #{len(volume_archives)}):")
        print(f"  Scan ID: {scan_id}")
        print(f"  Scan Time: {scan_time}")
        print(f"  Content Hash: {content_hash}...")
        if verbose: # Show more details if verbose
             dirs = record.get('top_level_dirs', [])
             files = record.get('top_level_file_types', {})
             usage = record.get('disk_usage_bytes', -1)
             print(f"  Dirs: {len(dirs)}")
             print(f"  File Types: {len(files)}")
             print(f"  Disk Usage (bytes): {usage if usage != -1 else 'N/A'}")
        # print("-" * 10) # Removed for slightly cleaner output


def manage_tags(volume_names_str, tags_str, remove_tags=False, verbose=True):
    """Adds or removes tags for specified volumes."""
    print(f"--- Managing Tags ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)

    if not volume_names_str or not tags_str:
        print_error("Both --volume and --tags arguments are required.")
        return

    # Split and clean input volume names and tags
    target_volume_names = {name.strip() for name in volume_names_str.split(',') if name.strip()}
    # Normalize tags to lowercase and store unique ones
    target_tags = {tag.strip().lower() for tag in tags_str.split(',') if tag.strip()}

    if not target_volume_names:
        print_error("No valid volume names provided.")
        return
    if not target_tags:
        print_error("No valid tags provided.")
        return

    action = "Removing" if remove_tags else "Adding"
    print(f"{action} tags {sorted(list(target_tags))} for volumes: {sorted(list(target_volume_names))}")

    made_changes = False
    processed_volumes = set()

    for volume_name in target_volume_names:
        if volume_name not in junk_drives_data:
            print_error(f"Volume '{volume_name}' not found in tracked data. Skipping.")
            continue

        processed_volumes.add(volume_name)
        scan_data = junk_drives_data[volume_name]

        # Get current tags, ensure it's a list, handle potential non-list data if file was manually edited
        current_tags_list = scan_data.get("tags", [])
        if not isinstance(current_tags_list, list):
             print_verbose(f"Warning: Existing 'tags' for {volume_name} is not a list. Resetting.", verbose)
             current_tags_set = set()
        else:
             # Normalize existing tags to lowercase set for easier processing
             current_tags_set = {tag.lower() for tag in current_tags_list}

        original_tags_set = current_tags_set.copy() # Keep track for change detection

        if remove_tags:
            current_tags_set.difference_update(target_tags) # Remove target tags
            action_desc = "removed"
        else:
            current_tags_set.update(target_tags) # Add target tags (set handles uniqueness)
            action_desc = "added"

        # Check if changes were actually made
        if current_tags_set != original_tags_set:
             # Store as a sorted list
             scan_data["tags"] = sorted(list(current_tags_set))
             made_changes = True
             print_verbose(f"Tags {action_desc} for volume '{volume_name}'. New tags: {scan_data['tags']}", verbose)
        else:
             print_verbose(f"No tag changes needed for volume '{volume_name}'.", verbose)

    if not processed_volumes:
         print("No matching volumes found in tracked data to update.")
         return # No need to save if no volumes were processed

    if made_changes:
        save_json_data(JUNKDRIVES_FILE, junk_drives_data)
        print(f"Successfully updated tags in {JUNKDRIVES_FILE}.")
    else:
        print("No changes were made to tags.")


def list_all_tags(verbose=True):
    """Lists all unique tags found across all tracked volumes."""
    print("--- Listing All Unique Tags ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)
    all_tags = set()

    if not junk_drives_data:
        print(f"No scan data found in {JUNKDRIVES_FILE}.")
        return

    for volume_name, scan_data in junk_drives_data.items():
        tags_list = scan_data.get("tags", [])
        if isinstance(tags_list, list):
             # Normalize to lowercase when collecting
             for tag in tags_list:
                 all_tags.add(tag.lower())
        elif tags_list: # If tags field exists but isn't a list
             print_verbose(f"Warning: Invalid 'tags' data found for volume '{volume_name}'. Skipping.", verbose)


    if not all_tags:
        print("No tags found for any volume.")
    else:
        print("Unique tags found (lowercase):")
        for tag in sorted(list(all_tags)):
            print(f"- {tag}")
    print("--- End Tag List ---")


def show_volumes_by_tag(target_tag, verbose=True):
    """Shows volumes associated with a specific tag."""
    if not target_tag:
        print_error("No tag specified.")
        return

    target_tag = target_tag.strip().lower() # Normalize input tag
    print(f"--- Showing Volumes with Tag: '{target_tag}' ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)
    found_volumes = []

    if not junk_drives_data:
        print(f"No scan data found in {JUNKDRIVES_FILE}.")
        return

    for volume_name, scan_data in junk_drives_data.items():
        tags_list = scan_data.get("tags", [])
        if isinstance(tags_list, list):
             # Check against normalized lowercase tags
             normalized_tags = {tag.lower() for tag in tags_list}
             if target_tag in normalized_tags:
                 found_volumes.append(volume_name)
        elif tags_list:
             print_verbose(f"Warning: Invalid 'tags' data found for volume '{volume_name}'. Skipping.", verbose)

    if not found_volumes:
        print(f"No volumes found with the tag '{target_tag}'.")
    else:
        print(f"Volumes associated with tag '{target_tag}':")
        for volume_name in sorted(found_volumes):
            print(f"- {volume_name}")
    print("--- End Volume List ---")

def list_folders(verbose=True):
    """Lists all unique top-level folder names found across tracked drives."""
    print("--- Tracked Top-Level Folders ---")
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)

    if not junk_drives_data:
        print(f"No scan data found in {JUNKDRIVES_FILE} to check.")
        return

    # Dictionary to map folder names to a set of volumes they appear on
    folder_to_volumes = {}

    for volume_name, scan_data in junk_drives_data.items():
        folder_list = scan_data.get("top_level_dirs") # Get the list of directories

        if folder_list and isinstance(folder_list, list):
            for folder_name in folder_list:
                if folder_name not in folder_to_volumes:
                    # Use a set for volumes to automatically handle duplicates
                    folder_to_volumes[folder_name] = set()
                folder_to_volumes[folder_name].add(volume_name)
        elif folder_list: # Exists but isn't a list
             print_verbose(f"Warning: Invalid 'top_level_dirs' data found for volume '{volume_name}'. Skipping.", verbose)

    if not folder_to_volumes:
        print("No top-level folders found in any scan data.")
    else:
        # Sort folders alphabetically for output
        for folder_name in sorted(folder_to_volumes.keys()):
            # Get the set of volumes, convert to sorted list for display
            volume_list = sorted(list(folder_to_volumes[folder_name]))

            # --- Apply color to the volume list part ---
            volume_list_str = f"({', '.join(volume_list)})"
            print(f"{folder_name} {COLOR_GRAY}{volume_list_str}{COLOR_RESET}")
            # --- End color application ---

    print("\n--- End Folder List ---")


def handle_default_action(target_os, verbose=True, dry_run=False, scan_untracked=False):
    """Detects volumes, lists status/dry-run data, and optionally scans untracked."""
    # (Keep the volume detection logic the same)
    print("Checking for connected volumes...")
    detected_volumes = detect_mounted_volumes(target_os, verbose)

    if not detected_volumes:
        print("No external volumes detected or accessible.")
        return

    # --- Dry Run Logic ---
    if dry_run:
        print("\n--- DRY RUN MODE (Auto-Detected Volumes) ---")
        print("Showing data that would be hashed for each detected volume:")
        any_failed = False
        for name, path in detected_volumes.items():
            print(f"\n--- Dry Run for: {name} ({path}) ---")
            listing_details = get_dir_listing_details(path, target_os, verbose)
            if listing_details is not None:
                pprint.pprint(listing_details)
            else:
                print_error(f"Could not get listing details for {name}.")
                any_failed = True
        print("\n--- END DRY RUN ---")
        if any_failed:
            print("Note: Some volumes failed during dry run listing.")
        return # Stop here for dry run

    # --- Normal Detection Logic (if not dry_run) ---
    junk_drives_data = load_json_data(JUNKDRIVES_FILE)
    tracked_names = junk_drives_data.keys()
    untracked_volumes_to_scan_paths = []

    print("\n--- Detected Volumes ---")
    for name, path in detected_volumes.items():
        if name in tracked_names:
            print(f"{COLOR_GREEN}[Tracked]   {name}{COLOR_RESET} ({path})")
        else:
            print(f"{COLOR_ORANGE}[Untracked] {name}{COLOR_RESET} ({path})")
            untracked_volumes_to_scan_paths.append(path) # Store path

    # --- Scan Untracked Logic ---
    if scan_untracked:
        if untracked_volumes_to_scan_paths:
            print(f"\nFound {len(untracked_volumes_to_scan_paths)} untracked volume(s). Starting scan (--scan-untracked specified)...")
            success_count = 0
            fail_count = 0
            for path in untracked_volumes_to_scan_paths:
                # Scans triggered here are never dry runs
                if perform_scan(path, target_os, verbose, dry_run=False):
                    success_count += 1
                else:
                    fail_count += 1
            print(f"\nScan summary: {success_count} succeeded, {fail_count} failed.")
        else:
            print("\nNo untracked volumes found to scan.")
    elif untracked_volumes_to_scan_paths:
        # If untracked volumes exist but --scan-untracked wasn't used
        print("\nNote: Untracked volumes detected. Use 'detect --scan-untracked' to scan them.")
    else:
        # All detected are tracked and --scan-untracked wasn't relevant
        print("\nAll detected volumes are already tracked.")

# --- Main Execution ---
def main():
    # Determine default OS based on the system running the script
    system_os = platform.system().lower()
    if system_os == 'darwin':
        default_os_profile = 'macos'
    elif system_os == 'linux':
        default_os_profile = 'linux'
    elif system_os == 'windows':
        default_os_profile = 'windows'
    else:
        default_os_profile = 'macos' # Fallback default

    parser = argparse.ArgumentParser(
        description="JunkStick: Scan and catalog flash drive contents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python junkstick.py                    # Auto-detect volumes, list status
  python junkstick.py detect --scan-untracked # Detect and scan untracked drives
  python junkstick.py scan --volume /Volumes/MyUSB
  python junkstick.py show-scan          # Show latest data for connected tracked drives
  python junkstick.py report-prefixes    # Show prefix counts for all tracked drives
  python junkstick.py check-duplicates   # Check for identical content hashes
  python junkstick.py list-drives
  python junkstick.py list-folders       # List all unique top-level folders found
  python junkstick.py list-tags          # List all unique tags used
  python junkstick.py tag --volume Vol1,Vol2 --tags project-x,client-y # Add tags
  python junkstick.py tag --volume Vol1 --tags backup --remove      # Remove a tag
  python junkstick.py show-volumes-by-tag --tag project-x            # Find volumes with a tag
"""
    )


    # --- Global options ---
    # Keep only truly global flags here
    parser.add_argument(
        '--os',
        choices=SUPPORTED_OS,
        default=default_os_profile,
        help=f"Specify the operating system profile (default: {default_os_profile}). Affects detection and some commands."
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose output (applies globally)."
    )

    # --- Subparsers ---
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # --- Scan command ---
    parser_scan = subparsers.add_parser('scan', help='Scan a specified volume.')
    parser_scan.add_argument(
        '--volume',
        required=True, # Volume is required for scan
        help="Path to the volume/drive to scan."
    )
    parser_scan.add_argument(
        '--dry-run',
        action='store_true',
        help="Perform a dry run (show data to be hashed) instead of a full scan."
    )

    # --- Detect command ---
    # This makes handling --dry-run for detection cleaner
    parser_detect = subparsers.add_parser('detect', help='Detect volumes, list status, or perform dry run on all.')
    parser_detect.add_argument(
        '--dry-run',
        action='store_true',
        help="Perform dry run listing for all detected volumes instead of showing status."
    )
    parser_detect.add_argument(
        '--scan-untracked', # Add flag to explicitly scan untracked ones
        action='store_true',
        help="Scan any detected volumes that are not currently tracked."
    )


    # --- List drives command ---
    parser_list_drives = subparsers.add_parser('list-drives', help='List all tracked drives.')
    # No specific args needed

    # --- List scans command ---
    parser_list_scans = subparsers.add_parser('list-scans', help='List scan history from the log (newest first).')
    parser_list_scans.add_argument(
        '--volume', # Allow filtering by volume
        required=False,
        help="Filter scan history by volume name/path."
    )

    # --- List archives command ---
    parser_list_archives = subparsers.add_parser('list-archives', help='List archived scans for a specific drive (newest first).')
    parser_list_archives.add_argument(
        '--volume', # Require volume for filtering archives
        required=True,
        help="Specify the volume name/path to list archives for."
    )

    # --- Show Scan command ---
    parser_show_scan = subparsers.add_parser('show-scan', help='Show latest scan data for currently connected & tracked drives.')
    # No specific arguments for now

    # --- Check Duplicates command ---
    parser_check_duplicates = subparsers.add_parser('check-duplicates', help='Check for drives with identical content hashes in latest scan.')
 
    # --- Report Prefixes command ---
    parser_report_prefixes = subparsers.add_parser('report-prefixes', help='Report custom prefix counts for all tracked drives.')

    # --- Tag command ---
    parser_tag = subparsers.add_parser('tag', help='Add or remove tags for specific volumes.')
    parser_tag.add_argument(
        '--volume',
        required=True,
        dest='volume_names_str', # Use specific dest to avoid conflict if needed
        help='Comma-separated list of volume names to tag.'
    )
    parser_tag.add_argument(
        '--tags',
        required=True,
        dest='tags_str',
        help='Comma-separated list of tags to add or remove (case-insensitive).'
    )
    parser_tag.add_argument(
        '--remove',
        action='store_true',
        dest='remove_tags',
        help='Remove the specified tags instead of adding them.'
    )

    # --- List Tags command ---
    parser_list_tags = subparsers.add_parser('list-tags', help='List all unique tags currently used.')
    # No specific arguments

    # --- Show Volumes by Tag command ---
    parser_show_volumes = subparsers.add_parser('show-volumes-by-tag', help='Show volumes associated with a specific tag.')
    parser_show_volumes.add_argument(
        '--tag',
        required=True,
        dest='target_tag',
        help='The specific tag (case-insensitive) to search for.'
    )

    # --- List Folders command ---
    parser_list_folders = subparsers.add_parser('list-folders', help='List all unique top-level folders found across tracked drives.')



    args = parser.parse_args()

    # --- Command Dispatch ---
    is_verbose = args.verbose

    if args.command == 'scan':
        perform_scan(args.volume, args.os, is_verbose, args.dry_run)
    elif args.command == 'detect':
        handle_default_action(args.os, is_verbose, args.dry_run, args.scan_untracked)
    elif args.command == 'show-scan':
        show_scan_data(args.os, is_verbose)
    elif args.command == 'check-duplicates':
        check_duplicates(is_verbose)
    elif args.command == 'report-prefixes':
        report_prefix_counts(is_verbose)
    elif args.command == 'tag': 
        manage_tags(args.volume_names_str, args.tags_str, args.remove_tags, is_verbose)
    elif args.command == 'list-tags': 
        list_all_tags(is_verbose)
    elif args.command == 'show-volumes-by-tag':
        show_volumes_by_tag(args.target_tag, is_verbose)
    elif args.command == 'list-drives':
        list_drives(is_verbose)
    elif args.command == 'list-folders':
        list_folders(is_verbose)
    elif args.command == 'list-scans':
        filter_volume = args.volume if hasattr(args, 'volume') else None
        list_scans(filter_volume, is_verbose)
    elif args.command == 'list-archives':
         list_archives(args.volume, is_verbose)
    elif args.command is None:
         # No command was given - run default detect action
         print("No command specified. Running volume detection (use 'detect --scan-untracked' to also scan new drives)...")
         handle_default_action(args.os, is_verbose, dry_run=False, scan_untracked=False)
    else:
         parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()