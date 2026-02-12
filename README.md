# 🚨 Slop Alert 🚨

Everything after this section in the README was AI generated with one prompt and will destroy your data.

It's provided AS-IS with NO WARRANTY OF ANY KIND.

It's purpose was to take a recovered file directory containing recovered data from a data carving tool like
foremost or PhotoRec, and combine it with a file listing created by the free version of DMDE, which I refuse to
pay for. By matching file sizes and extensions of the listing with the actual recovered data, you recreate the
file structure of recovered data without paying for professional grade software.

# File Recovery Renaming Script

A Python script to identify and organize recovered files from a failed hard drive by matching file sizes and extensions with a file listing.

## Overview

This script matches recovered files (with generic names like `f12345.doc`) to their original filenames by:
1. Parsing a file listing that contains original filenames, sizes, and extensions
2. Scanning recovered files and extracting their metadata
3. Matching files based on size and extension
4. Organizing files into categories based on match confidence
5. Generating detailed reports and statistics

## Features

- **Exact Matching**: Files with unique size+extension combinations are confidently identified
- **Ambiguous Handling**: Files with multiple possible matches are separated with metadata
- **Unidentified Tracking**: Files without matches are organized by extension
- **Path Preservation**: Original directory structure is maintained where possible
- **Safety First**: Only copies files, never moves or deletes
- **Comprehensive Reports**: Generates summary, detailed CSV, and JSON reports
- **Dry Run Mode**: Preview actions before executing
- **Type Safety**: Full type hints using Python's typing module

## Requirements

- Python 3.7 or higher
- Standard library only (no external dependencies)

## Usage

### Basic Usage

```bash
python3 file_recovery.py
```

This will:
- Read from `raw/filelist.txt`
- Scan files in `raw/` directory
- Output organized files to `recovered/` directory
- Generate reports

### Options

```bash
# Preview actions without copying files
python3 file_recovery.py --dry-run

# Enable verbose logging for debugging
python3 file_recovery.py --verbose

# Specify custom directories
python3 file_recovery.py --raw-dir /path/to/raw --output-dir /path/to/output

# Combine options
python3 file_recovery.py --dry-run --verbose
```

### Command-Line Arguments

- `--dry-run`: Preview actions without copying files
- `--verbose, -v`: Enable detailed logging output
- `--raw-dir PATH`: Path to raw directory (default: `raw`)
- `--output-dir PATH`: Path to output directory (default: `recovered`)
- `--help, -h`: Show help message

## Output Structure

The script creates the following directory structure:

```
recovered/
├── identified/                    # Files with exact matches (single match)
│   ├── 2013/                     # Original directory structure preserved
│   │   └── filename.doc
│   ├── Reports/
│   │   └── report.xlsx
│   └── doc/                      # Files without path (flat structure)
│       └── single_file.doc
│
├── ambiguous/                    # Files with multiple possible matches
│   ├── by_extension/
│   │   ├── doc/
│   │   ├── pdf/
│   │   └── ...
│   └── metadata.json            # Lists all possible matches for each file
│
├── unidentified/                # Files with no matches
│   ├── doc/
│   ├── pdf/
│   └── ...
│
├── summary.txt                  # Human-readable summary report
├── detailed_report.csv          # Detailed CSV with all matches
└── report.json                  # Machine-readable JSON report
```

## Reports

### Summary Report (summary.txt)

Human-readable text file with:
- Overall statistics (total files, match rates)
- Breakdown by extension
- Success/error counts

### Detailed CSV Report (detailed_report.csv)

Spreadsheet-compatible format with columns:
- Recovered Filename
- File Size
- Extension
- Confidence (exact/ambiguous/none)
- Match Count
- Matched Filename(s)
- Original Path(s)

### JSON Report (report.json)

Machine-readable format containing:
- Timestamp
- Statistics
- Complete match details for all files
- Suitable for further processing or integration

### Ambiguous Metadata (ambiguous/metadata.json)

For files with multiple possible matches, contains:
- Recovered filename
- Size and extension
- List of all possible original filenames with paths and timestamps

## How It Works

### 1. File List Parsing

The script parses `filelist.txt` which should be in the format:

```
YYYY-MM-DD HH:MM:SS.mmm    SIZE   FLAGS  path\to\filename.ext
```

It creates an index mapping `(size, extension)` to original file metadata.

### 2. File Scanning

Recursively scans the `raw/` directory for recovered files, extracting:
- File path
- File size
- Extension

### 3. Matching

For each recovered file:
- Looks up `(size, extension)` in the index
- **Exact match**: One file in list → high confidence
- **Ambiguous**: Multiple files → needs review
- **No match**: Not in list → unidentified

### 4. Organization

Files are copied (not moved) to appropriate directories:
- **Exact matches**: Preserve original path structure when available
- **Ambiguous matches**: Group by extension with metadata file
- **Unidentified**: Group by extension

### 5. Report Generation

Creates multiple report formats for analysis and verification.

## Notes and Best Practices

### CHK Files

The script automatically ignores `.CHK` files created by `chkdsk` as these are typically corrupted or system files.

### File Safety

- Files are always **copied**, never moved or deleted
- Original recovered files in `raw/` remain untouched
- Dry run mode available for preview
- Filename conflicts are handled by adding numeric suffixes

### Match Confidence

- **Exact (15-25% typical)**: Single matching file in list - safe to use
- **Ambiguous (5-15% typical)**: Multiple matches - review metadata.json
- **Unidentified (60-80% typical)**: Not in file list - may be system files, temp files, or corrupted entries

### Path Preservation

The script attempts to preserve the original directory structure:
- Volume and cluster information is removed (`$Volume 01`, `$Root`, `$F00010`)
- Clean paths are created (e.g., `2013/Reports/file.doc`)
- Files without directory structure go to `extension/` subdirectories

### Performance

- Processes thousands of files in seconds
- Uses efficient indexing for O(1) lookups
- Memory usage scales with file list size, not file contents

## Troubleshooting

### "File list not found"

Ensure `filelist.txt` exists in the raw directory.

### "No recovered files found"

Check that:
- Files exist in the raw directory
- Files have extensions
- Files aren't all `.CHK` files

### Files going to "unidentified"

This is normal for:
- System files (Thumbs.db, desktop.ini)
- Temporary files
- Files not in the file listing
- Files created after the listing was generated
- Corrupted file entries

### High ambiguous rate

Common reasons:
- Many files with same size (e.g., default document templates)
- Use `metadata.json` to manually review and choose correct files
- Consider file timestamps if available

## Example Session

```bash
$ python3 file_recovery.py --dry-run
2026-02-12 10:11:45 - INFO - DRY RUN MODE - No files will be copied
2026-02-12 10:11:45 - INFO - Step 1: Parsing file list...
2026-02-12 10:11:45 - INFO - Processed 5565 lines, parsed 2553 files
2026-02-12 10:11:45 - INFO - Step 2: Scanning recovered files...
2026-02-12 10:11:45 - INFO - Found 4230 recovered files
2026-02-12 10:11:45 - INFO - Step 3: Matching files...
2026-02-12 10:11:45 - INFO - Matching complete: 644 exact, 409 ambiguous, 3177 unidentified
2026-02-12 10:11:52 - INFO - COMPLETED SUCCESSFULLY

============================================================
RECOVERY COMPLETE
============================================================
Total files: 4230
Identified (exact match): 644 (15.2%)
Ambiguous (multiple matches): 409 (9.7%)
Unidentified: 3177 (75.1%)

Output directory: recovered
  - Identified files: recovered/identified
  - Ambiguous files: recovered/ambiguous
  - Unidentified files: recovered/unidentified
```

## License

This script is provided as-is for data recovery purposes.

## Technical Details

### Architecture

The script uses a modular object-oriented design:

- `FileMetadata`: Dataclass for file listing entries
- `RecoveredFile`: Dataclass for scanned files
- `MatchResult`: Dataclass for match results
- `FileListParser`: Parses the file listing
- `FileScanner`: Scans recovered files
- `FileMatcher`: Matches files by size+extension
- `FileOrganizer`: Copies files to output structure
- `ReportGenerator`: Creates reports

### Type Safety

Full type hints throughout:
- All function parameters and return types annotated
- Dataclasses for structured data
- Type checking compatible with mypy

### Error Handling

- Encoding errors handled (uses `errors='ignore'` for malformed paths)
- File operation errors logged and counted
- Keyboard interrupt handled gracefully
- Detailed error messages with context
