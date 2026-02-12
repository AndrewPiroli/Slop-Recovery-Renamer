#!/usr/bin/env python3
"""
File Recovery Script for HDD Data Recovery

This script matches recovered files (with generic names) to their original filenames
by comparing file sizes and extensions from a file listing.

Usage:
    python file_recovery.py [--dry-run] [--verbose]
"""

import argparse
import csv
import json
import logging
import re
import shutil
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime


@dataclass
class FileMetadata:
    """Metadata for a file from the listing."""
    original_path: str
    filename: str
    size: int
    extension: str
    timestamp: Optional[str] = None
    
    def get_sanitized_path(self) -> str:
        """Get sanitized path suitable for filesystem."""
        # Remove volume prefix and clean up path
        path = self.original_path
        
        # Remove volume information (e.g., "$Volume 01 - FAT 2\")
        if '\\' in path:
            parts = path.split('\\')
            # Skip volume and root parts
            cleaned_parts = []
            skip_next = False
            for part in parts:
                # Skip volume definitions
                if part.startswith('$Volume'):
                    continue
                # Skip $Root
                if part == '$Root':
                    continue
                # Skip cluster folders like $F00010
                if re.match(r'\$F\d+$', part):
                    continue
                cleaned_parts.append(part)
            
            path = '/'.join(cleaned_parts)
        
        # Remove leading/trailing slashes
        path = path.strip('/')
        
        return path


@dataclass
class RecoveredFile:
    """Metadata for a recovered file."""
    path: Path
    size: int
    extension: str
    relative_path: Path


@dataclass
class MatchResult:
    """Result of matching a recovered file."""
    recovered_file: RecoveredFile
    matched_files: List[FileMetadata]
    confidence: str  # 'exact', 'ambiguous', 'none'
    
    def __post_init__(self):
        """Validate confidence level."""
        if self.confidence not in ('exact', 'ambiguous', 'none'):
            raise ValueError(f"Invalid confidence: {self.confidence}")


class FileListParser:
    """Parser for the file listing from data recovery software."""
    
    # Pattern to match file entries (not directories)
    FILE_PATTERN = re.compile(
        r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'  # timestamp
        r'(\d+)\s+'  # size
        r'[^\s]+\s+'  # flags
        r'[^\s]+\s+'  # more flags
        r'f\s+'  # file indicator
        r'(.+)$'  # path
    )
    
    def __init__(self, filelist_path: Path):
        """Initialize parser with path to filelist.txt."""
        self.filelist_path = filelist_path
        self.logger = logging.getLogger(__name__)
    
    def parse(self) -> Dict[Tuple[int, str], List[FileMetadata]]:
        """
        Parse the file listing and create an index.
        
        Returns:
            Dictionary mapping (size, extension) to list of FileMetadata
        """
        index: Dict[Tuple[int, str], List[FileMetadata]] = defaultdict(list)
        files_parsed = 0
        lines_processed = 0
        
        self.logger.info(f"Parsing file list: {self.filelist_path}")
        
        try:
            with open(self.filelist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    lines_processed += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # Skip directory entries
                    if '<DIR>' in line:
                        continue
                    
                    # Try to match file pattern
                    match = self.FILE_PATTERN.match(line)
                    if not match:
                        continue
                    
                    timestamp, size_str, filepath = match.groups()
                    
                    # Skip CHK files
                    if filepath.upper().endswith('.CHK'):
                        continue
                    
                    # Extract filename and extension
                    filename = filepath.split('\\')[-1]
                    
                    # Get extension (handle files without extension)
                    if '.' in filename:
                        extension = filename.split('.')[-1].lower()
                    else:
                        extension = ''
                    
                    # Skip files with no extension or temporary files
                    if not extension or filename.startswith('~'):
                        continue
                    
                    size = int(size_str)
                    
                    # Skip zero-size files
                    if size == 0:
                        continue
                    
                    # Create metadata
                    metadata = FileMetadata(
                        original_path=filepath,
                        filename=filename,
                        size=size,
                        extension=extension,
                        timestamp=timestamp
                    )
                    
                    # Add to index
                    key = (size, extension)
                    index[key].append(metadata)
                    files_parsed += 1
        
        except Exception as e:
            self.logger.error(f"Error parsing file list: {e}")
            raise
        
        self.logger.info(f"Processed {lines_processed} lines, parsed {files_parsed} files")
        self.logger.info(f"Created index with {len(index)} unique (size, extension) combinations")
        
        return index


class FileScanner:
    """Scanner for recovered files in the raw directory."""
    
    def __init__(self, raw_dir: Path):
        """Initialize scanner with raw directory path."""
        self.raw_dir = raw_dir
        self.logger = logging.getLogger(__name__)
    
    def scan(self) -> List[RecoveredFile]:
        """
        Scan the raw directory for recovered files.
        
        Returns:
            List of RecoveredFile objects
        """
        recovered_files: List[RecoveredFile] = []
        
        self.logger.info(f"Scanning directory: {self.raw_dir}")
        
        # Skip the filelist.txt itself
        for file_path in self.raw_dir.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip filelist.txt
            if file_path.name == 'filelist.txt':
                continue
            
            # Skip CHK files
            if file_path.suffix.upper() == '.CHK':
                continue
            
            # Get file info
            size = file_path.stat().st_size
            extension = file_path.suffix.lstrip('.').lower()
            
            # Skip files without extension
            if not extension:
                continue
            
            # Get relative path from raw directory
            relative_path = file_path.relative_to(self.raw_dir)
            
            recovered = RecoveredFile(
                path=file_path,
                size=size,
                extension=extension,
                relative_path=relative_path
            )
            
            recovered_files.append(recovered)
        
        self.logger.info(f"Found {len(recovered_files)} recovered files")
        
        return recovered_files


class FileMatcher:
    """Matches recovered files to original filenames using size and extension."""
    
    def __init__(self, file_index: Dict[Tuple[int, str], List[FileMetadata]]):
        """Initialize matcher with file index."""
        self.file_index = file_index
        self.logger = logging.getLogger(__name__)
    
    def match(self, recovered_files: List[RecoveredFile]) -> List[MatchResult]:
        """
        Match recovered files to original filenames.
        
        Returns:
            List of MatchResult objects
        """
        results: List[MatchResult] = []
        
        exact_matches = 0
        ambiguous_matches = 0
        no_matches = 0
        
        self.logger.info(f"Matching {len(recovered_files)} recovered files")
        
        for recovered in recovered_files:
            key = (recovered.size, recovered.extension)
            matched_files = self.file_index.get(key, [])
            
            if len(matched_files) == 1:
                confidence = 'exact'
                exact_matches += 1
            elif len(matched_files) > 1:
                confidence = 'ambiguous'
                ambiguous_matches += 1
            else:
                confidence = 'none'
                no_matches += 1
            
            result = MatchResult(
                recovered_file=recovered,
                matched_files=matched_files,
                confidence=confidence
            )
            
            results.append(result)
        
        self.logger.info(f"Matching complete: {exact_matches} exact, "
                        f"{ambiguous_matches} ambiguous, {no_matches} unidentified")
        
        return results


class FileOrganizer:
    """Organizes matched files into output directory structure."""
    
    def __init__(self, output_dir: Path, dry_run: bool = False):
        """Initialize organizer with output directory."""
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)
        
        # Create output directory structure
        self.identified_dir = output_dir / 'identified'
        self.ambiguous_dir = output_dir / 'ambiguous'
        self.unidentified_dir = output_dir / 'unidentified'
    
    def organize(self, match_results: List[MatchResult]) -> Dict[str, int]:
        """
        Organize files based on match results.
        
        Returns:
            Statistics dictionary
        """
        stats = {
            'exact_copied': 0,
            'ambiguous_copied': 0,
            'unidentified_copied': 0,
            'errors': 0
        }
        
        # Store ambiguous file metadata
        ambiguous_metadata: List[Dict] = []
        
        for result in match_results:
            try:
                if result.confidence == 'exact':
                    self._copy_exact_match(result)
                    stats['exact_copied'] += 1
                
                elif result.confidence == 'ambiguous':
                    self._copy_ambiguous_match(result, ambiguous_metadata)
                    stats['ambiguous_copied'] += 1
                
                else:  # no match
                    self._copy_unidentified(result)
                    stats['unidentified_copied'] += 1
            
            except Exception as e:
                self.logger.error(f"Error processing {result.recovered_file.path}: {e}")
                stats['errors'] += 1
        
        # Write ambiguous metadata file
        if ambiguous_metadata and not self.dry_run:
            metadata_file = self.ambiguous_dir / 'metadata.json'
            metadata_file.parent.mkdir(parents=True, exist_ok=True)
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(ambiguous_metadata, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Wrote ambiguous metadata to {metadata_file}")
        
        return stats
    
    def _copy_exact_match(self, result: MatchResult) -> None:
        """Copy file with exact match to identified directory."""
        matched = result.matched_files[0]
        recovered = result.recovered_file
        
        # Get sanitized path
        sanitized_path = matched.get_sanitized_path()
        
        # Create output path preserving directory structure
        if '/' in sanitized_path:
            output_path = self.identified_dir / sanitized_path
        else:
            # Fallback to extension-based directory
            output_path = self.identified_dir / recovered.extension / matched.filename
        
        self._copy_file(recovered.path, output_path)
    
    def _copy_ambiguous_match(self, result: MatchResult, metadata_list: List[Dict]) -> None:
        """Copy file with ambiguous matches to ambiguous directory."""
        recovered = result.recovered_file
        
        # Copy to ambiguous directory organized by extension
        output_path = self.ambiguous_dir / 'by_extension' / recovered.extension / recovered.path.name
        
        self._copy_file(recovered.path, output_path)
        
        # Add metadata entry
        metadata_entry = {
            'recovered_filename': str(recovered.path.name),
            'size': recovered.size,
            'extension': recovered.extension,
            'possible_matches': [
                {
                    'filename': m.filename,
                    'original_path': m.original_path,
                    'timestamp': m.timestamp
                }
                for m in result.matched_files
            ]
        }
        metadata_list.append(metadata_entry)
    
    def _copy_unidentified(self, result: MatchResult) -> None:
        """Copy unidentified file to unidentified directory."""
        recovered = result.recovered_file
        
        # Copy to unidentified directory organized by extension
        output_path = self.unidentified_dir / recovered.extension / recovered.path.name
        
        self._copy_file(recovered.path, output_path)
    
    def _copy_file(self, src: Path, dst: Path) -> None:
        """Copy file from source to destination, preserving metadata."""
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would copy: {src} -> {dst}")
            return
        
        # Create parent directory
        dst.parent.mkdir(parents=True, exist_ok=True)
        
        # Handle filename conflicts
        if dst.exists():
            # Add counter to filename
            counter = 1
            while True:
                stem = dst.stem
                suffix = dst.suffix
                new_dst = dst.parent / f"{stem}_{counter}{suffix}"
                if not new_dst.exists():
                    dst = new_dst
                    break
                counter += 1
            self.logger.warning(f"File exists, using: {dst.name}")
        
        # Copy file preserving metadata
        shutil.copy2(src, dst)
        self.logger.debug(f"Copied: {src} -> {dst}")


class ReportGenerator:
    """Generates detailed reports and statistics."""
    
    def __init__(self, output_dir: Path):
        """Initialize report generator."""
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
    
    def generate_reports(self, match_results: List[MatchResult], stats: Dict[str, int]) -> None:
        """Generate summary and detailed reports."""
        self.logger.info("Generating reports...")
        
        # Generate summary report
        self._generate_summary(stats, match_results)
        
        # Generate detailed CSV report
        self._generate_detailed_csv(match_results)
        
        # Generate JSON report
        self._generate_json_report(match_results, stats)
    
    def _generate_summary(self, stats: Dict[str, int], match_results: List[MatchResult]) -> None:
        """Generate summary report."""
        summary_path = self.output_dir / 'summary.txt'
        
        total_files = len(match_results)
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("FILE RECOVERY SUMMARY REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n")
            
            f.write("STATISTICS:\n")
            f.write("-" * 60 + "\n")
            f.write(f"Total files processed: {total_files}\n")
            f.write(f"Exact matches (identified): {stats['exact_copied']} "
                   f"({stats['exact_copied']/total_files*100:.1f}%)\n")
            f.write(f"Ambiguous matches: {stats['ambiguous_copied']} "
                   f"({stats['ambiguous_copied']/total_files*100:.1f}%)\n")
            f.write(f"Unidentified files: {stats['unidentified_copied']} "
                   f"({stats['unidentified_copied']/total_files*100:.1f}%)\n")
            f.write(f"Errors: {stats['errors']}\n")
            f.write("\n")
            
            # Extension breakdown
            f.write("BREAKDOWN BY EXTENSION:\n")
            f.write("-" * 60 + "\n")
            
            ext_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
                'exact': 0, 'ambiguous': 0, 'none': 0
            })
            
            for result in match_results:
                ext = result.recovered_file.extension
                ext_stats[ext][result.confidence] += 1
            
            for ext in sorted(ext_stats.keys()):
                counts = ext_stats[ext]
                total = sum(counts.values())
                f.write(f".{ext}: {total} files (exact: {counts['exact']}, "
                       f"ambiguous: {counts['ambiguous']}, unidentified: {counts['none']})\n")
        
        self.logger.info(f"Summary report written to {summary_path}")
        print(f"\nSummary report: {summary_path}")
    
    def _generate_detailed_csv(self, match_results: List[MatchResult]) -> None:
        """Generate detailed CSV report."""
        csv_path = self.output_dir / 'detailed_report.csv'
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Recovered Filename',
                'File Size',
                'Extension',
                'Confidence',
                'Match Count',
                'Matched Filename(s)',
                'Original Path(s)'
            ])
            
            for result in match_results:
                rec = result.recovered_file
                
                if result.matched_files:
                    filenames = ' | '.join(m.filename for m in result.matched_files)
                    paths = ' | '.join(m.original_path for m in result.matched_files)
                else:
                    filenames = ''
                    paths = ''
                
                writer.writerow([
                    str(rec.path.name),
                    rec.size,
                    rec.extension,
                    result.confidence,
                    len(result.matched_files),
                    filenames,
                    paths
                ])
        
        self.logger.info(f"Detailed CSV report written to {csv_path}")
        print(f"Detailed report: {csv_path}")
    
    def _generate_json_report(self, match_results: List[MatchResult], stats: Dict[str, int]) -> None:
        """Generate JSON report."""
        json_path = self.output_dir / 'report.json'
        
        report = {
            'generated': datetime.now().isoformat(),
            'statistics': stats,
            'total_files': len(match_results),
            'matches': []
        }
        
        for result in match_results:
            rec = result.recovered_file
            
            match_entry = {
                'recovered_file': {
                    'filename': str(rec.path.name),
                    'size': rec.size,
                    'extension': rec.extension,
                    'path': str(rec.relative_path)
                },
                'confidence': result.confidence,
                'matched_files': [
                    {
                        'filename': m.filename,
                        'original_path': m.original_path,
                        'timestamp': m.timestamp
                    }
                    for m in result.matched_files
                ]
            }
            
            report['matches'].append(match_entry)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON report written to {json_path}")


def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Match recovered files to original filenames using size and extension'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview actions without copying files'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--raw-dir',
        type=Path,
        default=Path('raw'),
        help='Path to raw directory containing recovered files (default: raw)'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('recovered'),
        help='Path to output directory (default: recovered)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Validate paths
        raw_dir = args.raw_dir
        if not raw_dir.exists():
            logger.error(f"Raw directory not found: {raw_dir}")
            return 1
        
        filelist_path = raw_dir / 'filelist.txt'
        if not filelist_path.exists():
            logger.error(f"File list not found: {filelist_path}")
            return 1
        
        output_dir = args.output_dir
        
        if args.dry_run:
            logger.info("DRY RUN MODE - No files will be copied")
        
        logger.info("=" * 60)
        logger.info("FILE RECOVERY SCRIPT")
        logger.info("=" * 60)
        
        # Step 1: Parse file list
        logger.info("Step 1: Parsing file list...")
        parser_obj = FileListParser(filelist_path)
        file_index = parser_obj.parse()
        
        # Step 2: Scan recovered files
        logger.info("Step 2: Scanning recovered files...")
        scanner = FileScanner(raw_dir)
        recovered_files = scanner.scan()
        
        if not recovered_files:
            logger.warning("No recovered files found!")
            return 0
        
        # Step 3: Match files
        logger.info("Step 3: Matching files...")
        matcher = FileMatcher(file_index)
        match_results = matcher.match(recovered_files)
        
        # Step 4: Organize files
        logger.info("Step 4: Organizing files...")
        organizer = FileOrganizer(output_dir, dry_run=args.dry_run)
        stats = organizer.organize(match_results)
        
        # Step 5: Generate reports
        if not args.dry_run:
            logger.info("Step 5: Generating reports...")
            report_gen = ReportGenerator(output_dir)
            report_gen.generate_reports(match_results, stats)
        
        logger.info("=" * 60)
        logger.info("COMPLETED SUCCESSFULLY")
        logger.info("=" * 60)
        
        # Print summary
        total = len(match_results)
        print(f"\n{'=' * 60}")
        print("RECOVERY COMPLETE")
        print(f"{'=' * 60}")
        print(f"Total files: {total}")
        print(f"Identified (exact match): {stats['exact_copied']} ({stats['exact_copied']/total*100:.1f}%)")
        print(f"Ambiguous (multiple matches): {stats['ambiguous_copied']} ({stats['ambiguous_copied']/total*100:.1f}%)")
        print(f"Unidentified: {stats['unidentified_copied']} ({stats['unidentified_copied']/total*100:.1f}%)")
        if stats['errors'] > 0:
            print(f"Errors: {stats['errors']}")
        
        if not args.dry_run:
            print(f"\nOutput directory: {output_dir}")
            print(f"  - Identified files: {output_dir / 'identified'}")
            print(f"  - Ambiguous files: {output_dir / 'ambiguous'}")
            print(f"  - Unidentified files: {output_dir / 'unidentified'}")
        
        return 0
    
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        return 130
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
