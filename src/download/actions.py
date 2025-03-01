"""
Download functionality for PHP CVE Dataset Collection Tool.
"""

from pathlib import Path
from typing import Optional, List, Tuple
import requests
import zipfile
import shutil
import csv
import json
from collections import Counter
from rich.table import Table
from rich import box
from rich.console import Console
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from ..logger import logger

def download_repositories(
    csv_file: Path,
    output_dir: Path,
    year_range: Optional[Tuple[Optional[int], Optional[int]]] = None,
    project_types: Optional[List[str]] = None,
    cwe_types: Optional[List[str]] = None
) -> bool:
    """
    Download GitHub repository archives based on CSV entries with filtering options.
    Organizes downloads in output_dir/cwe_id/cve_id structure.
    
    Args:
        csv_file: Path to the CSV file containing CVE data
        output_dir: Directory to store downloaded and extracted repositories
        year_range: Optional tuple of (start_year, end_year) to filter CVEs
        project_types: Optional list of project types to filter
        cwe_types: Optional list of CWE types to filter
    """
    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Read and filter CSV entries
        filtered_entries = []
        console = Console()
        console.print("[cyan]Reading and filtering CSV entries...[/cyan]")
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Extract year from CVE ID
                year = int(row['cve_id'].split('-')[1])
                
                # Apply year filter
                if year_range:
                    start_year, end_year = year_range
                    if (start_year and year < start_year) or (end_year and year > end_year):
                        continue
                
                # Apply project type filter
                if project_types and row['project_type'] not in project_types:
                    continue
                
                # Apply CWE type filter
                if cwe_types:
                    row_cwes = set(cwe.strip().upper() for cwe in row['cwe_ids'].split(',')) if row['cwe_ids'] else set()
                    if not any(cwe in row_cwes for cwe in cwe_types):
                        continue
                
                filtered_entries.append(row)
        
        if not filtered_entries:
            logger.warning("No entries match the specified filters")
            return False
        
        # Format filter conditions for display
        filter_info = []
        if year_range and (year_range[0] or year_range[1]):
            year_str = f"{year_range[0] or 'start'} - {year_range[1] or 'present'}"
            filter_info.append(f"Years: {year_str}")
        if project_types:
            filter_info.append(f"Project Types: {', '.join(project_types)}")
        if cwe_types:
            filter_info.append(f"CWE Types: {', '.join(cwe_types)}")
            
        # Display found entries with filter information using console
        console.print(f"[green]Found {len(filtered_entries)} matching entries[/green]" + 
                    (f" with filters:\n" + "\n".join(f"[yellow]•[/yellow] {info}" for info in filter_info) if filter_info else ""))
        console.print()
        
        # Process filtered entries with progress bar
        success_count = 0
        successful_entries = []  # Store successful entries for statistics
        
        # Create progress bar
        progress = Progress(
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            TextColumn("•"),
            TextColumn("[progress.description]{task.description}"),
        )
        
        with progress:
            # Add main task
            task = progress.add_task(
                "",  # Empty initial description
                total=len(filtered_entries)
            )
            
            for entry in filtered_entries:
                cve_id = entry['cve_id']
                repo = entry['github_repo']
                commit = entry['pre_commit']
                cwe_ids = entry['cwe_ids'].split(',') if entry['cwe_ids'] else []
                
                # Update progress description with current CVE and CWE
                main_cwe = cwe_ids[0].strip().upper() if cwe_ids else "Unknown"
                if not main_cwe.startswith('CWE-'):
                    main_cwe = f"CWE-{main_cwe.lstrip('CWE')}"
                # Extract repository name from full path
                repo_name = repo.split('/')[-1] if repo else "unknown"
                progress.update(task, description=f"[cyan]{main_cwe}/{cve_id}({repo_name})")
                
                try:
                    # Create archive URL
                    archive_url = f"https://github.com/{repo}/archive/{commit}.zip"
                    
                    # Download zip file
                    response = requests.get(archive_url, stream=True)
                    response.raise_for_status()
                    
                    # Create temporary zip file
                    temp_zip = output_dir / f"{cve_id}_temp.zip"
                    with open(temp_zip, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract zip file
                    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                        # Get the name of the root directory in the zip
                        root_dir = zip_ref.namelist()[0].split('/')[0]
                        zip_ref.extractall(output_dir)
                    
                    # For each CWE, create a symbolic link in the corresponding CWE directory
                    extracted_path = output_dir / root_dir
                    for cwe_id in cwe_ids:
                        cwe_id = cwe_id.strip().upper()
                        if not cwe_id.startswith('CWE-'):
                            cwe_id = f"CWE-{cwe_id.lstrip('CWE')}"
                        
                        # Create CWE directory
                        cwe_dir = output_dir / cwe_id
                        cwe_dir.mkdir(parents=True, exist_ok=True)
                        
                        # Move repository to first CWE directory, create symlinks for others
                        cve_path = cwe_dir / cve_id
                        if cwe_id == cwe_ids[0].strip().upper():
                            if cve_path.exists():
                                shutil.rmtree(cve_path)
                            extracted_path.rename(cve_path)
                        else:
                            # Create relative symlink
                            if cve_path.exists():
                                if cve_path.is_symlink():
                                    cve_path.unlink()
                                else:
                                    shutil.rmtree(cve_path)
                            relative_path = Path(f"../{cwe_ids[0].strip().upper()}/{cve_id}")
                            cve_path.symlink_to(relative_path, target_is_directory=True)
                    
                    # Create metadata file in the main repository directory
                    metadata = {
                        'cve_id': cve_id,
                        'cwe_ids': cwe_ids,
                        'github_repo': repo,
                        'commit_hex': commit,
                        'project_type': entry['project_type']
                    }
                    
                    main_cwe_dir = output_dir / cwe_ids[0].strip().upper()
                    with open(main_cwe_dir / cve_id / '.ds_meta.json', 'w', encoding='utf-8') as f:
                        json.dump(metadata, f, indent=2)
                    
                    # Clean up
                    temp_zip.unlink()
                    
                    # If successful, store the entry
                    successful_entries.append(entry)
                    success_count += 1
                    
                except Exception as e:
                    logger.error(f"Error processing {cve_id}: {str(e)}")
                
                # Advance progress bar
                progress.advance(task)
        
        # Generate statistics after download
        console = Console()
        
        # Collect statistics
        stats = {
            'total_cves': len(successful_entries),
            'project_types': Counter(entry['project_type'] for entry in successful_entries),
            'cwe_types': Counter(),
            'years': set()
        }
        
        # Process CWEs and years
        for entry in successful_entries:
            year = int(entry['cve_id'].split('-')[1])
            stats['years'].add(year)
            if entry['cwe_ids']:
                for cwe in entry['cwe_ids'].split(','):
                    cwe = cwe.strip().upper()
                    if not cwe.startswith('CWE-'):
                        cwe = f"CWE-{cwe.lstrip('CWE')}"
                    stats['cwe_types'][cwe] += 1
        
        # Create summary tables
        console.print("\n[bold cyan]Download Summary[/bold cyan]")
        
        # Main statistics table
        main_table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        main_table.add_column("Metric", style="cyan")
        main_table.add_column("Value", justify="right")
        
        main_table.add_row(
            "Total CVEs Downloaded",
            str(stats['total_cves'])
        )
        main_table.add_row(
            "Year Range",
            f"{min(stats['years'])} - {max(stats['years'])}" if stats['years'] else "N/A"
        )
        main_table.add_row(
            "Project Types",
            str(len(stats['project_types']))
        )
        main_table.add_row(
            "Unique CWE Types",
            str(len(stats['cwe_types']))
        )
        
        console.print(main_table)
        console.print()
        
        # Project types distribution
        if stats['project_types']:
            console.print("[bold cyan]Project Type Distribution[/bold cyan]")
            proj_table = Table(box=box.SIMPLE, show_header=True)
            proj_table.add_column("Project Type", style="bold")
            proj_table.add_column("CVE Count", justify="right")
            proj_table.add_column("Percentage", justify="right")
            
            for proj_type, count in stats['project_types'].most_common():
                percentage = (count / stats['total_cves']) * 100
                proj_table.add_row(
                    proj_type,
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            console.print(proj_table)
            console.print()
        
        # Top CWEs
        if stats['cwe_types']:
            console.print("[bold cyan]Top 10 CWE Types[/bold cyan]")
            cwe_table = Table(box=box.SIMPLE, show_header=True)
            cwe_table.add_column("CWE", style="bold")
            cwe_table.add_column("Count", justify="right")
            cwe_table.add_column("Percentage", justify="right")
            
            total_cwes = sum(stats['cwe_types'].values())
            for cwe, count in stats['cwe_types'].most_common(10):
                percentage = (count / total_cwes) * 100
                cwe_table.add_row(
                    cwe,
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            console.print(cwe_table)
        
        logger.operation('end', "Download process completed", extra_info={
            'total': len(filtered_entries),
            'successful': success_count,
            'failed': len(filtered_entries) - success_count
        })
        
        return True
        
    except Exception as e:
        logger.error(f"Download operation failed: {str(e)}")
        return False 