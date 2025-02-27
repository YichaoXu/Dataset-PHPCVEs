"""
Statistic command module for PHP CVE Dataset Collection Tool.

This module provides functionality to generate statistics and visualizations
from the collected data.
"""

import os
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
import typer
from rich.console import Console

from src.utils.logger import Logger
from src.utils.file_utils import ensure_dir, read_csv_file, write_json_file
from src.utils.ui import ProgressUI, print_table
from src.config import config

console = Console()

def statistic(
    input_dir: Path = typer.Argument(..., help="Directory containing collected data"),
    output_dir: Path = typer.Option(Path("statistics"), help="Directory to store statistics"),
    generate_charts: bool = typer.Option(True, help="Generate charts"),
    verbose: bool = typer.Option(False, help="Enable verbose output")
):
    """
    Generate statistics and visualizations from the collected data.
    
    This command analyzes the collected data to generate statistics and visualizations
    about CWE types, project types, and their distributions over time.
    """
    # Start timing
    start_time = time.time()
    
    # Create output directory
    ensure_dir(output_dir)
    
    # Find input file
    input_file = input_dir / "collected_data.csv"
    if not input_file.exists():
        Logger.error(f"Input file not found: {input_file}")
        raise typer.Exit(1)
    
    # Read input file
    Logger.info(f"Reading input file: {input_file}")
    records = read_csv_file(input_file)
    
    if not records:
        Logger.error("No records found in input file")
        raise typer.Exit(1)
    
    Logger.info(f"Generating statistics for {len(records)} records")
    
    # Generate statistics
    statistics = {
        "total_records": len(records),
        "cwe_counts": _count_cwe_types(records),
        "project_type_counts": _count_project_types(records),
        "yearly_counts": _count_by_year(records),
        "top_repositories": _get_top_repositories(records, 10)
    }
    
    # Save statistics
    stats_file = output_dir / "statistics.json"
    write_json_file(statistics, stats_file)
    
    # Generate charts
    if generate_charts:
        try:
            import matplotlib.pyplot as plt
            
            # Create charts directory
            charts_dir = output_dir / "charts"
            ensure_dir(charts_dir)
            
            # Generate CWE distribution chart
            _generate_cwe_chart(statistics["cwe_counts"], charts_dir)
            
            # Generate project type distribution chart
            _generate_project_type_chart(statistics["project_type_counts"], charts_dir)
            
            # Generate yearly distribution chart
            _generate_yearly_chart(statistics["yearly_counts"], charts_dir)
            
            Logger.success(f"Charts generated in {charts_dir}")
        except ImportError:
            Logger.warning("Matplotlib not installed. Charts not generated.")
    
    # Display summary
    _display_statistics_summary(statistics)
    
    # Report timing
    elapsed_time = time.time() - start_time
    Logger.info(f"Statistics generation completed in {elapsed_time:.2f} seconds")
    Logger.success(f"Statistics saved to {stats_file}")
    
    return statistics

def _count_cwe_types(records: List[Dict[str, str]]) -> Dict[str, int]:
    """Count CWE types."""
    cwe_counts = {}
    for record in records:
        cwe_id = record.get("cwe_id", "Unknown")
        if not cwe_id:
            cwe_id = "Unknown"
        cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
    
    # Sort by count (descending)
    return dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True))

def _count_project_types(records: List[Dict[str, str]]) -> Dict[str, int]:
    """Count project types."""
    project_type_counts = {}
    for record in records:
        project_type = record.get("project_type", "Unknown")
        if not project_type:
            project_type = "Unknown"
        project_type_counts[project_type] = project_type_counts.get(project_type, 0) + 1
    
    # Sort by count (descending)
    return dict(sorted(project_type_counts.items(), key=lambda x: x[1], reverse=True))

def _count_by_year(records: List[Dict[str, str]]) -> Dict[str, int]:
    """Count records by year."""
    yearly_counts = {}
    for record in records:
        cve_id = record.get("cve_id", "")
        if cve_id and len(cve_id.split("-")) >= 2:
            year = cve_id.split("-")[1]
            yearly_counts[year] = yearly_counts.get(year, 0) + 1
    
    # Sort by year (ascending)
    return dict(sorted(yearly_counts.items()))

def _get_top_repositories(records: List[Dict[str, str]], limit: int = 10) -> Dict[str, int]:
    """Get top repositories by count."""
    repo_counts = {}
    for record in records:
        repo = record.get("repository", "")
        if repo:
            repo_counts[repo] = repo_counts.get(repo, 0) + 1
    
    # Sort by count (descending) and take top N
    return dict(sorted(repo_counts.items(), key=lambda x: x[1], reverse=True)[:limit])

def _generate_cwe_chart(cwe_counts: Dict[str, int], output_dir: Path):
    """Generate CWE distribution chart."""
    import matplotlib.pyplot as plt
    
    # Take top 10 CWEs
    top_cwes = list(cwe_counts.items())[:10]
    
    # Create figure
    plt.figure(figsize=(12, 8))
    plt.bar([cwe for cwe, _ in top_cwes], [count for _, count in top_cwes])
    plt.title("Top 10 CWE Types")
    plt.xlabel("CWE ID")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save figure
    plt.savefig(output_dir / "cwe_distribution.png")
    plt.close()

def _generate_project_type_chart(project_type_counts: Dict[str, int], output_dir: Path):
    """Generate project type distribution chart."""
    import matplotlib.pyplot as plt
    
    # Create figure
    plt.figure(figsize=(12, 8))
    plt.pie(
        project_type_counts.values(),
        labels=project_type_counts.keys(),
        autopct='%1.1f%%',
        startangle=90
    )
    plt.title("Project Type Distribution")
    plt.axis('equal')
    plt.tight_layout()
    
    # Save figure
    plt.savefig(output_dir / "project_type_distribution.png")
    plt.close()

def _generate_yearly_chart(yearly_counts: Dict[str, int], output_dir: Path):
    """Generate yearly distribution chart."""
    import matplotlib.pyplot as plt
    
    # Create figure
    plt.figure(figsize=(12, 8))
    plt.plot(list(yearly_counts.keys()), list(yearly_counts.values()), marker='o')
    plt.title("CVEs by Year")
    plt.xlabel("Year")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.tight_layout()
    
    # Save figure
    plt.savefig(output_dir / "yearly_distribution.png")
    plt.close()

def _display_statistics_summary(statistics: Dict[str, Any]):
    """Display statistics summary."""
    console.print("\n[bold]Statistics Summary[/bold]")
    console.print(f"Total records: {statistics['total_records']}")
    
    # Display CWE distribution
    console.print("\n[bold]Top CWE Types:[/bold]")
    cwe_rows = []
    for cwe_id, count in list(statistics["cwe_counts"].items())[:10]:
        percentage = (count / statistics["total_records"]) * 100
        cwe_rows.append([cwe_id, count, f"{percentage:.1f}%"])
    
    print_table(["CWE ID", "Count", "Percentage"], cwe_rows)
    
    # Display project type distribution
    console.print("\n[bold]Project Type Distribution:[/bold]")
    project_rows = []
    for project_type, count in statistics["project_type_counts"].items():
        percentage = (count / statistics["total_records"]) * 100
        project_rows.append([project_type, count, f"{percentage:.1f}%"])
    
    print_table(["Project Type", "Count", "Percentage"], project_rows) 