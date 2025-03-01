#!/usr/bin/env python3

import os, sys, typer
from pathlib import Path
from typing import Optional, List, Tuple

# Add src directory to Python path
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_path)

# Import commands
from src.collect import collect_cves
from src.statistic import analyze_cve_distribution

# Create Typer app
app = typer.Typer(
    help="Command-line interface for PHP CVE Dataset Collection Tool.",
    no_args_is_help=True,
    add_completion=False,
)

def collect(
   output_dir: Path = typer.Argument(Path("output"), help="Directory to store output files."),
   use_cache: bool = typer.Option(True, help="Use cached data if available."),
   github_token: Optional[str] = typer.Option(None, help="GitHub API token for higher rate limits."),
   ai_classifier: Optional[str] = typer.Option(None, help="AI classifier configuration in format 'api_url:api_model:api_key'. "),
   verbose: bool = typer.Option(False, help="Verbose output.")
):
    """
    Collect and analyze PHP-related CVE data from the official CVE List.
    """
    collect_cves(output_dir, use_cache, github_token, ai_classifier, verbose) 

def statistic(
    csv_file: Path = typer.Argument(..., help="Path to the CSV file containing CVE data"),
    project_types: str = typer.Option(None, "--types", "-t", help="Project types to analyze, comma-separated, e.g., 'Web App,Framework'"),
    year_from: Optional[int] = typer.Option(None, "--from", "-f", help="Start year, e.g., 2020"),
    year_to: Optional[int] = typer.Option(None, "--to", "-t", help="End year, e.g., 2024"),
    min_cves: int = typer.Option(0, "--min-cves", "-m", help="Minimum number of CVEs to include a project type"),
    top_cwes: int = typer.Option(5, "--top-cwes", "-c", help="Show top N most common CWE types for each project type"),
    sort_by: str = typer.Option("cves", "--sort", "-s", 
                               help="Sort by: cves (CVE count), percentage, repos (repository count), cwes (CWE type count)",
                               show_default=True)
):
    """
    Analyze CVE distribution across different project types.

    Examples:
    \b
    # Basic usage
    python reproduce.py statistic data/collected.csv

    \b
    # Analyze specific project types
    python reproduce.py statistic data/collected.csv --types "Web App,Framework"

    \b
    # Analyze by year range
    python reproduce.py statistic data/collected.csv --from 2020 --to 2024

    \b
    # Show top 10 most common CWEs for each type
    python reproduce.py statistic data/collected.csv --top-cwes 10

    \b
    # Sort by repository count
    python reproduce.py statistic data/collected.csv --sort repos
    """
    # Build year range tuple
    year_range = None
    if year_from is not None or year_to is not None:
        year_range = (year_from, year_to)
    
    # Process project types list
    project_type_list = None
    if project_types:
        project_type_list = [pt.strip() for pt in project_types.split(",")]
    
    # Execute analysis
    analyze_cve_distribution(
        csv_file=csv_file,
        project_types=project_type_list,
        year_range=year_range,
        min_cves=min_cves,
        top_cwes=top_cwes,
        sort_by=sort_by
    )

if __name__ == "__main__":
   app.command()(collect)
   app.command()(statistic)
   app() 