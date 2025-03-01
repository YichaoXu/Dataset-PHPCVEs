from rich.console import Console
from rich.table import Table
from rich import box
from collections import Counter, defaultdict
from typing import Optional, List, Tuple
import logging
from pathlib import Path
import csv
from datetime import datetime
from cwe_tree import query as cwe_query

def analyze_cve_distribution(
    csv_file: Path,
    min_cves: int = 0,
    project_types: Optional[List[str]] = None,
    sort_by: str = "cves",
    year_range: Optional[Tuple[Optional[int], Optional[int]]] = None,
    top_cwes: int = 5
) -> bool:
    """
    Analyze CVE distribution across different project types.
    
    Args:
        csv_file: Path to the CSV file containing CVE data
        min_cves: Minimum number of CVEs required to include a project type
        project_types: List of project types to analyze
        sort_by: Sort results by: 'cves', 'percentage', 'repos', or 'cwes'
        year_range: Tuple of (start_year, end_year) to filter CVEs
        top_cwes: Number of top CWE types to show for each project type
    """
    console = Console()
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize data structures
        stats = defaultdict(lambda: {
            'cves': 0,
            'repositories': set(),
            'cwe_types': set(),
            'all_cwes': [],
            'years': set()
        })
        total_cves = 0
        
        # Read and process CSV data
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Extract year from CVE ID (e.g., CVE-2024-1234 -> 2024)
                year = int(row['cve_id'].split('-')[1])
                
                # Apply year filter if specified
                if year_range:
                    start_year, end_year = year_range
                    if (start_year and year < start_year) or (end_year and year > end_year):
                        continue
                
                project_type = row['project_type']
                if project_types and project_type not in project_types:
                    continue
                
                # Update statistics
                stats[project_type]['cves'] += 1
                stats[project_type]['repositories'].add(row['github_repo'])
                stats[project_type]['years'].add(year)
                
                # Process CWEs
                if row['cwe_ids']:
                    cwes = row['cwe_ids'].split(',')
                    stats[project_type]['cwe_types'].update(cwes)
                    stats[project_type]['all_cwes'].extend(cwes)
                
                total_cves += 1
        
        # Calculate percentages and year spans
        for project_type in stats:
            stats[project_type]['percentage'] = (stats[project_type]['cves'] / total_cves) * 100
            years = sorted(stats[project_type]['years'])
            stats[project_type]['year_span'] = f"{min(years)} - {max(years)}"
        
        # Filter by minimum CVEs
        stats = {k: v for k, v in stats.items() if v['cves'] >= min_cves}
        
        # Sort statistics
        sort_key = {
            'cves': lambda x: x[1]['cves'],
            'percentage': lambda x: x[1]['percentage'],
            'repos': lambda x: len(x[1]['repositories']),
            'cwes': lambda x: len(x[1]['cwe_types'])
        }
        sorted_stats = sorted(stats.items(), key=sort_key[sort_by], reverse=True)
        
        # Print analysis header with filter information
        console.print("\n[bold cyan]CVE Distribution Analysis[/bold cyan]")
        if any([year_range, min_cves > 0, sort_by != "cves", project_types]):
            console.print("[dim]Applied filters:[/dim]")
            if year_range:
                console.print(f"  • Year range: {year_range[0] or 'start'} - {year_range[1] or 'end'}")
            if min_cves > 0:
                console.print(f"  • Minimum CVEs: {min_cves}")
            if sort_by != "cves":
                console.print(f"  • Sorted by: {sort_by}")
            if project_types:
                console.print(f"  • Project types: {', '.join(project_types)}")
        console.print()
        
        # Create and display the main statistics table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Project Type", style="cyan")
        table.add_column("CVEs", justify="right")
        table.add_column("Repos", justify="right")
        table.add_column("CWEs", justify="right")
        table.add_column("Percentage", justify="right")
        table.add_column("Year Span", justify="center")
        
        for project_type, stat in sorted_stats:
            table.add_row(
                project_type,
                str(stat['cves']),
                str(len(stat['repositories'])),
                str(len(stat['cwe_types'])),
                f"{stat['percentage']:.1f}%",
                stat['year_span']
            )
        
        console.print(table)
        console.print()
        
        # Show CWE distribution for each project type
        console.print("[bold cyan]CWE Distribution by Project Type[/bold cyan]")
        console.print()
        
        for project_type, stat in sorted_stats:
            # Count CWE frequencies
            cwe_counter = Counter(stat['all_cwes'])
            total_cwes = sum(cwe_counter.values())
            
            # Create CWE distribution table for this project type
            cwe_table = Table(
                box=box.SIMPLE,
                title=f"[bold]{project_type}[/bold] (Total CVEs: {stat['cves']})",
                title_style="cyan"
            )
            cwe_table.add_column("CWE", style="bold")
            cwe_table.add_column("Description", style="dim", width=50)
            cwe_table.add_column("Type", style="dim")
            cwe_table.add_column("Count", justify="right")
            cwe_table.add_column("Percentage", justify="right")
            
            # Get top N most common CWEs
            for cwe_id, count in cwe_counter.most_common(top_cwes):
                percentage = (count / total_cwes) * 100
                # Get CWE metadata
                cwe_node = cwe_query.get_node(cwe_id)
                if cwe_node:
                    metadata = cwe_node.get_metadata()
                    description = metadata.get('name', 'Unknown')
                    cwe_type = metadata.get('abstract', 'Unknown')
                else:
                    description = "Unknown"
                    cwe_type = "Unknown"
                
                cwe_table.add_row(
                    cwe_id,
                    description,
                    cwe_type,
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            console.print(cwe_table)
            console.print()
        
        # Print summary
        console.print("[bold cyan]Analysis Summary[/bold cyan]")
        summary_table = Table(box=box.SIMPLE)
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value")
        
        all_years = set()
        for stat in stats.values():
            all_years.update(stat['years'])
        year_range_str = f"{min(all_years)} - {max(all_years)}"
        
        summary_table.add_row("Total CVEs", str(total_cves))
        summary_table.add_row("Project Types", str(len(stats)))
        summary_table.add_row("Most Common Type", f"{sorted_stats[0][0]} ({sorted_stats[0][1]['cves']} CVEs)")
        summary_table.add_row("Total Repositories", str(sum(len(s['repositories']) for s in stats.values())))
        summary_table.add_row("Total CWE Types", str(len(set().union(*[s['cwe_types'] for s in stats.values()]))))
        summary_table.add_row("Year Range", year_range_str)
        summary_table.add_row("Avg CVEs per Type", f"{total_cves / len(stats):.1f}")
        
        console.print(summary_table)
        
        return True
        
    except Exception as e:
        logger.error(f"Error analyzing CVE distribution: {str(e)}")
        return False 