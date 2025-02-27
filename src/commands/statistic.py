import os
import csv
import re
from pathlib import Path
import typer
from collections import Counter, defaultdict
from utils.logger import Logger
from core.validator import DataValidator
from commands.collect import collect

def statistic(
    output_dir: str = typer.Argument(None, help="📂 Statistics output directory path"),
    dataset_path: str = typer.Option(None, help="📊 Dataset CSV file path"),
    github_token: str = typer.Option(None, "--token", help="🔑 GitHub API Token")
):
    """
    Generate detailed statistics and analysis of the PHP CVE dataset.
    
    This command analyzes the dataset and generates various statistics including
    CWE type distribution, project type distribution, yearly trends, and correlations
    between CWEs and project types.
    """
    output_dir = Path(output_dir or os.path.dirname(os.path.abspath(__file__)))
    stats_dir = output_dir / "statistics"
    dataset_path = Path(dataset_path or output_dir / "dataset.csv")

    if not dataset_path.exists():
        Logger.warning("Dataset not found, collecting data first...")
        collect(str(output_dir), github_token=github_token)
        dataset_path = output_dir / "dataset.csv"

    if not DataValidator.validate_dataset(dataset_path):
        raise typer.Exit(code=1)

    try:
        os.makedirs(stats_dir, exist_ok=True)
        
        stats = {
            'total': 0,
            'cwe_counts': Counter(),
            'repo_counts': Counter(),
            'cves_by_year': Counter(),
            'project_type_counts': Counter(),
            'cwe_by_project_type': defaultdict(Counter),
            'project_type_by_year': defaultdict(Counter)
        }
        
        cwe_details = defaultdict(list)
        project_type_details = defaultdict(list)
        
        with open(dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Strict year validation
                year_match = re.match(r'CVE-(\d{4})-\d+', row['cve_id'])
                year = year_match.group(1) if year_match else "UNKNOWN"
                
                # Validate year range
                try:
                    if year != "UNKNOWN":
                        year_int = int(year)
                        if not (1999 <= year_int <= 2025):
                            year = "UNKNOWN"
                except ValueError:
                    year = "UNKNOWN"
                
                stats['total'] += 1
                stats['cwe_counts'][row['cwe_type']] += 1
                stats['repo_counts'][row['repository']] += 1
                stats['cves_by_year'][year] += 1
                stats['project_type_counts'][row['project_type']] += 1
                stats['cwe_by_project_type'][row['project_type']][row['cwe_type']] += 1
                stats['project_type_by_year'][year][row['project_type']] += 1
                
                cwe_details[row['cwe_type']].append(row['cve_id'])
                project_type_details[row['project_type']].append({
                    'cve_id': row['cve_id'],
                    'cwe_type': row['cwe_type'],
                    'repository': row['repository']
                })

        # Save summary
        with open(stats_dir / "summary.txt", 'w', encoding='utf-8') as f:
            f.write(f"Total CVEs: {stats['total']}\n")
            f.write(f"Unique CWEs: {len(stats['cwe_counts'])}\n")
            f.write(f"Unique Repositories: {len(stats['repo_counts'])}\n")
            f.write(f"Project Types: {len(stats['project_type_counts'])}\n\n")
            
            f.write("Top 10 CWEs:\n")
            for cwe, count in stats['cwe_counts'].most_common(10):
                f.write(f"{cwe}: {count} CVEs\n")
            
            f.write("\nProject Type Distribution:\n")
            for ptype, count in stats['project_type_counts'].most_common():
                f.write(f"{ptype}: {count} CVEs ({count/stats['total']*100:.1f}%)\n")
            
            f.write("\nCVEs by Year:\n")
            for year, count in sorted(stats['cves_by_year'].items()):
                f.write(f"{year}: {count} CVEs\n")

        # Save project type details
        with open(stats_dir / "project_type_details.csv", 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Project Type', 'Total CVEs', 'Unique CWEs', 'Most Common CWE', 'Repositories'])
            for ptype, cves in project_type_details.items():
                cwe_counter = Counter(cve['cwe_type'] for cve in cves)
                most_common_cwe = cwe_counter.most_common(1)[0][0] if cwe_counter else "N/A"
                unique_repos = len({cve['repository'] for cve in cves})
                writer.writerow([
                    ptype, 
                    len(cves), 
                    len(cwe_counter),
                    most_common_cwe,
                    unique_repos
                ])

        # Check before writing matrix
        project_types = sorted(stats['project_type_counts'].keys())
        if not project_types:
            Logger.warning("No project types found, skipping matrix CSV")
        else:
            with open(stats_dir / "cwe_project_type_matrix.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['CWE'] + project_types)
                
                for cwe in sorted(stats['cwe_counts'].keys()):
                    row = [cwe]
                    for ptype in project_types:
                        row.append(stats['cwe_by_project_type'][ptype][cwe])
                    writer.writerow(row)

        # Save project type trends
        with open(stats_dir / "project_type_trends.csv", 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Year'] + project_types)
            
            for year in sorted(stats['cves_by_year'].keys()):
                row = [year]
                for ptype in project_types:
                    row.append(stats['project_type_by_year'][year][ptype])
                writer.writerow(row)

        Logger.success(f"Statistics saved to: {stats_dir}")

    except Exception as e:
        Logger.error(f"Statistics generation failed: {e}")
        raise typer.Exit(code=1) 