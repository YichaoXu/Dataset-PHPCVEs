"""
PHP CVE Collection Tool
=======================

A command-line tool for collecting, downloading, and analyzing PHP-related CVEs 
(Common Vulnerabilities and Exposures) with their associated GitHub commits.

This tool provides three main commands:

1. collect: Downloads CVE data, filters for PHP-related vulnerabilities, and extracts
   GitHub commit information to create a structured dataset.

2. download: Downloads vulnerable code versions from GitHub repositories based on
   the collected dataset, organizing them by CWE type and CVE ID.

3. statistic: Analyzes the dataset to generate statistics about CWE types, project types,
   and their distributions over time.

Workflow:
---------
1. Collect CVE data and identify PHP-related vulnerabilities
2. Download vulnerable code from GitHub repositories
3. Generate statistics and insights from the collected data

Example usage:
-------------
# Collect PHP-related CVEs
$ python reproduce.py collect ./output --token=YOUR_GITHUB_TOKEN

# Download vulnerable code for specific CWE types
$ python reproduce.py download ./output --cwes=79,89

# Generate statistics
$ python reproduce.py statistic ./output

For detailed command options, use:
$ python reproduce.py [command] --help
"""

import os
import sys
import typer

# Add src directory to Python path
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_path)

# Use explicit import from src.commands for IDE recognition
from src.commands import collect, download, statistic


app = typer.Typer(
    help="""Command-line interface for PHP CVE Dataset Collection Tool.""",
    no_args_is_help=True,
    add_completion=False,
)


# Register commands
app.command()(collect)
app.command()(download)
app.command()(statistic)

if __name__ == "__main__":
    app() 