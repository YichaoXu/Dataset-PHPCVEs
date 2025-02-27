#!/usr/bin/env python3
"""
PHP CVE Collection Tool
=======================

A command-line tool for collecting, downloading, and analyzing PHP-related CVEs 
(Common Vulnerabilities and Exposures) with their associated GitHub commits.

This tool provides the following main commands:

1. collect: Downloads CVE data, filters for PHP-related vulnerabilities, and extracts
   GitHub commit information to create a structured dataset.

2. download: Downloads vulnerable code versions from GitHub repositories based on
   the collected dataset, organizing them by CWE type and CVE ID.

3. analyze: Analyzes the dataset to generate statistics about CWE types, project types,
   and their distributions over time.

4. statistic: Generates detailed statistics and visualizations from the collected data.

5. ai-reclassify: Uses AI to reclassify PHP projects based on README content.

6. clean: Cleans up temporary files and directories.

Workflow:
---------
1. Collect CVE data and identify PHP-related vulnerabilities
2. Download vulnerable code from GitHub repositories
3. Analyze the collected data and generate statistics
4. Optionally reclassify projects using AI

Example usage:
-------------
# Collect PHP-related CVEs
$ python reproduce.py collect ./output --token=YOUR_GITHUB_TOKEN

# Download vulnerable code for specific CWE types
$ python reproduce.py download ./output --cwes=79,89

# Generate statistics
$ python reproduce.py statistic ./output

# Reclassify projects using AI
$ python reproduce.py ai-reclassify ./output/collected_data.csv YOUR_API_KEY

For detailed command options, use:
$ python reproduce.py [command] --help
"""

import os
import sys
import typer

# Add src directory to Python path
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_path)

# Import commands
from src.commands.collect import collect
from src.commands.download import download
from src.commands.statistic import statistic
from src.commands.clean import clean
from src.commands.reclassify import reclassify

# Create Typer app
app = typer.Typer(
    help="Command-line interface for PHP CVE Dataset Collection Tool.",
    no_args_is_help=True,
    add_completion=False,
)

# Register commands
app.command()(collect)
app.command()(download)
app.command()(statistic)
app.command()(reclassify)
app.command()(clean)

if __name__ == "__main__":
    app() 