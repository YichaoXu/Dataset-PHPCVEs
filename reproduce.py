#!/usr/bin/env python3

import os, sys, typer
from pathlib import Path
from typing import Optional

# Add src directory to Python path
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_path)

# Import commands
from src.collect import collect_cves


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


if __name__ == "__main__":
   app.command()(collect)
   app() 