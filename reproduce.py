import os
import sys
import typer

# Add src directory to Python path
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_path)

# Use explicit import from src.commands for IDE recognition
from src.commands import collect, download, statistic

app = typer.Typer(help="PHP CVE Dataset Collection Tool")
# Register commands
app.command()(collect)
app.command()(download)
app.command()(statistic)

if __name__ == "__main__":
    app() 