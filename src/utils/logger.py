import typer

class Logger:
    """Unified logging with consistent styling"""
    @staticmethod
    def info(msg: str):
        typer.echo(f"ℹ️ {msg}")

    @staticmethod
    def warning(msg: str):
        typer.secho(f"⚠️ {msg}", fg=typer.colors.YELLOW)

    @staticmethod
    def error(msg: str):
        typer.secho(f"❌ {msg}", fg=typer.colors.RED)

    @staticmethod
    def success(msg: str):
        typer.secho(f"✅ {msg}", fg=typer.colors.GREEN) 