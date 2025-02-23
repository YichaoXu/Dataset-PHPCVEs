import typer
import docker
import os

app = typer.Typer(add_completion=False)
client = docker.from_env()

IMAGE_NAME = "dscves_jhuseclab"

@app.command()
def install(
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Do not use cache of the docker."
    ),
    do_enforce: bool = typer.Option(
        False, "--do-enforce", help="Force rebuild the image even if it already exists."
    ),
):
    """🔨 Build and install the Docker image with cache and optional enforcement."""

    # Get the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    docker_dir = os.path.join(script_dir, "docker")
    typer.echo(f"🚀 Checking if Docker build file exists in {docker_dir}...")
    if not os.path.exists(docker_dir): raise "❌ Dockerfile do not exist, you may changed the script location."

    # Check if the image already exists
    try:
        client.images.get(IMAGE_NAME)
        if not do_enforce:
            typer.secho(
                f"✅ Image '{IMAGE_NAME}' already exists. Skipping installation.",
                fg=typer.colors.YELLOW,
            )
            return
        else:
            typer.secho(
                f"⚠️ Image '{IMAGE_NAME}' exists, but --do-enforce is set. Rebuilding...",
                fg=typer.colors.RED,
            )
    except docker.errors.ImageNotFound:
        typer.echo("⚠️ Image not found. Proceeding with installation...")
    except docker.errors.APIError as e:
        typer.secho(f"❌ Docker API error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    # Build the image and stream progress logs
    try:
        typer.echo(f"🔨 Building Docker image from {docker_dir} ...")
        image_build_logs = client.api.build(
            path=docker_dir, nocache=no_cache, tag=IMAGE_NAME, decode=True
        )

        # Display progress in real-time
        for log in image_build_logs:
            if "stream" in log:
                typer.echo(log["stream"].strip())
            elif "status" in log:
                typer.echo(f"🔄 {log['status']}", nl=False)

        typer.secho(f"\n✅ Installation complete: {IMAGE_NAME}", fg=typer.colors.GREEN)
    except docker.errors.BuildError as e:
        typer.secho(f"❌ Build failed: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@app.command()
def clean():
    """🧹 Remove the Docker image."""
    typer.echo("🧹 Cleaning up old Docker images and containers...")
    try:
        client.images.remove(IMAGE_NAME, force=True)
        typer.secho("✅ Cleanup complete.", fg=typer.colors.GREEN)
    except docker.errors.ImageNotFound:
        typer.secho("⚠️ Image not found, skipping cleanup.", fg=typer.colors.YELLOW)
    except docker.errors.APIError as e:
        typer.secho(f"❌ Error removing image: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@app.command()
def download(
    output_dir: str = typer.Argument("data", help="📂 Path to the output directory"),
    gh_token: str = typer.Option(None, "--token", help="🔑 GitHub API Token")
):
    """📥 Run the container and download the dataset to the output directory."""
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    typer.echo(f"🚀 Running Docker container to download dataset...")
    typer.echo(f"📂 Output directory: {output_dir}")

    try:
        # Run the Docker container with the necessary environment variables
        container = client.containers.run(
            IMAGE_NAME, environment={"GITHUB_TOKEN": gh_token},
            volumes={output_dir: {"bind": "/output", "mode": "rw"}},
            remove=True, detach=True,  # Run in background to capture logs
        )
        # Stream logs in real-time
        for log in container.logs(stream=True):
            typer.echo(log.decode().strip())
        typer.secho(f"✅ Dataset downloaded to: {output_dir}", fg=typer.colors.GREEN)
    except docker.errors.ContainerError as e:
        typer.secho(f"❌ Download failed: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    except docker.errors.APIError as e:
        typer.secho(f"❌ Docker API Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()