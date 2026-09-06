"""CLI entry point for BioDrift."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from biodrift.config import load_config

app = typer.Typer(name="biodrift", help="Contextual behavioral verification for Python packages")
console = Console()


@app.command()
def verify(
    package: str = typer.Argument(help="Package path or name"),
    contract: str | None = typer.Option(None, "--contract", "-c", help="Contract file path"),
    config: str | None = typer.Option(None, "--config", help="Config file path"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    verbose: int = typer.Option(1, "-v", "--verbose", help="Verbosity level"),
) -> None:
    """Verify a package against a behavioral contract."""
    cfg = load_config(Path(config) if config else None)
    cfg.verbosity = verbose
    console.print("[bold]BioDrift[/bold] v0.1.0")
    console.print(f"Package: {package}")
    console.print(f"Contract: {contract or 'auto-detect'}")
    console.print(f"Config: {config or 'default'}")

    from biodrift.pipeline import VerificationError, run_verification

    try:
        result = run_verification(
            package_path=package,
            contract_path=contract,
            config=cfg,
            output_dir=output or "results",
        )
    except VerificationError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    verdict = result.decision.verdict
    colors = {
        "COMPLIANT": "green",
        "VIOLATION": "red",
        "INCONCLUSIVE": "yellow",
    }
    color = colors.get(verdict.value, "white")
    console.print(f"\n[bold {color}]Verdict: {verdict.value}[/bold {color}]")
    console.print(f"  Reason: {result.decision.reason}")
    console.print(f"  Events captured: {result.events_count}")
    console.print(f"  Coverage ratio: {result.decision.coverage_ratio:.2%}")
    console.print(f"  Attribution: {result.decision.attribution_confidence:.2f}")
    if result.report_path:
        console.print(f"  Report: {result.report_path}")


@app.command()
def init(
    path: str = typer.Option(".", "--path", help="Project root path"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
) -> None:
    """Initialize BioDrift configuration in the current directory."""
    target = Path(path) / "config"
    target.mkdir(parents=True, exist_ok=True)
    contracts_dir = target / "contracts"
    contracts_dir.mkdir(exist_ok=True)

    default_config = target / "default.yaml"
    if default_config.exists() and not force:
        msg = f"[yellow]Config exists at {default_config}. Use --force to overwrite.[/yellow]"
        console.print(msg)
        return

    import yaml

    config_data = {
        "observers": {
            "python_audit": {"enabled": True, "options": {}},
            "process": {"enabled": True, "options": {}},
            "ptrace": {"enabled": False, "options": {"platform_gate": "linux"}},
            "ebpf": {"enabled": False, "options": {"platform_gate": "linux"}},
        },
        "storage": {"db_path": "results/biodrift.db", "evidence_dir": "results/evidence"},
        "coverage": {
            "weights": {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25},
            "threshold": 0.8,
        },
        "decision": {
            "min_attribution_confidence": 0.6,
            "min_coverage": 0.8,
            "conflict_tolerance": 0.0,
        },
    }

    observers_data = {"observers": config_data["observers"]}

    with open(default_config, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False)

    with open(target / "observers.yaml", "w") as f:
        yaml.dump(observers_data, f, default_flow_style=False)

    console.print(f"[green]Initialized BioDrift config at {target}[/green]")


@app.command()
def report(
    run_id: str | None = typer.Option(None, "--run-id", help="Run ID to report"),
    db_path: str | None = typer.Option(None, "--db", help="Database path"),
) -> None:
    """Display results for a verification run."""
    from rich.table import Table

    from biodrift.config import load_config as _load_cfg
    from biodrift.storage.db import init_db
    from biodrift.storage.repositories import RunRepository

    cfg = _load_cfg()
    db = init_db(db_path or cfg.storage.db_path)
    with db() as session:
        repo = RunRepository(session)
        if run_id:
            run_meta = repo.get(run_id)
            if not run_meta:
                console.print(f"[red]Run {run_id} not found[/red]")
                return
            runs = [run_meta]
        else:
            runs = repo.list_runs()[:20]
            if not runs:
                console.print("[yellow]No runs found.[/yellow]")
                return

    table = Table(title="Verification Runs")
    table.add_column("Run ID", style="dim")
    table.add_column("Package")
    table.add_column("Verdict", style="bold")
    table.add_column("Events")
    for r in runs:
        verdict = str(r.final_verdict or "UNKNOWN")
        style = {"COMPLIANT": "green", "VIOLATION": "red"}.get(verdict, "yellow")
        table.add_row(r.run_id[:8], r.package_id, f"[{style}]{verdict}[/{style}]", "")
    console.print(table)


@app.command()
def contract_diff(
    baseline: str = typer.Argument(help="Baseline contract file"),
    current: str = typer.Argument(help="Current contract file"),
) -> None:
    """Compare two contract versions and flag drift."""
    from biodrift.contract.evolution import detect_drift
    from biodrift.contract.manager import load_contract

    baseline_contract = load_contract(baseline)
    current_contract = load_contract(current)
    drifted = detect_drift(baseline_contract, current_contract)

    if not drifted:
        console.print("[green]No drift detected.[/green]")
        return

    console.print("[bold red]Contract drift detected:[/bold red]")
    for field in sorted(drifted):
        console.print(f"  [yellow]─ {field}[/yellow]")


@app.command()
def benchmark(
    fixtures_dir: str = typer.Option("fixtures", "--fixtures", help="Fixtures directory"),
    config: str | None = typer.Option(None, "--config", help="Config file path"),
    output: str | None = typer.Option("results", "--output", "-o", help="Results directory"),
) -> None:
    """Run the benchmark suite against all fixtures."""
    from rich.table import Table

    from biodrift.pipeline import run_verification

    cfg = load_config(Path(config) if config else None)
    fixtures_path = Path(fixtures_dir)
    fixture_dirs = sorted(
        {d.parent for d in fixtures_path.rglob("pyproject.toml")}
    )

    if not fixture_dirs:
        console.print(f"[yellow]No fixtures found in {fixtures_path}[/yellow]")
        return

    console.print(f"[bold]Running benchmark on {len(fixture_dirs)} fixtures...[/bold]\n")

    table = Table(title="Benchmark Results")
    table.add_column("Fixture", style="dim")
    table.add_column("Verdict", style="bold")
    table.add_column("Coverage")
    table.add_column("Events")
    table.add_column("Reason")

    counts = {"COMPLIANT": 0, "VIOLATION": 0, "INCONCLUSIVE": 0, "ERROR": 0}
    colors = {"COMPLIANT": "green", "VIOLATION": "red", "INCONCLUSIVE": "yellow"}

    for fixture in fixture_dirs:
        try:
            result = run_verification(
                package_path=fixture,
                config=cfg,
                output_dir=output or "results",
                persist=False,
            )
            v = result.decision.verdict.value
            c = colors.get(v, "white")
            table.add_row(
                fixture.name,
                f"[{c}]{v}[/{c}]",
                f"{result.decision.coverage_ratio:.0%}",
                str(result.events_count),
                result.decision.reason[:60],
            )
        except Exception as e:
            v = "ERROR"
            table.add_row(fixture.name, "[red]ERROR[/red]", "-", "-", str(e)[:60])
        counts[v] = counts.get(v, 0) + 1

    console.print(table)
    console.print(
        f"\n[bold]{len(fixture_dirs)}[/bold] fixtures — "
        f"[green]{counts['COMPLIANT']} COMPLIANT[/green]  "
        f"[red]{counts['VIOLATION']} VIOLATION[/red]  "
        f"[yellow]{counts['INCONCLUSIVE']} INCONCLUSIVE[/yellow]"
        + (f"  [red]{counts['ERROR']} ERROR[/red]" if counts["ERROR"] else "")
    )


if __name__ == "__main__":
    app()
