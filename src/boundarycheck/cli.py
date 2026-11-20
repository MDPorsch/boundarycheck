"""The command line: a thin layer over the library. Exit codes: 0 clean, 1 findings, 2 anything else."""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
from collections import Counter
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from boundarycheck import __version__
from boundarycheck.config import ConfigError, load_config
from boundarycheck.engine import RunResult, run
from boundarycheck.evidence import RunStore, StoreError, parse_age
from boundarycheck.model import EgressViolation, Status, TransportUnavailable
from boundarycheck.planner import plan
from boundarycheck.redact import SecretLeakError
from boundarycheck.report import to_json, to_markdown
from boundarycheck.template import STARTER_CONFIG

DEFAULT_RUNS = Path(".boundarycheck/runs")
app = typer.Typer(
    add_completion=False, no_args_is_help=True, pretty_exceptions_enable=False,
    help="Check that an API enforces the authorization boundaries you declare. Read-only, loopback-only in v0.1.",
)  # fmt: skip
Config_ = Annotated[Path, typer.Option("--config", "-c", help="Path to the YAML config.")]
Runs_ = Annotated[Path, typer.Option("--runs-dir", help="Where runs are stored.")]


def _fail(message: str) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(2)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"boundarycheck {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    """boundarycheck"""


def _load(path: Path) -> Any:
    try:
        return load_config(path)
    except ConfigError as exc:
        _fail(f"config: {exc}")


@app.command()
def init(
    output: Annotated[Path, typer.Option("--output", "-o", help="Where to write the starter config.")] = Path(
        "boundarycheck.yaml"
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write an annotated, safe-by-default starter config."""
    try:
        with output.open("w" if force else "x", encoding="utf-8") as handle:
            handle.write(STARTER_CONFIG)
    except FileExistsError:
        _fail(f"{output} already exists (use --force to overwrite it)")
    except OSError:
        _fail(f"could not write {output}")
    typer.echo(f"wrote {output}. Next: edit it, then 'boundarycheck validate --config {output}'.")


@app.command()
def validate(config: Config_) -> None:
    """Check the config (schema, references, policy completeness). No network."""
    cfg = _load(config)
    cases = plan(cfg)
    typer.echo(
        f"ok: scope '{cfg.scope.id}', {len(cfg.tenants)} tenants, {len(cfg.principals)} principals, "
        f"{len(cfg.resources)} resources, {len(cfg.actions)} actions; {len(cases)} cases planned "
        "(plus concealment checks derived from them)"
    )


@app.command(name="plan")
def plan_cmd(config: Config_) -> None:
    """Print every request that would be sent. Nothing is sent and no credential is read."""
    cfg = _load(config)
    cases = plan(cfg)
    for c in cases:
        typer.echo(
            f"{c.id} {c.action.method} {c.path} as {c.principal or 'anonymous'} "
            f"-> expect {c.expected.outcome.value} ({c.expected.reason})"
        )
    typer.echo(f"{len(cases)} requests planned; none sent.")


def _summarize(result: RunResult, saved: Path | None) -> None:
    counts = Counter(c.status.value for c in result.cases)
    typer.echo(f"boundarycheck {result.tool_version} | scope {result.scope_id} | transport {result.transport}")
    typer.echo(
        "cases: " + ", ".join(f"{s.value}: {counts.get(s.value, 0)}" for s in Status) + f" (total {len(result.cases)})"
    )
    findings = [c for c in result.cases if c.status is Status.FINDING_CANDIDATE]
    for c in findings[:50]:
        typer.echo(f"  FINDING {c.id} {c.rule_id} [{c.severity}] {c.key}: {c.detail}")
    if len(findings) > 50:
        typer.echo(f"  ... and {len(findings) - 50} more in the report")
    problems = [c for c in result.cases if c.status not in (Status.FINDING_CANDIDATE, Status.NO_ISSUE_OBSERVED)]
    for status, group in sorted(
        {s: [c for c in problems if c.status is s] for s in {c.status for c in problems}}.items(),
        key=lambda kv: kv[0].value,
    ):
        typer.echo(f"  {status.value}: {len(group)} (first: {group[0].key}: {group[0].detail})")
    if saved is not None:
        typer.echo(f"run {result.run_id} saved to {saved}")
    typer.echo(f"exit code {result.exit_code}. Note: no_issue_observed does not mean the target is secure.")


async def _run_fixture(cfg: Any, variant: str | None, flaws: list[str] | None) -> RunResult:
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    async with LabFixtureTransport.open(cfg, variant=variant, flaws=flaws) as transport:
        return await run(cfg, transport)


async def _run_live(cfg: Any) -> RunResult:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    transport = LiveTransport.from_config(cfg, os.environ)
    try:
        return await run(cfg, transport)
    finally:
        await transport.aclose()


@app.command(name="test")
def check_cmd(
    config: Config_,
    transport: Annotated[
        str,
        typer.Option("--transport", "-t", help="fixture (in-process lab) or live (loopback only)."),
    ] = "fixture",
    runs_dir: Runs_ = DEFAULT_RUNS,
    no_save: Annotated[bool, typer.Option("--no-save", help="Print the summary but store nothing.")] = False,
    fixture_variant: Annotated[
        str | None,
        typer.Option("--fixture-variant", help="Lab adapter only: patched or vulnerable."),
    ] = None,
    fixture_flaws: Annotated[
        str | None,
        typer.Option(
            "--fixture-flaws",
            help="Lab adapter only: comma-separated flaw names (vulnerable variant).",
        ),
    ] = None,
) -> None:
    """Run the checks and judge every result against the declared policy."""
    if transport not in ("fixture", "live"):
        _fail("--transport must be 'fixture' or 'live'")
    cfg = _load(config)
    flaws = [f.strip() for f in fixture_flaws.split(",") if f.strip()] if fixture_flaws is not None else None
    try:
        result = asyncio.run(_run_fixture(cfg, fixture_variant, flaws) if transport == "fixture" else _run_live(cfg))
    except (TransportUnavailable, EgressViolation) as exc:
        _fail(str(exc))
    except Exception as exc:
        if os.environ.get("BOUNDARYCHECK_DEBUG"):
            traceback.print_exc()
        _fail(f"internal error ({type(exc).__name__}); set BOUNDARYCHECK_DEBUG=1 for a traceback")
    saved: Path | None = None
    if not no_save:
        try:
            saved = RunStore(runs_dir).save(result, to_json(result), to_markdown(result), _secrets_of(result, cfg))
        except (StoreError, SecretLeakError) as exc:
            _fail(str(exc))
    _summarize(result, saved)
    raise typer.Exit(result.exit_code)


def _secrets_of(result: RunResult, cfg: Any) -> list[str]:
    """Every credential value used in this run (re-read from the environment for the live transport;
    the fixture transport's tokens are scanned for inside the engine, which sees them first)."""
    return [
        os.environ[p.credential.env]
        for p in cfg.principals.values()
        if p.credential and p.credential.env and p.credential.env in os.environ
    ]


@app.command()
def report(
    run_id: Annotated[str, typer.Option("--run", help="Run id (see list-runs).")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="json or md.")] = "md",
    runs_dir: Runs_ = DEFAULT_RUNS,
) -> None:
    """Print a stored report."""
    try:
        typer.echo(RunStore(runs_dir).read_report(run_id, fmt), nl=False)
    except StoreError as exc:
        _fail(str(exc))


@app.command(name="list-runs")
def list_runs(runs_dir: Runs_ = DEFAULT_RUNS) -> None:
    """List stored runs, newest first."""
    try:
        rows = RunStore(runs_dir).list_runs()
    except StoreError as exc:
        _fail(str(exc))
    if not rows:
        typer.echo("no runs")
    for r in rows:
        typer.echo(
            f"{r['run_id']}  scope {r['scope_id']}  cases {r['total']}  exit {r['exit_code']}  "
            f"started {r['started_at']}"
        )


@app.command()
def purge(
    older_than: Annotated[str, typer.Option("--older-than", help="Age such as 30d, 12h or 45m.")],
    runs_dir: Runs_ = DEFAULT_RUNS,
) -> None:
    """Delete stored runs older than the given age. Only directories that look like runs are touched."""
    try:
        removed = RunStore(runs_dir).purge(parse_age(older_than))
    except StoreError as exc:
        _fail(str(exc))
    typer.echo(f"removed {len(removed)} run(s)" + "".join(f"\n  {r}" for r in removed))


if __name__ == "__main__":  # pragma: no cover
    app()
    sys.exit(0)
