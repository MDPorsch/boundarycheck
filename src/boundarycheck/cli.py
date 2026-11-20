"""The command line: a thin layer over the library. Exit codes: 0 clean, 1 findings, 2 anything else."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from boundarycheck import __version__, authorization
from boundarycheck.config import ConfigError, load_config
from boundarycheck.engine import RunResult, run
from boundarycheck.evidence import RunStore, StoreError, parse_age
from boundarycheck.model import EgressViolation, Status, TransportUnavailable
from boundarycheck.netcheck import AddressRefused, EgressPolicy, parse_target_url
from boundarycheck.planner import plan
from boundarycheck.redact import SecretLeakError
from boundarycheck.report import to_json, to_markdown
from boundarycheck.sarif import action_lines, to_sarif
from boundarycheck.template import REMOTE_CONFIG, STARTER_CONFIG

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
    remote: Annotated[
        bool,
        typer.Option("--remote", help="A starter for ONE remote https host, with the authorization block."),
    ] = False,
) -> None:
    """Write an annotated, safe-by-default starter config."""
    try:
        with output.open("w" if force else "x", encoding="utf-8") as handle:
            handle.write(REMOTE_CONFIG if remote else STARTER_CONFIG)
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
        body = ""
        if c.action.body is not None:  # the presence and size of a body, never its content
            body = f" [JSON body, {len(json.dumps(c.action.body, separators=(',', ':')))} bytes]"
        typer.echo(
            f"{c.id} {c.action.method} {c.path}{body} as {c.principal or 'anonymous'} "
            f"-> expect {c.expected.outcome.value} ({c.expected.reason})"
        )
    writes = sum(1 for c in cases if c.action.is_write)
    note = f" ({writes} are writes: fixture transport only)" if writes else ""
    typer.echo(f"{len(cases)} requests planned{note}; none sent.")


@app.command()
def preflight(config: Config_) -> None:
    """Check a remote config and show what a run would do. Resolves the name; sends NO request."""
    from boundarycheck.transports.live import _system_resolver  # noqa: PLC0415

    cfg = _load(config)
    target = cfg.scope.target
    if target.base_url is None or not target.is_remote:
        typer.echo("ok: the target is loopback (or the in-process fixture): there is nothing remote to check.")
        return
    auth = cfg.scope.authorization
    typer.echo(f"target: {target.base_url}  (allowed host: {target.allowed_hosts[0]})")
    typer.echo(f"authorization: {authorization.describe(auth)}")
    try:
        authorization.check_window(auth, datetime.now(UTC))
    except authorization.AuthorizationError as exc:
        _fail(f"{exc}; nothing was resolved and nothing was sent")
    typer.echo("authorization window: open")
    _scheme, host, port, _remote = parse_target_url(target.base_url)
    policy = EgressPolicy.remote(host=host, port=port, allowed_networks=target.allowed_networks)
    try:
        addresses = [host] if _is_literal(host) else _system_resolver(host)
    except OSError:
        _fail("the host name could not be resolved")
    if not addresses:
        _fail("the host name did not resolve to any address")
    refused = 0
    for address in sorted(addresses):
        try:
            policy.check(address)
        except AddressRefused as exc:
            refused += 1
            typer.echo(f"  {address}: refused: {exc}")
        else:
            typer.echo(f"  {address}: acceptable")
    rate = target.effective_rate_limit_rps
    typer.echo(f"limits: {rate:g} requests per second, a budget of {target.request_budget} requests, GET and HEAD only")
    if refused:
        _fail(f"{refused} of {len(addresses)} address(es) are refused, so a run would send nothing")
    typer.echo("ok: a run would connect only to the acceptable address(es) above. No request was sent.")


def _is_literal(host: str) -> bool:
    from boundarycheck.netcheck import parse_address  # noqa: PLC0415

    try:
        parse_address(host)
    except AddressRefused:
        return False
    return True


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
    for note in result.limitations:
        if "--reads-only" in note or "not exercised" in note:
            typer.echo(f"  note: {note}")
    if saved is not None:
        typer.echo(f"run {result.run_id} saved to {saved}")
    typer.echo(f"exit code {result.exit_code}. Note: no_issue_observed does not mean the target is secure.")


async def _run_fixture(
    cfg: Any, variant: str | None, flaws: list[str] | None, reads_only: bool
) -> tuple[RunResult, list[str]]:
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    async with LabFixtureTransport.open(cfg, variant=variant, flaws=flaws) as transport:
        return await run(cfg, transport, reads_only=reads_only), []


def _remote_gate(cfg: Any, acknowledged: bool, transport: str) -> None:
    """A remote run needs the declared authorization, its window and the per-run acknowledgement.
    Checked BEFORE anything touches the network, not even a name lookup."""
    target = cfg.scope.target
    if transport != "live" or not target.is_remote:
        return
    if not acknowledged:
        _fail(
            f"{target.base_url} is a remote host: add --ack-authorization to confirm, for this run, that you "
            "are authorized to assess it (the authorization block in the config is what the report will quote)"
        )
    try:
        authorization.check_window(cfg.scope.authorization, datetime.now(UTC))
    except authorization.AuthorizationError as exc:
        _fail(str(exc))


async def _run_live(cfg: Any, reads_only: bool) -> tuple[RunResult, list[str]]:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    transport = LiveTransport.from_config(cfg, os.environ)  # the name is resolved here, once
    remote = cfg.scope.target.is_remote
    typer.echo(f"target: {transport.describe()}")
    for reason in transport.notes:
        typer.echo(f"note: {reason}")
    note: str | None = None
    if remote:
        auth = cfg.scope.authorization
        typer.echo(f"authorization: {authorization.describe(auth)}")
        note = authorization.attestation(auth, transport.describe())
    try:
        return await run(cfg, transport, reads_only=reads_only, attestation=note), transport.secrets()
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
    sarif_uri: Annotated[
        str | None,
        typer.Option(
            "--sarif-uri",
            help="The config file's path as it appears in your repository, for report.sarif (default: its file name).",
        ),
    ] = None,
    ack_authorization: Annotated[
        bool,
        typer.Option(
            "--ack-authorization",
            help="Remote targets only: confirm, for THIS run, that you are authorized to assess the host.",
        ),
    ] = False,
    reads_only: Annotated[
        bool,
        typer.Option(
            "--reads-only",
            help="Leave the declared write checks out (they need the fixture's state diff). The report says so.",
        ),
    ] = False,
) -> None:
    """Run the checks and judge every result against the declared policy."""
    if transport not in ("fixture", "live"):
        _fail("--transport must be 'fixture' or 'live'")
    cfg = _load(config)
    _remote_gate(cfg, ack_authorization, transport)
    flaws = [f.strip() for f in fixture_flaws.split(",") if f.strip()] if fixture_flaws is not None else None
    try:
        result, used = asyncio.run(
            _run_fixture(cfg, fixture_variant, flaws, reads_only)
            if transport == "fixture"
            else _run_live(cfg, reads_only)
        )
    except (TransportUnavailable, EgressViolation) as exc:
        _fail(str(exc))
    except Exception as exc:
        if os.environ.get("BOUNDARYCHECK_DEBUG"):
            traceback.print_exc()
        _fail(f"internal error ({type(exc).__name__}); set BOUNDARYCHECK_DEBUG=1 for a traceback")
    saved: Path | None = None
    if not no_save:
        try:
            saved = RunStore(runs_dir).save(
                result,
                to_json(result),
                to_markdown(result),
                [*used, *_env_secrets(cfg)],
                sarif=_sarif_text(result, config, sarif_uri),
            )
        except (StoreError, SecretLeakError) as exc:
            _fail(str(exc))
    _summarize(result, saved)
    raise typer.Exit(result.exit_code)


def _sarif_text(result: RunResult, config: Path, sarif_uri: str | None) -> str:
    """report.sarif: results point at the line of each action in the config file."""
    try:
        text = config.read_text(encoding="utf-8")[:262_144]
    except OSError:
        text = ""
    return to_sarif(result, config_uri=sarif_uri if sarif_uri is not None else config.name, lines=action_lines(text))


def _env_secrets(cfg: Any) -> list[str]:
    """Credential values named by env variables (the leak guard also gets the transport's own list, which
    covers keychain values; the fixture transport's tokens are scanned for inside the engine)."""
    return [
        os.environ[p.credential.env]
        for p in cfg.principals.values()
        if p.credential and p.credential.env and p.credential.env in os.environ
    ]


@app.command()
def report(
    run_id: Annotated[str, typer.Option("--run", help="Run id (see list-runs).")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="json, md or sarif.")] = "md",
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


keychain_app = typer.Typer(
    help="Store credentials in the operating system's keychain (optional extra).", no_args_is_help=True
)
app.add_typer(keychain_app, name="keychain")
Username_ = Annotated[
    str, typer.Option("--username", "-u", help="The keychain entry's username (for example alice@acme).")
]
Service_ = Annotated[str, typer.Option("--service", help="The keychain service name.")]


def _keychain_names(service: str, username: str) -> None:
    import re  # noqa: PLC0415

    from boundarycheck.config import KEYCHAIN_NAME  # noqa: PLC0415

    if not (re.fullmatch(KEYCHAIN_NAME, service) and re.fullmatch(KEYCHAIN_NAME, username)):
        _fail("the service and username are letters, digits and . _ @ + - only (at most 128 characters)")


@keychain_app.command("set")
def keychain_set(username: Username_, service: Service_ = "boundarycheck") -> None:
    """Store a credential. The value is typed at a hidden prompt: it never touches a file or a command line."""
    from boundarycheck import keychain  # noqa: PLC0415

    _keychain_names(service, username)
    try:
        keychain.backend()  # refuse a plaintext or missing store BEFORE asking for a secret
        first = typer.prompt("Value (hidden)", hide_input=True)
        if first != typer.prompt("Again (hidden)", hide_input=True):
            _fail("the two values do not match; nothing was stored")
        keychain.set_value(service, username, first)
    except keychain.KeychainError as exc:
        _fail(str(exc))
    typer.echo(
        f"stored in the operating-system keychain (service '{service}', username '{username}'). "
        "It was not shown or saved anywhere else."
    )


@keychain_app.command("check")
def keychain_check(username: Username_, service: Service_ = "boundarycheck") -> None:
    """Exit 0 if the entry exists, 1 if it does not. The value is never printed."""
    from boundarycheck import keychain  # noqa: PLC0415

    _keychain_names(service, username)
    try:
        present = keychain.exists(service, username)
    except keychain.KeychainError as exc:
        _fail(str(exc))
    typer.echo("present" if present else "not found")
    raise typer.Exit(0 if present else 1)


@keychain_app.command("delete")
def keychain_delete(username: Username_, service: Service_ = "boundarycheck") -> None:
    """Remove an entry."""
    from boundarycheck import keychain  # noqa: PLC0415

    _keychain_names(service, username)
    try:
        keychain.delete(service, username)
    except keychain.KeychainError as exc:
        _fail(str(exc))
    typer.echo("deleted")


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
