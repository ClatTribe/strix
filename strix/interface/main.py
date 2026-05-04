#!/usr/bin/env python3
"""
Strix Agent Interface
"""

import argparse
import asyncio
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import litellm
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import Config, apply_saved_config, save_current_config
from strix.config.config import resolve_llm_config
from strix.llm.utils import resolve_strix_model


apply_saved_config()

from strix.interface.cli import run_cli  # noqa: E402
from strix.interface.preflight import (  # noqa: E402
    all_network_targets_unreachable,
    preflight_check_targets,
    render_preflight_panel,
)
from strix.interface.tui import run_tui  # noqa: E402
from strix.interface.utils import (  # noqa: E402
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    process_pull_line,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
    validate_llm_response,
)
from strix.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME  # noqa: E402
from strix.telemetry import posthog  # noqa: E402
from strix.telemetry.tracer import get_global_tracer  # noqa: E402


logging.getLogger().setLevel(logging.ERROR)


def validate_environment() -> None:  # noqa: PLR0912, PLR0915
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    strix_llm = Config.get("strix_llm")
    uses_strix_models = strix_llm and strix_llm.startswith("strix/")

    if not strix_llm:
        missing_required_vars.append("STRIX_LLM")

    has_base_url = uses_strix_models or any(
        [
            Config.get("llm_api_base"),
            Config.get("openai_api_base"),
            Config.get("litellm_base_url"),
            Config.get("ollama_api_base"),
        ]
    )

    if not Config.get("llm_api_key"):
        missing_optional_vars.append("LLM_API_KEY")

    if not has_base_url:
        missing_optional_vars.append("LLM_API_BASE")

    if not Config.get("perplexity_api_key"):
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if not Config.get("strix_reasoning_effort"):
        missing_optional_vars.append("STRIX_REASONING_EFFORT")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "STRIX_LLM":
                error_text.append("• ", style="white")
                error_text.append("STRIX_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use with litellm (e.g., 'openai/gpt-5.4')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("STRIX_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export STRIX_LLM='openai/gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# not needed for local models, Vertex AI, AWS, etc.\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


async def warm_up_llm() -> None:
    console = Console()

    try:
        model_name, api_key, api_base = resolve_llm_config()
        litellm_model, _ = resolve_strix_model(model_name)
        litellm_model = litellm_model or model_name

        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with just 'OK'."},
        ]

        llm_timeout = int(Config.get("llm_timeout") or "300")

        completion_kwargs: dict[str, Any] = {
            "model": litellm_model,
            "messages": test_messages,
            "timeout": llm_timeout,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = litellm.completion(**completion_kwargs)

        validate_llm_response(response)

    except Exception as e:  # noqa: BLE001
        error_text = Text()
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  strix --target https://example.com

  # GitHub repository analysis
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # Local code analysis
  strix --target ./my-project

  # Domain penetration test
  strix --target example.com

  # IP address penetration test
  strix --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Custom instructions (inline)
  strix --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "Scope mode for code targets: "
            "'auto' enables PR diff-scope in CI/headless runs, "
            "'diff' forces changed-files scope, "
            "'full' disables diff-scope."
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "Target branch or commit to compare against (e.g., origin/main). "
            "Defaults to the repository's default branch."
        ),
    )

    # Roadmap §3 PR #117 — `--branch <ref>` for repository targets.
    parser.add_argument(
        "--branch",
        type=str,
        default=None,
        help=(
            "Branch / tag / commit to clone (e.g. `develop`, `staging`, "
            "`v1.2.3`). Default: repository's default branch. "
            "Adds `--branch <ref> --single-branch` to the underlying git "
            "clone — keeps the working tree small and ensures the scan "
            "doesn't pick up content from unrelated branches. Only "
            "applies to `repository` targets."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.strix/cli-config.json",
    )

    parser.add_argument(
        "--preflight",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Run a fast DNS + TCP reachability check on network targets before "
            "spawning the agent loop. If every network target is unreachable, "
            "exit with a clear diagnostic instead of running for many minutes. "
            "Disable with --no-preflight."
        ),
    )

    parser.add_argument(
        "--dns-only",
        action="store_true",
        default=False,
        help=(
            "Domain-target passive-recon mode. Skip every step that issues "
            "HTTP/TCP probes to the target's own hosts: subdomain triage, "
            "subdomain-takeover fingerprinting, cloud-asset HEAD probes, "
            "MX SMTP banner grab, tech-stack fingerprinting. Pure DNS lookups "
            "and third-party API calls (passive DNS, reverse-IP, code-search, "
            "SaaS leak discovery) still run. Use when the engagement scope "
            "limits active probing or when surface-mapping a target you don't "
            "yet have authorization to probe."
        ),
    )

    auth_group = parser.add_argument_group(
        "authentication",
        (
            "Credentials are forwarded to the sandbox as environment variables "
            "and injected by the HTTP tool at request time. They are NEVER "
            "written to events.jsonl, the agent's prompt, or tool outputs. "
            "The agent receives a system-prompt note that credentials are "
            "configured, not the values themselves."
        ),
    )
    auth_group.add_argument(
        "--auth-cookie",
        type=str,
        default=None,
        metavar="VALUE",
        help=(
            "Cookie header value injected on every HTTP request to in-scope "
            "targets (e.g. 'session=abc123; auth=xyz'). Use for cookie-based "
            "session auth."
        ),
    )
    auth_group.add_argument(
        "--auth-bearer",
        type=str,
        default=None,
        metavar="TOKEN",
        help=(
            "Bearer token injected as 'Authorization: Bearer <token>' on every "
            "HTTP request to in-scope targets."
        ),
    )
    auth_group.add_argument(
        "--auth-basic",
        type=str,
        default=None,
        metavar="USER:PASS",
        help=(
            "Basic-auth credentials injected as 'Authorization: Basic <b64>' on "
            "every HTTP request to in-scope targets. Format: 'username:password'."
        ),
    )
    auth_group.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help=(
            "Custom header injected on every HTTP request to in-scope targets. "
            "Repeatable. Use for API keys ('X-API-Key:abc'), WAF bypass, "
            "X-Forwarded-For, etc. Sensitive values are forwarded via env (same "
            "as --auth-* flags) and never logged."
        ),
    )

    crawl_group = parser.add_argument_group("crawl steering")
    crawl_group.add_argument(
        "--seed-url",
        action="append",
        default=[],
        metavar="URL",
        help=(
            "Extra start URL for the BFS crawler in addition to the target. "
            "Repeatable. Use to point the crawl at non-discoverable surfaces "
            "(e.g. '--seed-url https://app/admin --seed-url https://app/api'). "
            "Forwarded to bfs_crawl via STRIX_SEED_URLS env."
        ),
    )
    crawl_group.add_argument(
        "--openapi",
        type=str,
        default=None,
        metavar="URL",
        help=(
            "OpenAPI 2.x / 3.x spec URL (JSON only — YAML not supported in the "
            "sandbox). When supplied, paths from the spec are seeded into the "
            "BFS crawl. Forwarded via STRIX_OPENAPI_URL env."
        ),
    )

    safety_group = parser.add_argument_group("production safety")
    safety_group.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        metavar="GLOB",
        help=(
            "Path glob the HTTP tool will REFUSE to request, regardless of "
            "what the agent decides. Repeatable. Use for destructive endpoints: "
            "'/api/billing/charge', '/admin/delete*', '/users/*/destroy'. "
            "Hard rule, not a hint — emits a tool.skipped event with reason "
            "'excluded' on attempted access. Glob syntax: fnmatch (* matches any "
            "segment, ? matches one char). Path-only matching (query string "
            "ignored)."
        ),
    )
    safety_group.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        metavar="QPS",
        help=(
            "Hard cap on outbound HTTP requests per second from the sandbox "
            "(applies across the whole scan, not per-host). Enforced inside the "
            "HTTP tool layer, not just hinted to the agent. Default: unlimited. "
            "Recommended for production traffic: 5-10 qps."
        ),
    )
    # Roadmap §4 PR #113 — run-level cost / token caps.
    safety_group.add_argument(
        "--max-cost",
        type=float,
        default=None,
        metavar="USD",
        help=(
            "Hard cap on total LLM spend for the run (USD). Strix exits "
            "cleanly with code 3 when the cumulative cost crosses the cap, "
            "emitting `run.terminated`. Findings emitted up to that point "
            "are still in vulnerabilities.json — the run is partial. "
            "Default: unlimited."
        ),
    )
    safety_group.add_argument(
        "--max-input-tokens",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Hard cap on cumulative input tokens for the run. Same self-exit "
            "+ exit-code-3 contract as --max-cost. Use when your billing is "
            "token-denominated (most providers) and you need a deterministic "
            "stop independent of fluctuating $-per-token. Default: unlimited."
        ),
    )

    # Roadmap §4 PR #121 — --quiet for server-side / non-TTY usage.
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help=(
            "Suppress Rich panels and ANSI escapes from console output. "
            "events.jsonl, vulnerabilities.json, and run_meta.json are written "
            "exactly as before — only the human-facing TTY output is silenced. "
            "Forces --non-interactive (the TUI is incompatible with quiet mode). "
            "Use for server-side / CI runs where the terminal is non-TTY and "
            "Rich panels become escape-code pollution in logs."
        ),
    )

    args = parser.parse_args()

    # --quiet forces --non-interactive (the TUI requires a tty).
    if args.quiet:
        args.non_interactive = True

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:  # noqa: BLE001
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.targets_info = []
    for target in args.target:
        try:
            target_type, target_dict = infer_target_type(target)

            if target_type == "local_code":
                display_target = target_dict.get("target_path", target)
            else:
                display_target = target

            args.targets_info.append(
                {"type": target_type, "details": target_dict, "original": display_target}
            )
        except ValueError:
            parser.error(f"Invalid target '{target}'")

    assign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    return args


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    # Roadmap §4 PR #121 — --quiet skips the Rich panel entirely.
    # events.jsonl / vulnerabilities.json / run_meta.json are
    # untouched (they're tracer-driven file writes, not console).
    if getattr(args, "quiet", False):
        return

    console = Console()
    tracer = get_global_tracer()

    scan_completed = False
    if tracer and tracer.scan_results:
        scan_completed = tracer.scan_results.get("scan_completed", False)

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    stats_text = build_final_stats_text(tracer)

    panel_parts = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]STRIX",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print("[#60a5fa]strix.ai[/]  [dim]·[/]  [#60a5fa]discord.gg/strix-ai[/]")
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    if image_exists(client, Config.get("strix_image")):  # type: ignore[arg-type]
        return

    console.print()
    console.print(f"[dim]Pulling image[/] {Config.get('strix_image')}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(Config.get("strix_image"), stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {Config.get('strix_image')}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def apply_config_override(config_path: str) -> None:
    # Clear env vars that were automatically applied from the default config file
    # so they don't leak into the custom config context.
    for var_name in Config._applied_from_default:
        os.environ.pop(var_name, None)
    Config._applied_from_default = {}

    Config._config_file_override = validate_config_file(config_path)
    apply_saved_config(force=True)


def persist_config() -> None:
    if Config._config_file_override is None:
        save_current_config()


def run_preflight_or_exit(args: argparse.Namespace) -> None:
    """Probe network targets for reachability before any expensive setup.

    On all-unreachable: print a panel and exit 1.
    On partial-unreachable: print a panel and prune the unreachable targets
    from `args.targets_info` so the scan continues with what's reachable.
    On all-reachable (or all-skipped code targets): print a brief one-liner.
    """
    console = Console()
    network_targets = [t for t in args.targets_info if t["type"] in ("web_application", "ip_address")]
    if not network_targets:
        return  # nothing to probe — only code targets

    console.print()
    console.print("[dim]Preflight reachability check ...[/dim]")
    results = preflight_check_targets(args.targets_info)

    if all_network_targets_unreachable(results):
        body = Text()
        body.append("PREFLIGHT FAILED — every network target is unreachable.\n\n", style="bold red")
        body.append(render_preflight_panel(results), style="white")
        body.append(
            "\n\nThis usually means: target offline, firewall, DNS misconfig, or wrong target spec.\n"
            "Re-run with --no-preflight to bypass this check.",
            style="dim",
        )
        panel = Panel(
            body, title="[bold white]STRIX", title_align="left", border_style="red", padding=(1, 2)
        )
        console.print(panel)
        sys.exit(1)

    unreachable = [r for r in results if r.status in ("dns_failed", "no_open_ports")]
    if unreachable:
        body = Text()
        body.append(
            "PREFLIGHT WARNING — some network targets are unreachable.\n"
            "Continuing with the reachable subset.\n\n",
            style="bold yellow",
        )
        body.append(render_preflight_panel(results), style="white")
        panel = Panel(
            body,
            title="[bold white]STRIX",
            title_align="left",
            border_style="yellow",
            padding=(1, 2),
        )
        console.print(panel)
        unreachable_originals = {r.target for r in unreachable}
        args.targets_info = [
            t for t in args.targets_info if t.get("original") not in unreachable_originals
        ]
        return

    # All reachable — quiet one-liner.
    reachable_count = sum(1 for r in results if r.status == "reachable")
    console.print(f"[green]✓ Preflight: {reachable_count}/{len(network_targets)} network target(s) reachable.[/green]")


def main() -> None:  # noqa: PLR0912, PLR0915
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    if args.config:
        apply_config_override(args.config)

    if args.preflight:
        run_preflight_or_exit(args)

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    persist_config()

    args.run_name = generate_run_name(args.targets_info)

    for target_info in args.targets_info:
        if target_info["type"] == "repository":
            repo_url = target_info["details"]["target_repo"]
            dest_name = target_info["details"].get("workspace_subdir")
            cloned_path = clone_repository(
                repo_url,
                args.run_name,
                dest_name,
                branch=getattr(args, "branch", None),
            )
            target_info["details"]["cloned_repo_path"] = cloned_path
            # Roadmap §3 PR #117: surface the resolved ref so consumers
            # can confirm what was scanned. The actual ref is discoverable
            # via `git -C <cloned_path> rev-parse HEAD`; we record the
            # caller's intent here.
            if getattr(args, "branch", None):
                target_info["details"]["branch"] = args.branch

    args.local_sources = collect_local_sources(args.targets_info)
    try:
        diff_scope = resolve_diff_scope_context(
            local_sources=args.local_sources,
            scope_mode=args.scope_mode,
            diff_base=args.diff_base,
            non_interactive=args.non_interactive,
        )
    except ValueError as e:
        console = Console()
        error_text = Text()
        error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append(str(e), style="white")

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)

    args.diff_scope = diff_scope.metadata
    if diff_scope.instruction_block:
        if args.instruction:
            args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
        else:
            args.instruction = diff_scope.instruction_block

    if args.dns_only:
        # The env var is the load-bearing signal: domain_recon_pipeline reads
        # STRIX_DNS_ONLY=1 and forces dns_only=True regardless of how the
        # agent invokes the tool. Sandbox runtime forwards STRIX_* env vars
        # to the container.
        os.environ["STRIX_DNS_ONLY"] = "1"
        dns_only_block = (
            "## Active scope: passive recon only (--dns-only)\n\n"
            "Do NOT issue HTTP/TCP probes against the target's own hosts. "
            "Specifically: avoid subdomain HEAD probes, takeover fingerprint "
            "fetches, cloud-asset HEAD probes, SMTP banner grabs, and "
            "tech-stack HTTP fingerprinting. DNS lookups and third-party "
            "API calls (passive DNS, reverse-IP, code-search, SaaS leak "
            "discovery) are allowed. When invoking domain_recon_pipeline, "
            "pass dns_only=True. Findings will be limited to what passive "
            "recon can establish — that is intentional."
        )
        args.instruction = (
            f"{dns_only_block}\n\n{args.instruction}" if args.instruction else dns_only_block
        )

    # Auth + production-safety flags. Values are forwarded to the sandbox
    # as env vars (see docker_runtime.py) and read by the HTTP tool layer
    # at request time. They are NEVER written to events.jsonl, the agent
    # prompt, or tool outputs — only a content-free note is added to the
    # instruction telling the agent that credentials are configured.
    auth_configured = []
    if args.auth_cookie:
        os.environ["STRIX_AUTH_COOKIE"] = args.auth_cookie
        auth_configured.append("session cookie (`--auth-cookie`)")
    if args.auth_bearer:
        os.environ["STRIX_AUTH_BEARER"] = args.auth_bearer
        auth_configured.append("bearer token (`--auth-bearer`)")
    if args.auth_basic:
        os.environ["STRIX_AUTH_BASIC"] = args.auth_basic
        auth_configured.append("HTTP basic auth (`--auth-basic`)")
    if args.header:
        # Forward as a JSON-encoded list to preserve ordering + colons in
        # values. The HTTP-tool side parses it back.
        import json as _json

        os.environ["STRIX_HEADERS"] = _json.dumps(args.header)
        # The header *names* are not sensitive (auditable); values stay in
        # the env var. We surface the names in the instruction so the agent
        # knows which headers it'll see on requests.
        names = []
        for h in args.header:
            if ":" in h:
                names.append(h.split(":", 1)[0].strip())
        if names:
            auth_configured.append(f"custom headers: {', '.join(names)}")

    if args.exclude_path:
        import json as _json

        os.environ["STRIX_EXCLUDE_PATHS"] = _json.dumps(args.exclude_path)

    if args.rate_limit is not None:
        if args.rate_limit <= 0:
            console = Console()
            console.print("[red]--rate-limit must be a positive number (qps).[/red]")
            sys.exit(2)
        os.environ["STRIX_RATE_LIMIT"] = str(args.rate_limit)

    # Roadmap §4 PR #113 — run-level cost / token caps. The
    # `strix.llm.run_budget` module reads these env vars on every
    # `is_run_budget_exceeded()` call so they plumb through Docker
    # sandbox boundaries the same way the rest of STRIX_* args do.
    if getattr(args, "max_cost", None) is not None:
        if args.max_cost <= 0:
            console = Console()
            console.print("[red]--max-cost must be a positive USD amount.[/red]")
            sys.exit(2)
        os.environ["STRIX_MAX_COST_USD"] = str(args.max_cost)
    if getattr(args, "max_input_tokens", None) is not None:
        if args.max_input_tokens <= 0:
            console = Console()
            console.print("[red]--max-input-tokens must be a positive integer.[/red]")
            sys.exit(2)
        os.environ["STRIX_MAX_INPUT_TOKENS_RUN"] = str(args.max_input_tokens)

    # Roadmap §4 PR #121 — propagate --quiet via env so any sub-
    # process / sandbox inherits it and suppresses Rich panels.
    if getattr(args, "quiet", False):
        os.environ["STRIX_QUIET"] = "1"

    crawl_steering: list[str] = []
    if args.seed_url:
        os.environ["STRIX_SEED_URLS"] = ",".join(args.seed_url)
        crawl_steering.append(f"{len(args.seed_url)} seed URL(s) (`--seed-url`)")
    if args.openapi:
        os.environ["STRIX_OPENAPI_URL"] = args.openapi
        crawl_steering.append(f"OpenAPI spec at `{args.openapi}` (`--openapi`)")

    instruction_blocks: list[str] = []
    if auth_configured:
        instruction_blocks.append(
            "## Authentication credentials configured\n\n"
            "The user has supplied credentials via --auth-* / --header flags. The "
            "HTTP tool layer injects them automatically on every outbound "
            "request to in-scope targets — you do NOT need to (and CANNOT) "
            "construct the credential values yourself. The values are deliberately "
            "withheld from your context for security.\n\n"
            "Configured: " + "; ".join(auth_configured) + ".\n\n"
            "Treat the application as authenticated for the duration of the scan. "
            "If you see a login form or 401/403 response on a path that should be "
            "accessible, that is a finding (auth not properly configured for that "
            "surface), not a reason to ask the user for credentials."
        )
    if args.exclude_path:
        instruction_blocks.append(
            "## Excluded paths (production safety)\n\n"
            "The HTTP tool layer will REFUSE to request the following path globs, "
            "regardless of any reasoning you produce:\n\n"
            + "\n".join(f"- `{p}`" for p in args.exclude_path)
            + "\n\nDo not attempt to bypass via path-encoding tricks — the rule "
            "is enforced after URL normalization. Respect the user's intent: "
            "these paths are excluded because they are destructive or out-of-scope."
        )
    if args.rate_limit is not None:
        instruction_blocks.append(
            f"## Rate limit ({args.rate_limit:g} qps)\n\n"
            f"The HTTP tool layer hard-throttles outbound requests at "
            f"{args.rate_limit:g} requests/second. Plan your testing around this "
            f"cap — don't burst-fan-out probes."
        )
    if crawl_steering:
        steering_lines = "\n".join(f"- {s}" for s in crawl_steering)
        if args.seed_url:
            steering_lines += "\n\n  Seeds:\n" + "\n".join(f"  - `{u}`" for u in args.seed_url)
        instruction_blocks.append(
            "## Crawl steering configured\n\n"
            "The user has supplied crawl-steering inputs that the `bfs_crawl` tool "
            "consumes automatically (no need to thread them through manually):\n\n"
            f"{steering_lines}\n\n"
            "When you invoke `bfs_crawl(target=...)` for any web_application target, "
            "these are picked up from the environment. Override only when the agent's "
            "own reasoning surfaces additional URLs to seed."
        )
    if instruction_blocks:
        block = "\n\n".join(instruction_blocks)
        args.instruction = (
            f"{block}\n\n{args.instruction}" if args.instruction else block
        )

    is_whitebox = bool(args.local_sources)

    # Roadmap §4 PR #114 — install SIGTERM / SIGINT handlers BEFORE
    # the agent loop starts so a cancel from a wrapper's "cancel
    # scan" button is caught even if the user clicks during the
    # very-early Docker-image-pull phase.
    try:
        from strix.interface.cancel_handler import install_handlers

        install_handlers()
    except Exception:  # noqa: BLE001
        # Best-effort. The fallback is the default Python signal
        # handlers (sys.exit on SIGTERM with no event emission).
        pass

    posthog.start(
        model=Config.get("strix_llm"),
        scan_mode=args.scan_mode,
        is_whitebox=is_whitebox,
        interactive=not args.non_interactive,
        has_instructions=bool(args.instruction),
    )

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as e:
        exit_reason = "error"
        posthog.error("unhandled_exception", str(e))
        raise
    finally:
        tracer = get_global_tracer()
        if tracer:
            posthog.end(tracer, exit_reason=exit_reason)

    results_path = Path("strix_runs") / args.run_name
    display_completion_message(args, results_path)

    if args.non_interactive:
        # Roadmap §4 PR #114 — clean SIGTERM / SIGINT cancel exit.
        # If the user/wrapper cancelled the scan, exit with the
        # documented signal-derived code (130 for SIGINT, 143 for
        # SIGTERM) instead of 0/2/3. Wrappers' "cancel scan" buttons
        # rely on this contract to distinguish "user cancelled" from
        # "real failure".
        try:
            from strix.interface.cancel_handler import (
                emit_run_cancelled_event_once,
                get_exit_code_for_cancel,
            )

            cancel_exit = get_exit_code_for_cancel()
            if cancel_exit is not None:
                # Defensive emit in case the agent loop never ran
                # long enough to fire the event itself.
                emit_run_cancelled_event_once()
                sys.exit(cancel_exit)
        except Exception:  # noqa: BLE001
            pass

        # Roadmap §4 PR #113 — `--max-cost` / `--max-input-tokens`
        # self-exit. When the run-level budget tripped during the
        # scan, exit with the documented EXIT_BUDGET_EXCEEDED (3)
        # rather than 0/2. Findings emitted up to the termination
        # point are still in vulnerabilities.json — the run is
        # partial.
        try:
            from strix.interface.exit_codes import EXIT_BUDGET_EXCEEDED
            from strix.llm.run_budget import is_run_budget_exceeded

            exceeded, _reason = is_run_budget_exceeded()
            if exceeded:
                sys.exit(EXIT_BUDGET_EXCEEDED)
        except Exception:  # noqa: BLE001
            # Bookkeeping failure should never block the normal exit path.
            pass

        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
