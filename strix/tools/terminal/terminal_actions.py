from typing import Any

from strix.tools.registry import register_tool


@register_tool
def terminal_execute(
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
) -> dict[str, Any]:
    """Run a shell command in the scan's terminal session.

    Per CLAUDE.md §1.5.7 — this is the PRIMITIVE escape hatch in the
    L2 catalog. Use it for ad-hoc inspection the anchor_prepass +
    other tools didn't cover. Per-asset canonical uses:

      * `repository` / `local_code`:
          - `grep -rn 'TODO\\|FIXME\\|XXX' src/`            (audit hot spots)
          - `find . -name '*.env*' -o -name 'config*.yaml'`  (config sweep)
          - `sed -n '40,80p' path/to/file.py`               (read excerpt)
          - `wc -l **/*.py`                                  (size sanity)

      * `ip_address`:
          - `nmap -sV -p 8080,8443 <ip>`                    (port follow-up)
          - `nc -v <ip> 6379`                                (raw service probe)
          - `curl -I http://<ip>:<port>`                    (HEAD test)

      * `container_image`:
          - `docker save <img> | tar -xC /tmp/img`          (mount for inspection)
          - `docker run --rm <img> cat /etc/passwd`         (manifest read)
          - `docker history <img>`                          (layer audit)

      * `domain`:
          - `dig +short <domain> NS`                        (ad-hoc DNS lookup)
          - `dig +short <domain> TXT`                       (SPF/DMARC raw)
          - `whois <domain>`                                (registration)
          - `host <subdomain>`                              (post-subfinder check)

    The terminal session is stateful — `terminal_id` lets you chain
    related commands (e.g., `cd repo && ...` then a follow-up `git
    log` in the same shell). Default session is "default".

    Args:
        command: shell command to run.
        is_input: True when sending input to a process already running
            in the terminal (e.g., responding to a prompt) rather than
            starting a new command.
        timeout: per-command timeout in seconds. None uses the manager
            default. Long-running follow-ups should set this explicitly.
        terminal_id: which terminal session to target. Default
            "default". Use a custom ID to keep concurrent investigations
            isolated.
        no_enter: when True, send the command without a trailing
            newline (rarely needed; useful for tab-completion probes).

    Returns:
        ```
        {status: "ok"|"error", exit_code: int|None,
         content: str, working_dir: str|None, ...}
        ```
        On ValueError / RuntimeError (manager-level errors), returns
        an error dict — never raises.
    """
    from .terminal_manager import get_terminal_manager

    manager = get_terminal_manager()

    try:
        return manager.execute_command(
            command=command,
            is_input=is_input,
            timeout=timeout,
            terminal_id=terminal_id,
            no_enter=no_enter,
        )
    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }
