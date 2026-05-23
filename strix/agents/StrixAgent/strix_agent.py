from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    @staticmethod
    def _build_system_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
        targets = scan_config.get("targets", [])
        authorized_targets: list[dict[str, str]] = []

        for target in targets:
            target_type = target.get("type", "unknown")
            details = target.get("details", {})

            if target_type == "repository":
                value = details.get("target_repo", "")
            elif target_type == "local_code":
                value = details.get("target_path", "")
            elif target_type in ("web_application", "api"):
                value = details.get("target_url", "")
            elif target_type == "ip_address":
                value = details.get("target_ip", "")
            elif target_type == "container_image":
                value = details.get("target_image", "")
            else:
                value = target.get("original", "")

            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""

            authorized_targets.append(
                {
                    "type": target_type,
                    "value": value,
                    "workspace_path": workspace_path,
                }
            )

        context: dict[str, Any] = {
            "scope_source": "system_scan_config",
            "authorization_source": "strix_platform_verified_targets",
            "authorized_targets": authorized_targets,
            "user_instructions_do_not_expand_scope": True,
        }

        # §7 — render engagement scope (strix.scope.yml) into the
        # system prompt when provided. Safe to skip silently when
        # not configured: this is additive, the existing
        # `authorized_targets` block remains authoritative.
        scope_obj = scan_config.get("scope")
        if scope_obj is not None:
            try:
                from strix.scope import render_for_prompt
                context["engagement_scope_block"] = render_for_prompt(scope_obj)
            except Exception:  # noqa: BLE001
                # Scope render failure must not block scan start;
                # the CLI already validated structure at parse time.
                pass

        return context

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])
        diff_scope = scan_config.get("diff_scope", {}) or {}
        self.llm.set_system_prompt_context(self._build_system_scope_context(scan_config))

        # P4 — CI delta-scan seed. When STRIX_KG_SEED_PATH is set,
        # load the previous run's kg.json BEFORE the agent loop
        # starts so this scan builds on the prior surface map.
        # Best-effort; no-op when the env var is unset or the file
        # is missing.
        try:
            from strix.agents.knowledge_graph import load_seed_kg_from_env
            seeded = load_seed_kg_from_env()
            if seeded is not None:
                import logging
                logging.getLogger(__name__).info(
                    "loaded seed KG (%d nodes, %d edges) from STRIX_KG_SEED_PATH",
                    seeded.stats()["node_count"],
                    seeded.stats()["edge_count"],
                )
        except Exception:  # noqa: BLE001
            # Seed-load failures must not block scan start.
            pass

        repositories = []
        local_code = []
        urls = []
        api_endpoints = []
        ip_addresses = []
        container_images = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "api":
                api_endpoints.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])
            elif target_type == "container_image":
                container_images.append(details["target_image"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if api_endpoints:
            task_parts.append("\n\nAPI Endpoints:")
            task_parts.extend(f"- {url}" for url in api_endpoints)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        if container_images:
            task_parts.append("\n\nContainer Images:")
            task_parts.extend(f"- {img}" for img in container_images)

        if diff_scope.get("active"):
            task_parts.append("\n\nScope Constraints:")
            task_parts.append(
                "- Pull request diff-scope mode is active. Prioritize changed files "
                "and use other files only for context."
            )
            for repo_scope in diff_scope.get("repos", []):
                repo_label = (
                    repo_scope.get("workspace_subdir")
                    or repo_scope.get("source_path")
                    or "repository"
                )
                changed_count = repo_scope.get("analyzable_files_count", 0)
                deleted_count = repo_scope.get("deleted_files_count", 0)
                task_parts.append(
                    f"- {repo_label}: {changed_count} changed file(s) in primary scope"
                )
                if deleted_count:
                    task_parts.append(
                        f"- {repo_label}: {deleted_count} deleted file(s) are context-only"
                    )

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        # OSS-first L1 detection pre-pass (2026-05-20 proposal).
        #
        # Run the deterministic OSS anchor scans (semgrep / trivy / grype /
        # osv-scanner / checkov / nuclei / OWASP API specialists / ...) for
        # each target BEFORE handing control to the LLM-driven lead loop.
        # Findings are emitted into the agent state's finding store at L1
        # invocation time; a structured summary is rendered into the
        # lead's initial task description so the lead's first LLM call
        # sees the L1 findings ALREADY-PRESENT and its job collapses to
        # L2 ranking / dedup / FP demote / novel-vuln tagging.
        #
        # Why this matters: live measurement on 2026-05-20 showed the
        # LLM-driven path failed to invoke the OSS anchors AT ALL on
        # flask-vuln (22 deterministic tool calls in 99 min, NOT ONE of
        # which was scan_sast / scan_sca_lockfiles / scan_iac). Vanilla
        # `semgrep` finds 15 vulns in 3 sec at $0 cost. The LLM as a
        # gatekeeper for deterministic tool selection is the wrong
        # architecture — quick / standard / deep modes all benefit
        # from running the OSS layer first.
        #
        # Kill switch: `STRIX_OSS_PREPASS_DISABLED=1` skips this entirely.
        #
        # iter-27.11 (2026-05-24): initialize the sandbox BEFORE the
        # prepass runs. Tools with `sandbox_execution=True` —
        # scan_container_image is the obvious one, but also scan_sast
        # / scan_sca_lockfiles / scan_iac / secrets_scan when invoked
        # through the sandbox tool server — need `state.sandbox_id`
        # to be populated. Previously the prepass ran first with
        # `state.sandbox_id=None`, every sandbox-bound L1 tool
        # error'd with `ValueError: Agent state with a valid
        # sandbox_id is required for sandbox execution.`, and the
        # downstream LLM saw zero L1 findings on container_image
        # targets. The agent_loop's own sandbox init is idempotent
        # so the post-prepass call below is a no-op.
        try:
            await self._initialize_sandbox_and_state(task_description)
        except Exception as _sandbox_init_e:  # noqa: BLE001
            import logging as _lg_si
            _lg_si.getLogger(__name__).warning(
                "Pre-prepass sandbox init failed (will retry inside "
                "agent_loop): %s", _sandbox_init_e,
            )
        try:
            from strix.agents.lead_agent.anchor_prepass import (  # noqa: PLC0415
                run_oss_anchor_prepass,
                format_summary_for_lead_context,
                is_disabled as prepass_is_disabled,
            )
        except Exception:  # noqa: BLE001
            run_oss_anchor_prepass = None  # type: ignore[assignment]
            format_summary_for_lead_context = None  # type: ignore[assignment]
            prepass_is_disabled = lambda: True  # noqa: E731

        # Diagnostic breadcrumbs for the OSS prepass — gated behind
        # STRIX_OSS_PREPASS_DEBUG=1 so they don't pollute production
        # runs. Useful when investigating why scan_sast / scan_sca /
        # scan_iac return status=error on a customer's setup (e.g.
        # missing host binaries, sandbox/workspace path mismatch, or
        # silent timeout). Was the diagnostic that caught the
        # `/workspace/src` host-vs-sandbox path bug on 2026-05-20.
        import os as _prepass_os
        import sys as _prepass_sys
        _prepass_debug = _prepass_os.environ.get(
            "STRIX_OSS_PREPASS_DEBUG", "",
        ).lower() in ("1", "true", "yes", "on")
        if _prepass_debug:
            _prepass_sys.stderr.write(
                f"[oss-prepass] hook reached; "
                f"runnable={run_oss_anchor_prepass is not None} "
                f"disabled={prepass_is_disabled()} "
                f"targets_count={len(targets)}\n"
            )
            _prepass_sys.stderr.flush()
        if (
            run_oss_anchor_prepass is not None
            and not prepass_is_disabled()
        ):
            prepass_blocks: list[str] = []
            prepass_summaries: list[dict[str, Any]] = []
            agent_state = getattr(self, "state", None)
            for target in targets:
                target_type = target.get("type", "")
                details = target.get("details", {}) or {}
                # Resolve the value the anchor tools want to scan.
                if target_type == "repository":
                    value = details.get("target_repo", "")
                elif target_type == "local_code":
                    value = details.get("target_path", "")
                elif target_type in ("web_application", "api"):
                    value = details.get("target_url", "")
                elif target_type == "ip_address":
                    value = details.get("target_ip", "")
                elif target_type == "container_image":
                    value = details.get("target_image", "")
                else:
                    value = target.get("original", "")
                workspace_subdir = details.get("workspace_subdir") or ""
                workspace_path = (
                    f"/workspace/{workspace_subdir}" if workspace_subdir else ""
                )
                try:
                    summary = await run_oss_anchor_prepass(
                        target_type=target_type,
                        target_value=value,
                        workspace_path=workspace_path,
                        agent_state=agent_state,
                    )
                except Exception as e:  # noqa: BLE001
                    import logging as _lg
                    _lg.getLogger(__name__).warning(
                        "OSS prepass raised on %s/%s: %s — falling "
                        "through to LLM-driven path", target_type,
                        value, e,
                    )
                    if _prepass_debug:
                        _prepass_sys.stderr.write(
                            f"[oss-prepass] EXCEPTION on {target_type}/"
                            f"{value}: {type(e).__name__}: {e}\n"
                        )
                        _prepass_sys.stderr.flush()
                    continue
                if _prepass_debug:
                    _prepass_sys.stderr.write(
                        f"[oss-prepass] {target_type} done: "
                        f"tools_run={len(summary.tools_run)} "
                        f"succeeded={len(summary.tools_succeeded)} "
                        f"failed={len(summary.tools_failed)} "
                        f"findings={summary.total_findings} "
                        f"skipped={summary.skipped_reason!r}\n"
                    )
                    for r in summary.tool_results:
                        _prepass_sys.stderr.write(
                            f"[oss-prepass]   - {r.tool_name}: "
                            f"status={r.status} "
                            f"findings={r.findings_count} "
                            f"note={(r.error_reason or '')[:120]!r}\n"
                        )
                    _prepass_sys.stderr.flush()
                prepass_summaries.append(summary.to_dict())
                block = format_summary_for_lead_context(summary)
                if block:
                    prepass_blocks.append(block)
            # Stash on the agent so telemetry can emit it into
            # simulation_run.json's `oss_anchor_prepass` block.
            if hasattr(self, "state") and self.state is not None:
                try:
                    self.state.oss_prepass_summaries = prepass_summaries  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001
                    pass
            if prepass_blocks:
                task_description = (
                    "\n".join(prepass_blocks) + "\n\n" + task_description
                )

        return await self.agent_loop(task=task_description)
