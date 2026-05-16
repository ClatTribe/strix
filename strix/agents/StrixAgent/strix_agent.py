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

        return await self.agent_loop(task=task_description)
