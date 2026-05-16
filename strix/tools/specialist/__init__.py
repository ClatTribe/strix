"""Roadmap §8.5 Phase 1 — specialist-tool primitive.

Wires the registry decorator + result schema + first deterministic
(`llm=False`) specialist (`scan_misconfig`) into the existing tool
catalog. Importing this package registers `scan_misconfig` so the
agent can call it normally.

Background patterns this implements:
  * B.1 — primitive (no LLM) vs Agent-pattern (delegates to sub-LLM).
  * B.2 — bounded input at every tool boundary.
  * B.8 — tool-result schema discipline (`SpecialistResult`).

See [`single-agent.md §2.2`](../../single-agent.md) for the full
specification.
"""

# `__all__` is explicitly empty so `from .specialist import *` from
# `strix/tools/__init__.py` does NOT propagate the `registry` /
# `result` / `scan_misconfig` submodules into `strix.tools.*`. The
# `registry` submodule name in particular would otherwise shadow
# `strix.tools.registry` — broke `tests/tools/test_mitre_attack_
# tagging.py` and `tests/tools/test_tool_registration_modes.py` post-
# Phase-1 sweep. Side-effect import below still registers the tool.
__all__: list[str] = []

# Import side-effects register tools.
from strix.tools.specialist import async_dispatch as _async_dispatch  # noqa: F401
from strix.tools.specialist import scan_misconfig as _scan_misconfig  # noqa: F401
from strix.tools.specialist import scan_sqli as _scan_sqli  # noqa: F401  # Phase 3b
from strix.tools.specialist import scan_xss as _scan_xss  # noqa: F401  # Phase 3b
from strix.tools.specialist import scan_xxe as _scan_xxe  # noqa: F401  # Phase 6
from strix.tools.specialist import scan_auth_flow as _scan_auth_flow  # noqa: F401  # Phase 6
from strix.tools.specialist import scan_business_logic as _scan_business_logic  # noqa: F401  # Phase 5.6
from strix.tools.specialist import scan_blind_ssrf as _scan_blind_ssrf  # noqa: F401  # Phase 4.5
from strix.tools.specialist import scan_deserialization as _scan_deserialization  # noqa: F401  # Phase 4.4
from strix.tools.specialist import scan_blind_cmd_injection as _scan_blind_cmd_injection  # noqa: F401  # Phase 4.3
from strix.tools.specialist import scan_oob_xxe as _scan_oob_xxe  # noqa: F401  # Phase 4.2
from strix.tools.specialist import scan_idor as _scan_idor  # noqa: F401  # Phase 4.1
from strix.tools.specialist import scan_api_rate_limit as _scan_api_rate_limit  # noqa: F401  # api target type
from strix.tools.specialist import scan_api_bola as _scan_api_bola  # noqa: F401  # api target type / OWASP API1
from strix.tools.specialist import scan_api_bfla as _scan_api_bfla  # noqa: F401  # api target type / OWASP API5
from strix.tools.specialist import scan_api_mass_assignment as _scan_api_mass_assignment  # noqa: F401  # api target type / OWASP API3
from strix.tools.specialist import graphql_introspection_deep as _graphql_introspection_deep  # noqa: F401  # api target type / GraphQL deep
from strix.tools.specialist import scan_api_grpc_reflection as _scan_api_grpc_reflection  # noqa: F401  # api target type / gRPC
from strix.tools.specialist import scan_multi_role_auth as _scan_multi_role_auth  # noqa: F401  # Phase 3.1
from strix.tools.specialist import scan_oauth as _scan_oauth  # noqa: F401  # Phase 2.11
from strix.tools.specialist import scan_request_smuggling_active as _scan_request_smuggling_active  # noqa: F401  # Phase 2.10
from strix.tools.specialist import scan_subdomain_takeover_active as _scan_subdomain_takeover_active  # noqa: F401  # Phase 2.9
from strix.tools.specialist import scan_ldap_injection as _scan_ldap_injection  # noqa: F401  # Phase 2.8
from strix.tools.specialist import scan_xpath_injection as _scan_xpath_injection  # noqa: F401  # Phase 2.7
from strix.tools.specialist import scan_cmd_injection as _scan_cmd_injection  # noqa: F401  # Phase 2.6
from strix.tools.specialist import scan_secrets_in_response as _scan_secrets_in_response  # noqa: F401  # Phase 2.5
from strix.tools.specialist import scan_nosql_injection as _scan_nosql_injection  # noqa: F401  # Phase 2.4
from strix.tools.specialist import scan_ssti as _scan_ssti  # noqa: F401  # Phase 2.3
from strix.tools.specialist import scan_path_traversal as _scan_path_traversal  # noqa: F401  # Phase 2.2
from strix.tools.specialist import scan_ssrf as _scan_ssrf  # noqa: F401  # Phase 2.1
