"""
MCP02:2025 - Privilege Escalation via Scope Creep
==================================================
Demonstrates Scenario A: Accidental Escalation (Read-Only → Write)

The story:
  A DevOps AI agent is deployed with read-only scope to browse the codebase.
  The MCP server records this scope but never enforces it.
  The agent can silently call write tools (merge PRs) despite being read-only.

Vulnerable: Scope is stored but never checked before tool execution.
Mitigated:  Scope is enforced — write actions blocked for read-only agents.

Real GitHub API calls using tokens stored as Railway environment variables:
  GITHUB_READ_TOKEN   — PAT with public_repo (read) scope
  GITHUB_WRITE_TOKEN  — PAT with full repo (write) scope
  GITHUB_REPO_OWNER   — GitHub username / org
  GITHUB_REPO_NAME    — Repository name
"""

import os
import requests
from datetime import datetime, timezone

# ── GitHub config from Railway environment variables ──────────────────────────
GITHUB_READ_TOKEN  = os.environ.get("GITHUB_READ_TOKEN", "")
GITHUB_WRITE_TOKEN = os.environ.get("GITHUB_WRITE_TOKEN", "")
GITHUB_REPO_OWNER  = os.environ.get("GITHUB_REPO_OWNER", "")
GITHUB_REPO_NAME   = os.environ.get("GITHUB_REPO_NAME", "")
GITHUB_API_BASE    = "https://api.github.com"

# ── In-memory agent registries ────────────────────────────────────────────────
_agent_registry: dict = {}    # VULNERABLE: scope recorded but never enforced
_enforced_registry: dict = {} # MITIGATED:  scope recorded and enforced


def register(mcp):

    # =========================================================================
    # SCENARIO A — Accidental Escalation (Read-Only → Write)
    # =========================================================================

    @mcp.tool(name="mcp02_register_agent_vulnerable")
    def register_agent_vulnerable(agent_id: str, scope: str) -> str:
        """
        [VULNERABLE] Register an AI agent with a declared scope.
        Scope is stored in memory but never validated on subsequent tool calls.
        Any agent can call any tool regardless of its registered scope.
        """
        _agent_registry[agent_id] = {
            "scope": scope,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        return (
            f"[VULNERABLE] Agent '{agent_id}' registered with scope: '{scope}'.\n"
            f"Warning: Scope is stored but NOT enforced — all tools remain accessible."
        )

    @mcp.tool(name="mcp02_register_agent_mitigated")
    def register_agent_mitigated(agent_id: str, scope: str) -> str:
        """
        [MITIGATED] Register an AI agent with an enforced scope.
        All subsequent tool calls will be validated against this declared scope.
        Write/admin actions are blocked for read-only agents at the server level.
        """
        _enforced_registry[agent_id] = {
            "scope": scope,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        return (
            f"[MITIGATED] Agent '{agent_id}' registered with enforced scope: '{scope}'.\n"
            f"Server will validate all actions against this scope before execution."
        )

    @mcp.tool(name="mcp02_read_repo_vulnerable")
    def read_repo_vulnerable(agent_id: str) -> str:
        """
        [VULNERABLE] List repository contents via GitHub API.
        Uses read-only token. No scope check performed — agent identity not verified.
        """
        headers = {
            "Authorization": f"token {GITHUB_READ_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/contents/"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return f"GitHub API error {response.status_code}: {response.text}"

        items = response.json()
        files = [i["name"] for i in items if i["type"] == "file"]
        dirs  = [i["name"] + "/" for i in items if i["type"] == "dir"]
        agent_scope = _agent_registry.get(agent_id, {}).get("scope", "not registered")

        return (
            f"[VULNERABLE] Agent '{agent_id}' (declared scope: {agent_scope}) read repo:\n"
            f"Repo: {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}\n"
            f"Directories: {dirs}\n"
            f"Files: {files}"
        )

    @mcp.tool(name="mcp02_read_repo_mitigated")
    def read_repo_mitigated(agent_id: str) -> str:
        """
        [MITIGATED] List repository contents via GitHub API.
        Requires agent to be registered. Read access is permitted for all scopes.
        """
        if agent_id not in _enforced_registry:
            return (
                f"[MITIGATED] Agent '{agent_id}' is not registered. "
                f"Call mcp02_register_agent_mitigated first."
            )

        headers = {
            "Authorization": f"token {GITHUB_READ_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/contents/"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return f"GitHub API error {response.status_code}: {response.text}"

        items = response.json()
        files = [i["name"] for i in items if i["type"] == "file"]
        dirs  = [i["name"] + "/" for i in items if i["type"] == "dir"]
        agent_scope = _enforced_registry[agent_id]["scope"]

        return (
            f"[MITIGATED] Agent '{agent_id}' (enforced scope: {agent_scope}) read repo:\n"
            f"Repo: {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}\n"
            f"Directories: {dirs}\n"
            f"Files: {files}\n"
            f"Read access: PERMITTED for scope '{agent_scope}'"
        )

    @mcp.tool(name="mcp02_merge_pr_vulnerable")
    def merge_pr_vulnerable(agent_id: str, pr_number: int) -> str:
        """
        [VULNERABLE] Merge a GitHub pull request using the write token.
        NO scope check — executes regardless of the agent's declared scope.
        A read-only agent can silently merge PRs, introducing unreviewed code.
        """
        agent_scope = _agent_registry.get(agent_id, {}).get("scope", "not registered")

        headers = {
            "Authorization": f"token {GITHUB_WRITE_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}/merge"
        payload = {
            "commit_title": f"[MCP02 Demo] Merged by agent '{agent_id}' (scope: {agent_scope})",
            "merge_method": "merge"
        }
        response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            sha = response.json().get("sha", "N/A")
            return (
                f"[VULNERABLE] ⚠️  PR #{pr_number} MERGED SUCCESSFULLY.\n"
                f"Agent: '{agent_id}'\n"
                f"Declared scope: '{agent_scope}'\n"
                f"Scope was NEVER checked — read-only agent performed a write action.\n"
                f"Merge SHA: {sha}\n"
                f"Risk: Unreviewed code is now in main. CI/CD may auto-deploy it."
            )
        elif response.status_code == 405:
            return f"PR #{pr_number} is not mergeable (already merged or conflicts exist)."
        else:
            return f"GitHub API error {response.status_code}: {response.text}"

    @mcp.tool(name="mcp02_merge_pr_mitigated")
    def merge_pr_mitigated(agent_id: str, pr_number: int) -> str:
        """
        [MITIGATED] Merge a GitHub pull request — scope enforced before any API call.
        Read-only agents are blocked at the server level. No GitHub call is made.
        Only agents with 'write' or 'admin' scope can merge.
        """
        if agent_id not in _enforced_registry:
            return (
                f"[MITIGATED] Agent '{agent_id}' is not registered. "
                f"Call mcp02_register_agent_mitigated first."
            )

        agent_scope = _enforced_registry[agent_id]["scope"]

        # Enforce scope — block write actions for read-only agents
        if agent_scope not in ("write", "admin"):
            return (
                f"[MITIGATED] 🚫 Access denied for agent '{agent_id}'.\n"
                f"Declared scope: '{agent_scope}'\n"
                f"Required scope: 'write' or 'admin'\n"
                f"Merge operation BLOCKED. No GitHub API call was made.\n"
                f"This is MCP02 mitigation: scope creep prevented at the server level."
            )

        # Only reaches here if agent has write/admin scope
        headers = {
            "Authorization": f"token {GITHUB_WRITE_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}/merge"
        payload = {
            "commit_title": f"[MCP02 Demo] Authorized merge by agent '{agent_id}' (scope: {agent_scope})",
            "merge_method": "merge"
        }
        response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            sha = response.json().get("sha", "N/A")
            return (
                f"[MITIGATED] PR #{pr_number} merged by authorized agent '{agent_id}' "
                f"(scope: {agent_scope}). Merge SHA: {sha}"
            )
        elif response.status_code == 405:
            return f"PR #{pr_number} is not mergeable (already merged or conflicts exist)."
        else:
            return f"GitHub API error {response.status_code}: {response.text}"
