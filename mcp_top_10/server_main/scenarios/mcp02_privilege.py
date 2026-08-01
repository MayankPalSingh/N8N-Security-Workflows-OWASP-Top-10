"""
MCP02:2025 - Privilege Escalation via Scope Creep
==================================================
Demonstrates Scenario A: Accidental Escalation (Read-Only → Write)

The user declares their scope dynamically in the chat message:
  Scope:Read  — should only be allowed to read
  Scope:Write — allowed to read and write

Vulnerable: Server ignores the declared scope entirely — merges regardless.
Mitigated:  Server enforces the declared scope — blocks merge if Scope:Read.

Real GitHub API calls using tokens stored as Railway environment variables:
  GITHUB_READ_TOKEN   — PAT with public_repo (read) scope
  GITHUB_WRITE_TOKEN  — PAT with full repo (write) scope
  GITHUB_REPO_OWNER   — GitHub username / org
  GITHUB_REPO_NAME    — Repository name
"""

import os
import requests

GITHUB_READ_TOKEN  = os.environ.get("GITHUB_READ_TOKEN", "")
GITHUB_WRITE_TOKEN = os.environ.get("GITHUB_WRITE_TOKEN", "")
GITHUB_REPO_OWNER  = os.environ.get("GITHUB_REPO_OWNER", "")
GITHUB_REPO_NAME   = os.environ.get("GITHUB_REPO_NAME", "")
GITHUB_API_BASE    = "https://api.github.com"


def register(mcp):

    # =========================================================================
    # SCENARIO A — Accidental Escalation (Read-Only → Write)
    # =========================================================================

    @mcp.tool(name="mcp02_read_repo_vulnerable")
    def read_repo_vulnerable() -> str:
        """
        [VULNERABLE] List repository root contents via GitHub API.
        Uses read-only token. No scope check performed.
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

        return (
            f"[VULNERABLE] Repository: {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}\n"
            f"Directories: {dirs}\n"
            f"Files: {files}"
        )

    @mcp.tool(name="mcp02_read_repo_mitigated")
    def read_repo_mitigated() -> str:
        """
        [MITIGATED] List repository root contents via GitHub API.
        Uses read-only token. Read access permitted for all scopes.
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

        return (
            f"[MITIGATED] Repository: {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}\n"
            f"Directories: {dirs}\n"
            f"Files: {files}\n"
            f"Read access: PERMITTED for all scopes"
        )

    @mcp.tool(name="mcp02_merge_pr_vulnerable")
    def merge_pr_vulnerable(pr_number: int) -> str:
        """
        [VULNERABLE] Merge a GitHub pull request using the write token.
        Scope is completely ignored — merges regardless of what the user declared.
        Attack: a Scope:Read agent can silently merge PRs.
        """
        headers = {
            "Authorization": f"token {GITHUB_WRITE_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}/merge"
        payload = {
            "commit_title": f"[MCP02 VULNERABLE] Merged PR #{pr_number} — scope was never checked",
            "merge_method": "merge"
        }
        response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            sha = response.json().get("sha", "N/A")
            return (
                f"[VULNERABLE] ⚠️  PR #{pr_number} MERGED SUCCESSFULLY.\n"
                f"Declared scope: IGNORED — server never checked it.\n"
                f"A Scope:Read agent just performed a write action on GitHub.\n"
                f"Merge SHA: {sha}\n"
                f"Risk: Unreviewed code is now in main. CI/CD may auto-deploy it."
            )
        elif response.status_code == 405:
            return f"PR #{pr_number} is not mergeable (already merged or has conflicts). Reopen it on GitHub to rerun the demo."
        else:
            return f"GitHub API error {response.status_code}: {response.text}"

    @mcp.tool(name="mcp02_merge_pr_mitigated")
    def merge_pr_mitigated(pr_number: int, scope: str) -> str:
        """
        [MITIGATED] Merge a GitHub pull request — scope enforced before any API call.
        Scope:Read is blocked at the MCP server level. No GitHub call is made.
        Only Scope:Write or Scope:Admin are permitted to merge.
        """
        # Normalize scope input — handle "Scope:Read", "read", "READ" etc.
        scope_normalized = scope.strip().lower().replace("scope:", "").replace(" ", "")

        if scope_normalized not in ("write", "admin"):
            return (
                f"[MITIGATED] 🚫 Merge BLOCKED for PR #{pr_number}.\n"
                f"Declared scope: '{scope}'\n"
                f"Required: Scope:Write or Scope:Admin\n"
                f"No GitHub API call was made — scope enforced at the MCP server level.\n"
                f"MCP02 mitigation: privilege escalation via scope creep prevented."
            )

        # Scope is write or admin — authorized, proceed
        headers = {
            "Authorization": f"token {GITHUB_WRITE_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}/merge"
        payload = {
            "commit_title": f"[MCP02 MITIGATED] Authorized merge — scope '{scope}' verified",
            "merge_method": "merge"
        }
        response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            sha = response.json().get("sha", "N/A")
            return (
                f"[MITIGATED] ✅ PR #{pr_number} merged by authorized agent.\n"
                f"Declared scope: '{scope}' — verified and permitted.\n"
                f"Merge SHA: {sha}"
            )
        elif response.status_code == 405:
            return f"PR #{pr_number} is not mergeable (already merged or has conflicts). Reopen it on GitHub to rerun the demo."
        else:
            return f"GitHub API error {response.status_code}: {response.text}"
