"""
OWASP MCP Top 10 - Main MCP Server
====================================
Modular FastMCP server. Each MCP scenario is a separate module in /scenarios.
To add a new scenario: create scenarios/mcpXX_name.py and add one import + register() call below.

Transport: SSE (Server-Sent Events) over HTTP
Railway URL: https://<your-app>.railway.app/sse
"""

import os
from fastmcp import FastMCP

# ── Import scenario modules ───────────────────────────────────────────────────
from scenarios import mcp01_token
# from scenarios import mcp02_privilege   # Uncomment when MCP02 is ready
# from scenarios import mcp04_supply      # Uncomment when MCP04 is ready
# from scenarios import mcp06_intent      # Uncomment when MCP06 is ready
# from scenarios import mcp07_auth        # Uncomment when MCP07 is ready
# from scenarios import mcp08_audit       # Uncomment when MCP08 is ready
# from scenarios import mcp10_context     # Uncomment when MCP10 is ready

# ── Server setup ──────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="OWASP MCP Top 10 - Demo Server",
    instructions=(
        "This MCP server demonstrates OWASP MCP Top 10 vulnerabilities for educational purposes. "
        "Each tool is prefixed with its scenario ID (e.g., mcp01_) and labeled [VULNERABLE] or [MITIGATED]. "
        "Use vulnerable tools to simulate attacks and mitigated tools to observe defenses."
    )
)

# ── Register scenario tools ───────────────────────────────────────────────────
mcp01_token.register(mcp)
# mcp02_privilege.register(mcp)   # Uncomment when ready
# mcp04_supply.register(mcp)
# mcp06_intent.register(mcp)
# mcp07_auth.register(mcp)
# mcp08_audit.register(mcp)
# mcp10_context.register(mcp)

# ── Run server ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting OWASP MCP Top 10 server on port {port} (SSE transport)")
    print(f"SSE endpoint: http://0.0.0.0:{port}/sse")
    mcp.run(transport="sse", host="0.0.0.0", port=port)
