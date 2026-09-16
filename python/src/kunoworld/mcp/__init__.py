"""KunoWorld's local MCP server for AI agents: `kunoworld-mcp`, installed with the `mcp` extra.

    pip install 'kunoworld[mcp]'
    KUNOWORLD_API_KEY=kw_live_... kunoworld-mcp

It runs on the user's computer and speaks MCP over stdio, so a Private job's prompt and video are encrypted and decrypted
here, never by a server in between. `tools.py` holds what the tools do and needs no MCP package; `server.py` serves them.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> None:
    try:
        from .server import main as serve
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.split(".")[0] == "mcp":
            print("kunoworld-mcp needs the MCP SDK: install kunoworld with its mcp extra, 'kunoworld[mcp]'.", file=sys.stderr)
            raise SystemExit(1) from None
        raise
    serve(argv)
