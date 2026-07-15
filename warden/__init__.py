"""MCP Warden — zero-trust security gateway for MCP tool calls.

Warden is an MCP proxy: an MCP server to the host above it, and an MCP client
to every downstream server below it. Every tool call that crosses it is
identified, integrity-checked, policy-checked, inspected, optionally held for
human approval, and recorded in a tamper-evident audit log.
"""
