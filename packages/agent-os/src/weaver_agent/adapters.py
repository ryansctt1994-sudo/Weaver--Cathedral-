"""External adapter registry; no third-party runtime code is vendored here."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterDescriptor:
    name: str
    role: str
    integration: str
    license_boundary: str


ADAPTERS = (
    AdapterDescriptor("ruflo", "orchestration", "MCP/CLI process adapter", "MIT; external dependency"),
    AdapterDescriptor("owl", "research agents", "API/process adapter", "verify upstream license before activation"),
    AdapterDescriptor("swarms", "workflow engine", "process-isolated service", "AGPL-3.0 boundary"),
    AdapterDescriptor("tinyclaw", "messaging", "event bridge", "MIT; external dependency"),
    AdapterDescriptor("cortex", "repository memory", "local CLI adapter", "MIT; preserve James Jackson attribution"),
    AdapterDescriptor("gbrain", "knowledge graph", "local service adapter", "MIT; preserve Garry Tan attribution"),
    AdapterDescriptor("strix", "security testing", "isolated scan job", "Apache-2.0; external dependency"),
)

