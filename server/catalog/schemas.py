from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ToolEntry:
    name: str
    display_name: str
    description: str
    project_url: str
    upstream_url: str
    upstream_version: str
    license: str
    sha256: str
    folder: str
    categories: list[str]
    platform: str  # "windows" | "linux" | "both"
    architecture: str  # "x64" | "x86" | "any"
    tags: list[str]
    finding_triggers: list[str]
    notes: str


@dataclass
class CategoryDef:
    name: str
    description: str
    folders: list[str]


@dataclass
class ToolCatalog:
    version: str
    release_base_url: str
    tools_release: str
    tools: list[ToolEntry]
    categories: dict[str, CategoryDef]

    def search(self, query: str) -> list[ToolEntry]:
        """Search tools by name, display_name, description, tags, or category. Case-insensitive."""
        q = query.lower()
        results = []
        for tool in self.tools:
            if (
                q in tool.name.lower()
                or q in tool.display_name.lower()
                or q in tool.description.lower()
                or any(q in t.lower() for t in tool.tags)
                or any(q in c.lower() for c in tool.categories)
            ):
                results.append(tool)
        return results

    def get_by_category(self, category: str) -> list[ToolEntry]:
        """Get all tools whose folder is listed in the given category."""
        cat_def = self.categories.get(category)
        if not cat_def:
            return []
        return [t for t in self.tools if t.folder in cat_def.folders]

    def get_by_platform(self, platform: str) -> list[ToolEntry]:
        """Get tools matching the given platform or 'both'."""
        return [t for t in self.tools if t.platform in (platform, "both")]

    def get_by_finding(self, finding_id: str) -> list[ToolEntry]:
        """Get tools triggered by a specific finding ID, or by wildcard '*'."""
        return [
            t
            for t in self.tools
            if finding_id in t.finding_triggers or "*" in t.finding_triggers
        ]

    def get_tool_url(self, tool: ToolEntry) -> str:
        """Construct the full download URL for a tool."""
        base = self.release_base_url.rstrip("/")
        return f"{base}/{self.tools_release}/{tool.name}"
