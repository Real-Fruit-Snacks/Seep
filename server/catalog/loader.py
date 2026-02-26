from __future__ import annotations

from pathlib import Path

import yaml

from .schemas import CategoryDef, ToolCatalog, ToolEntry

CATALOG_PATH = Path(__file__).parent / "tools.yaml"

REQUIRED_TOOL_FIELDS: list[str] = [
    "name",
    "display_name",
    "description",
    "project_url",
    "upstream_url",
    "upstream_version",
    "license",
    "sha256",
    "folder",
    "categories",
    "platform",
    "architecture",
    "tags",
    "finding_triggers",
    "notes",
]

VALID_PLATFORMS: set[str] = {"windows", "linux", "both"}
VALID_ARCHITECTURES: set[str] = {"x64", "x86", "any"}


class CatalogLoadError(Exception):
    pass


class CatalogLoader:
    def __init__(self, catalog_path: Path | None = None) -> None:
        self.catalog_path = catalog_path or CATALOG_PATH

    def load(self) -> ToolCatalog:
        """Load and validate the YAML catalog. Raises CatalogLoadError on any problems."""
        if not self.catalog_path.exists():
            raise CatalogLoadError(f"Catalog file not found: {self.catalog_path}")

        try:
            raw = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CatalogLoadError(f"Failed to parse YAML: {exc}") from exc

        if not isinstance(raw, dict):
            raise CatalogLoadError("Catalog root must be a YAML mapping.")

        for key in (
            "version",
            "release_base_url",
            "tools_release",
            "tools",
            "categories",
        ):
            if key not in raw:
                raise CatalogLoadError(f"Catalog is missing top-level key: '{key}'")

        raw_tools = raw["tools"]
        if not isinstance(raw_tools, list):
            raise CatalogLoadError("'tools' must be a YAML sequence.")

        all_errors: list[str] = []
        for idx, entry in enumerate(raw_tools):
            if not isinstance(entry, dict):
                all_errors.append(f"Tool[{idx}]: entry is not a mapping.")
                continue
            all_errors.extend(self.validate_entry(entry, idx))

        if all_errors:
            error_block = "\n  - ".join(all_errors)
            raise CatalogLoadError(
                f"Catalog validation failed with {len(all_errors)} error(s):\n  - {error_block}"
            )

        tools = [self._parse_tool(entry) for entry in raw_tools]
        categories = self._parse_categories(raw.get("categories") or {})

        return ToolCatalog(
            version=str(raw["version"]),
            release_base_url=str(raw["release_base_url"]),
            tools_release=str(raw["tools_release"]),
            tools=tools,
            categories=categories,
        )

    def validate_entry(self, entry: dict, index: int) -> list[str]:
        """Validate a single tool entry dict. Returns a (possibly empty) list of error messages."""
        errors: list[str] = []
        name_hint = entry.get("name", f"<index {index}>")

        for field in REQUIRED_TOOL_FIELDS:
            if field not in entry:
                errors.append(f"Tool '{name_hint}': missing required field '{field}'.")

        platform = entry.get("platform")
        if platform is not None and platform not in VALID_PLATFORMS:
            errors.append(
                f"Tool '{name_hint}': invalid platform '{platform}'. "
                f"Must be one of: {sorted(VALID_PLATFORMS)}."
            )

        architecture = entry.get("architecture")
        if architecture is not None and architecture not in VALID_ARCHITECTURES:
            errors.append(
                f"Tool '{name_hint}': invalid architecture '{architecture}'. "
                f"Must be one of: {sorted(VALID_ARCHITECTURES)}."
            )

        for list_field in ("categories", "tags", "finding_triggers"):
            val = entry.get(list_field)
            if val is not None and not isinstance(val, list):
                errors.append(
                    f"Tool '{name_hint}': field '{list_field}' must be a list, got {type(val).__name__}."
                )

        return errors

    def _parse_tool(self, entry: dict) -> ToolEntry:
        """Convert a validated raw dict to a ToolEntry."""
        return ToolEntry(
            name=str(entry["name"]),
            display_name=str(entry["display_name"]),
            description=str(entry["description"]),
            project_url=str(entry["project_url"]),
            upstream_url=str(entry["upstream_url"]),
            upstream_version=str(entry["upstream_version"]),
            license=str(entry["license"]),
            sha256=str(entry.get("sha256") or ""),
            folder=str(entry["folder"]),
            categories=list(entry["categories"]),
            platform=str(entry["platform"]),
            architecture=str(entry["architecture"]),
            tags=list(entry["tags"]),
            finding_triggers=list(entry["finding_triggers"]),
            notes=str(entry.get("notes") or ""),
        )

    def _parse_categories(self, raw: dict) -> dict[str, CategoryDef]:
        """Convert raw category mapping to CategoryDef objects."""
        result: dict[str, CategoryDef] = {}
        for cat_name, cat_data in raw.items():
            if not isinstance(cat_data, dict):
                raise CatalogLoadError(
                    f"Category '{cat_name}': definition must be a mapping, got {type(cat_data).__name__}."
                )
            result[cat_name] = CategoryDef(
                name=str(cat_data.get("name", cat_name)),
                description=str(cat_data.get("description", "")),
                folders=list(cat_data.get("folders", [])),
            )
        return result
