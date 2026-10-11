#!/usr/bin/env python3
"""
Validate all plugin input/output schemas are valid JSON Schema.

Usage:
    python scripts/validate_schemas.py

Exit codes:
    0 - All schemas valid
    1 - One or more schemas invalid
"""

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema package required. Install with: pip install jsonschema")
    sys.exit(1)


def validate_schema(schema_path: Path) -> list[str]:
    """Validate a JSON Schema file. Returns list of errors."""
    errors = []

    try:
        with open(schema_path) as f:
            schema = json.load(f)

        # Check $schema is present
        if "$schema" not in schema:
            errors.append(f"{schema_path}: Missing $schema declaration")

        # Try to compile the schema
        jsonschema.Draft202012Validator.check_schema(schema)

    except json.JSONDecodeError as e:
        errors.append(f"{schema_path}: Invalid JSON - {e}")
    except jsonschema.SchemaError as e:
        errors.append(f"{schema_path}: Invalid schema - {e.message}")

    return errors


def main():
    root = Path(__file__).parent.parent
    plugins_dir = root / "plugins"

    all_errors = []
    validated = 0

    for pillar_dir in plugins_dir.iterdir():
        if not pillar_dir.is_dir() or pillar_dir.name.startswith("_"):
            continue

        for plugin_dir in pillar_dir.iterdir():
            if not plugin_dir.is_dir() or plugin_dir.name.startswith("_"):
                continue
            if not (plugin_dir / "manifest.json").exists() and not (
                plugin_dir / "tool.py"
            ).exists():
                continue

            schemas_dir = plugin_dir / "schemas"
            if not schemas_dir.exists():
                all_errors.append(f"{plugin_dir.name}: schemas/ directory not found")
                continue

            for schema_name in ["input.schema.json", "output.schema.json"]:
                schema_path = schemas_dir / schema_name
                if not schema_path.exists():
                    all_errors.append(f"{plugin_dir.name}: {schema_name} not found")
                    continue

                errors = validate_schema(schema_path)
                if errors:
                    all_errors.extend(errors)
                else:
                    validated += 1
                    print(f"✓ {pillar_dir.name}/{plugin_dir.name}/{schema_name}")

    print()
    print(f"Validated: {validated} schemas")

    if all_errors:
        print(f"Errors: {len(all_errors)}")
        for error in all_errors:
            print(f"  ✗ {error}")
        sys.exit(1)

    print("All schemas valid.")
    sys.exit(0)


if __name__ == "__main__":
    main()
