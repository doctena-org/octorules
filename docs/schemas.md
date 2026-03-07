# Schema Architecture

The linter needs to know every valid Cloudflare field and function, along with
metadata that determines where and how each can be used. This page documents
how that data is sourced, merged, and consumed.

## Two data sources

### 1. wirefilter (Rust FFI)

[octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter)
provides the authoritative list of **field names**, **field types**, and
**function names** — the same data Cloudflare's own engine uses to validate
expressions.

wirefilter has no concept of billing plans, response-only fields, or per-phase
function restrictions. It validates pure expression grammar and types.

### 2. overlay.toml (Python-only metadata)

[`overlay.toml`](../src/octorules/linter/schemas/overlay.toml) adds Cloudflare
product-level properties that wirefilter doesn't track:

| Property | Meaning | Example |
|---|---|---|
| `requires_plan` | Billing plan that gates the field/function | `cf.waf.score` → `"enterprise"` |
| `is_response` | Field only available in response phases | `http.response.code` → `true` |
| `restricted_phases` | Function only allowed in specific phases | `sha256` → transform phases only |

Only entries that differ from defaults are listed. Defaults: `requires_plan = ""`,
`is_response = false`, `restricted_phases = []`.

## Data flow

```
wirefilter (Rust)             overlay.toml
  field names + types           plan, response, phase metadata
  function names
        │                              │
        └──────────┬───────────────────┘
                   ↓
            _registry.py
         merges at import time
                   ↓
    fields.py FIELDS dict    functions.py FUNCTIONS dict
                   ↓
    ast_linter.py          phase_linter.py
    (field/function         (phase restriction
     validation)             checks)
```

When wirefilter is **not** installed, `_registry.py` loads the same merged data
from `schemas.json` — a frozen snapshot:

```
schemas.json (frozen fallback)
        ↓
   _registry.py loads it
        ↓
   same FIELDS / FUNCTIONS dicts
```

## Key files

| File | Role |
|---|---|
| [`_registry.py`](../src/octorules/linter/schemas/_registry.py) | Import-time loader: wirefilter + overlay → dicts, or JSON fallback |
| [`overlay.toml`](../src/octorules/linter/schemas/overlay.toml) | Python-only metadata (plan, response, phase restrictions) |
| [`schemas.json`](../src/octorules/linter/schemas/schemas.json) | Frozen snapshot for users without wirefilter |
| [`fields.py`](../src/octorules/linter/schemas/fields.py) | `FIELDS` registry, `FieldDef` dataclass, manual entries |
| [`functions.py`](../src/octorules/linter/schemas/functions.py) | `FUNCTIONS` registry, `FunctionDef` dataclass |
| [`scripts/sync_schemas.py`](../scripts/sync_schemas.py) | Regenerates `schemas.json` from wirefilter + overlay |

## Manual entries

Some fields are registered directly in `fields.py` as Python code, outside the
loaded data. These are entries **not** returned by wirefilter's
`get_schema_info()`:

- **Deprecated `ip.geoip.*` fields** — kept so the linter emits G010 ("use
  `ip.src.*` instead") rather than F002 ("unknown field")
- **Account-level fields** (`cf.zone.name`, `cf.zone.plan`) — only valid in
  account-scoped rulesets, not in per-zone wirefilter schemas
- **`http.request.uri.path`** — wirefilter registers it as a field, but in
  transform phases Cloudflare also treats it as a callable function

## Keeping schemas.json fresh

`schemas.json` is a frozen fallback — the linter **does not use it** when
wirefilter is installed. It exists for users who `pip install octorules` without
the `[wirefilter]` extra.

> **v1.0.0 decision:** Consider dropping the fallback entirely. Without
> wirefilter, the linter already has degraded coverage (no type checking, no
> syntax validation). Dropping the fallback would also skip registry-dependent
> rules (unknown field, plan tier, phase restrictions) — but that's honest.
> This would eliminate `schemas.json`, `sync_schemas.py`, and the pre-commit
> hook.

A pre-commit hook ([`scripts/hooks/pre-commit`](../scripts/hooks/pre-commit))
auto-regenerates `schemas.json` when `overlay.toml` or `pyproject.toml` is
modified. Install it once after cloning:

```bash
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

You can also regenerate manually:

```bash
python scripts/sync_schemas.py          # regenerate
python scripts/sync_schemas.py --check  # verify without writing
```

## Editing overlay.toml

When adding or changing metadata:

1. Edit `overlay.toml` with the new entry
2. `git add` the file — the pre-commit hook will regenerate `schemas.json`
   automatically when you commit
3. If adding a field/function that wirefilter doesn't report at all, add it to
   the `[functions]` or `[fields]` section — `_registry.py` includes
   overlay-only entries automatically

Source of truth for plan requirements and phase restrictions: Cloudflare
dashboard and [API docs](https://developers.cloudflare.com/ruleset-engine/rules-language/).
