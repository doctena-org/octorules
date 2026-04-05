---
name: No --dry-run on sync
description: octorules deliberately uses separate plan/sync commands; do not add --dry-run to sync
type: feedback
---

Do not add a `--dry-run` flag to `octorules sync`. Use `octorules plan` instead.

**Why:** octorules deliberately splits planning and applying into separate subcommands (`plan` vs `sync --doit`), diverging from octodns's single `octodns-sync [--doit]` pattern. The split exists because octorules targets WAF rules (higher blast radius than DNS) and benefits from the GitHub Action's two-step workflow: `mode: plan` in one step, `mode: sync` in a later step with checksum verification. A `sync --dry-run` is redundant with `plan` and muddies the CLI contract (e.g., `sync --doit --dry-run` is nonsensical). This was implemented and then reverted during the 2026-03-30 audit after realizing it contradicted the design.

**How to apply:** If someone requests `--dry-run` for sync, point them to `octorules plan` instead. The existing `plan` command already supports all the same flags (`--zone`, `--phase`, `--checksum`, `--scope`).
