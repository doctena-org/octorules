# Stage 4: Cross-Rule Analysis

Analyzes relationships between rules within each phase.

## Category P — Cross-Rule / Ruleset-Level (4 rules)

### P001 — Duplicate expression across rules

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when two rules in the same phase have identical expressions (after whitespace normalization).

Fix: Remove the duplicate rule, or differentiate the expressions if the rules serve different purposes.

### P002 — Unreachable rule after terminating action

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when a rule follows an always-true rule (`expression: "true"`) with a terminating action (`block`, `challenge`, `js_challenge`, `managed_challenge`, `redirect`, `rewrite`). The subsequent rule will never execute.

```yaml
waf_custom_rules:
  - ref: block-all
    expression: "true"
    action: block
  - ref: log-bots             # unreachable
    expression: 'cf.bot_management.score lt 30'
    action: log
```

Fix: Reorder rules so the catch-all comes last, or remove the unreachable rule.

### P003 — Unresolved list reference

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when an expression references a list via `$list_name` syntax but the list is not defined in the `lists` section of the rules file. Does not flag managed list references (`$cf.*`) — those are checked by P004.

```yaml
lists:
  - name: known_ips
    kind: ip
    items: [...]

waf_custom_rules:
  - ref: block-unknown
    expression: 'ip.src in $unknown_list'    # $unknown_list not in lists section
```

Fix: Add the referenced list to the `lists` section, or fix the list name.

```yaml
lists:
  - name: unknown_list
    kind: ip
    items: [...]
```

### P004 — Invalid managed list name

| Severity | Category |
|----------|----------|
| WARNING | cross_rule |

Triggers when an expression references a managed list via `$cf.*` syntax that is not a valid Cloudflare managed list.

```yaml
waf_custom_rules:
  - ref: block-anon
    expression: 'ip.src in $cf.invalid_list'
```

Fix: Use a valid managed list name. Valid managed lists: `$cf.anonymizer`, `$cf.botnetcc`, `$cf.malware`, `$cf.open_proxies`, `$cf.vpn`.
