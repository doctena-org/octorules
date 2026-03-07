# Stage 2d: List Validation

Validates the `lists` section for structural correctness and item validity. Checks list metadata (name, kind) and validates individual items based on the list kind (IP, ASN, hostname, redirect).

## Category Q — List Validation (6 rules)

### Q001 — Missing or duplicate list name

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when:
- A list entry is missing the `name` field.
- Two lists share the same `name`.

```yaml
lists:
  - kind: ip
    items: []
    # missing name
```

Fix: Give each list a unique, non-empty `name`.

### Q002 — Missing or invalid list kind

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when a list entry is missing the `kind` field or has an unrecognized kind value. Valid kinds: `ip`, `asn`, `hostname`, `redirect`.

```yaml
lists:
  - name: my_list
    kind: bogus     # not a valid kind
    items: []
```

Fix: Use a valid kind value.

### Q003 — List item missing required field

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when a list item is missing the required field for its kind:
- **IP lists**: each item must have an `ip` field.
- **ASN lists**: each item must have an `asn` field.
- **Hostname lists**: each item must have a `hostname` field.
- **Redirect lists**: each item must have a `redirect` field.

```yaml
lists:
  - name: my_ips
    kind: ip
    items:
      - comment: "oops"    # missing ip field
```

Fix: Add the required field for the list kind.

### Q004 — Invalid IP address in IP list

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when an `ip` field value is not a valid IPv4/IPv6 address or CIDR range.

```yaml
lists:
  - name: my_ips
    kind: ip
    items:
      - ip: "not-an-ip"
```

Fix: Use a valid IP address (e.g., `1.2.3.4`) or CIDR range (e.g., `10.0.0.0/8`, `2001:db8::/32`).

### Q005 — Invalid ASN value in ASN list

| Severity | Category |
|----------|----------|
| ERROR | list |

Triggers when an `asn` field value is not an integer, or is outside the valid range (0–4294967295).

```yaml
lists:
  - name: my_asns
    kind: asn
    items:
      - asn: "not-int"    # must be integer
      - asn: -1            # out of range
```

Fix: Use a valid ASN integer between 0 and 4294967295.

### Q006 — Duplicate items within list

| Severity | Category |
|----------|----------|
| WARNING | list |

Triggers when a list contains duplicate items. Checks the identifying value for each kind:
- **IP lists**: duplicate `ip` values.
- **ASN lists**: duplicate `asn` values.
- **Hostname lists**: duplicate `url_hostname` values within `hostname` objects.
- **Redirect lists**: duplicate `source_url` values within `redirect` objects.

```yaml
lists:
  - name: my_ips
    kind: ip
    items:
      - ip: "1.2.3.4"
      - ip: "1.2.3.4"     # duplicate
```

Fix: Remove the duplicate entry.
