# Hermes tool-result-compactor

`tool-result-compactor` is an experimental Hermes Agent plugin that reduces context pressure from oversized successful tool results. It stores the original result in a bounded profile-local SQLite store, places a compact preview plus `<<hermes_compact:...>>` marker in the conversation, and exposes `context_compactor_retrieve` so omitted content can be searched later.

## Safety posture

This plugin is intentionally query-first and conservative:

- failed tool calls are left verbatim;
- outputs above `max_store_chars` are not stored;
- credential-shaped JSON keys and values are skipped rather than persisted;
- empty retrievals return metadata and guidance, not broad content;
- broad full retrieval is disabled by default;
- if enabled, full retrieval still requires `confirm_broad_retrieval: true` and a short `broad_reason`;
- stored records are bounded by TTL and `max_records`;
- the store directory and SQLite file are tightened on POSIX systems;
- plugin connections enable SQLite `secure_delete` and avoid WAL mode.

The store is still plaintext SQLite. Do not treat it as a vault for secrets or regulated data.

## Install

Install through the normal Hermes plugin flow from a repository or local path containing this directory:

```bash
hermes plugins install <path-or-git-url> --enable
```

Then enable the `context_compactor` toolset in the target profile. Start with a non-default profile until your own multi-turn recovery tests pass.

## Configuration

See `config.example.yaml` for a safe default profile block.

Important defaults:

```yaml
context_compactor:
  enabled: true
  min_chars: 8000
  preview_chars: 1600
  retrieve_max_chars: 40000
  ttl_seconds: 604800
  allow_unbounded_retention: false
  secure_delete: true
  private_store: true
  allow_full_retrieval: false
  max_records: 200
  max_store_chars: 2000000
```

## Retrieval pattern

Prefer targeted search:

```json
{"hash": "<marker-hash>", "query": "specific terms from the omitted output"}
```

Metadata-only retrieval:

```json
{"hash": "<marker-hash>", "mode": "metadata"}
```

Full retrieval is intentionally gated and should be a last resort:

```json
{
  "hash": "<marker-hash>",
  "mode": "full",
  "confirm_broad_retrieval": true,
  "broad_reason": "targeted search did not recover the required context"
}
```

## Development checks

```bash
python -m py_compile __init__.py tests/test_tool_result_compactor.py
python -m pytest tests -q
```

## License

MIT. See `LICENSE`.
