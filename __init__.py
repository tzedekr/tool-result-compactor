"""Hermes tool-result compactor plugin.

Compacts oversized successful tool results into a bounded profile-local SQLite
store and exposes a retrieval/search tool for omitted content.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

PLUGIN_NAME = "tool-result-compactor"
TOOL_NAME = "context_compactor_retrieve"
MARKER_PREFIX = "<<hermes_compact:"
DEFAULT_MIN_CHARS = 8_000
DEFAULT_PREVIEW_CHARS = 1_600
DEFAULT_RETRIEVE_MAX_CHARS = 40_000
DEFAULT_QUERY_MAX_LINES = 80
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_MAX_STORE_CHARS = 2_000_000
DEFAULT_MAX_RECORDS = 200
DEFAULT_ALLOW_UNBOUNDED_RETENTION = False
DEFAULT_ALLOW_FULL_RETRIEVAL = False
DEFAULT_PRIVATE_STORE = True
DEFAULT_SECURE_DELETE = True

_CONFIG_CACHE: dict[str, Any] | None = None

# Key-name scanner: deliberately avoids generic "token" substrings in phrases
# such as "token budget" while still catching credential-shaped JSON keys.
_SECRET_KEY_NORMALIZED = {
    "apikey",
    "xapikey",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "authtoken",
    "authorization",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "credential",
    "credentials",
    "privatekey",
    "accesskeyid",
    "awsaccesskeyid",
}
_SECRET_KEY_CONTAINS = (
    "apikey",
    "authorization",
    "clientsecret",
    "privatekey",
    "accesskeyid",
)
_BENIGN_KEY_NORMALIZED = {
    "tokens",
    "tokencount",
    "tokencounts",
    "maxtokens",
    "maxoutputtokens",
    "prompttokens",
    "completiontokens",
    "totaltokens",
    "tokenbudget",
    "tokenusage",
}
_SECRET_VALUE_RE = re.compile(
    r"(?ix)"
    r"(\bBearer\s+[A-Za-z0-9._~+/=-]{8,})"
    r"|(sk-[A-Za-z0-9._-]{6,})"
    r"|(gh[pousr]_[A-Za-z0-9_]{12,})"
    r"|(xox[abprs]-[A-Za-z0-9-]{10,})"
    r"|(AKIA[0-9A-Z.]{8,})"
    r"|(-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----)"
    r"|((api[_-]?key|access[_-]?key|secret|password|token)\s*[:=]\s*[^\s'\"{}]{6,})"
)


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()


def _db_path() -> Path:
    path = _hermes_home() / "cache" / "tool-result-compactor" / "store.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _ensure_private_store_permissions(path)
    return path


def _ensure_private_store_permissions(path: Path) -> None:
    if not _bool_config("private_store", DEFAULT_PRIVATE_STORE):
        return
    for target, mode in ((path.parent, 0o700), (path, 0o600)):
        try:
            if target.exists():
                target.chmod(mode)
        except OSError:
            # Permission tightening is best-effort so the plugin does not break
            # read-only or unusual profile filesystems. Tests cover normal POSIX.
            pass


def _load_plugin_config() -> dict[str, Any]:
    """Return the `context_compactor:` config block from HERMES_HOME/config.yaml.

    The plugin is profile-scoped: a temporary or non-default HERMES_HOME can
    enable and tune it without touching the default profile. Environment
    variables remain as fallback for ad-hoc smoke tests, but config wins.
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    cfg_path = _hermes_home() / "config.yaml"
    block: dict[str, Any] = {}
    if cfg_path.exists():
        try:
            import yaml  # type: ignore

            raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            candidate = raw.get("context_compactor")
            if isinstance(candidate, dict):
                block = candidate
        except Exception:
            block = {}
    _CONFIG_CACHE = block
    return block


def _bool_config(name: str, default: bool) -> bool:
    raw = _load_plugin_config().get(name, default)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() not in {"0", "false", "no", "off", "disabled"}
    return bool(raw)


def _int_config(
    name: str,
    default: int,
    *,
    env: str | None = None,
    minimum: int | None = None,
) -> int:
    cfg = _load_plugin_config()
    raw = cfg.get(name)
    if raw is None and env:
        raw = os.environ.get(env)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _min_chars() -> int:
    return _int_config(
        "min_chars",
        DEFAULT_MIN_CHARS,
        env="HERMES_TOOL_COMPACTOR_MIN_CHARS",
        minimum=1,
    )


def _preview_chars() -> int:
    return _int_config(
        "preview_chars",
        DEFAULT_PREVIEW_CHARS,
        env="HERMES_TOOL_COMPACTOR_PREVIEW_CHARS",
        minimum=1,
    )


def _retrieve_max_chars() -> int:
    return _int_config(
        "retrieve_max_chars",
        DEFAULT_RETRIEVE_MAX_CHARS,
        env="HERMES_TOOL_COMPACTOR_RETRIEVE_MAX_CHARS",
        minimum=1,
    )


def _query_max_lines() -> int:
    return _int_config(
        "query_max_lines",
        DEFAULT_QUERY_MAX_LINES,
        env="HERMES_TOOL_COMPACTOR_QUERY_MAX_LINES",
        minimum=1,
    )


def _configured_ttl_seconds() -> int:
    # <=0 requests no expiry, but the plugin only honors that when
    # allow_unbounded_retention is explicitly true. Plaintext SQLite should be
    # bounded by default.
    return _int_config(
        "ttl_seconds",
        DEFAULT_TTL_SECONDS,
        env="HERMES_TOOL_COMPACTOR_TTL_SECONDS",
    )


def _allow_unbounded_retention() -> bool:
    return _bool_config("allow_unbounded_retention", DEFAULT_ALLOW_UNBOUNDED_RETENTION)


def _ttl_seconds() -> int:
    configured = _configured_ttl_seconds()
    if configured <= 0 and not _allow_unbounded_retention():
        return DEFAULT_TTL_SECONDS
    return configured


def _retention_policy(created_at: float | None = None) -> dict[str, Any]:
    created = time.time() if created_at is None else created_at
    configured = _configured_ttl_seconds()
    effective = _ttl_seconds()
    expires_at = None if effective <= 0 else created + effective
    return {
        "configured_ttl_seconds": configured,
        "effective_ttl_seconds": effective,
        "allow_unbounded_retention": _allow_unbounded_retention(),
        "unbounded_retention": effective <= 0,
        "expires_at": expires_at,
    }


def _max_store_chars() -> int:
    return _int_config(
        "max_store_chars",
        DEFAULT_MAX_STORE_CHARS,
        env="HERMES_TOOL_COMPACTOR_MAX_STORE_CHARS",
        minimum=1,
    )


def _max_records() -> int:
    return _int_config(
        "max_records",
        DEFAULT_MAX_RECORDS,
        env="HERMES_TOOL_COMPACTOR_MAX_RECORDS",
        minimum=1,
    )


def _secure_delete_enabled() -> bool:
    return _bool_config("secure_delete", DEFAULT_SECURE_DELETE)


def _allow_full_retrieval() -> bool:
    return _bool_config("allow_full_retrieval", DEFAULT_ALLOW_FULL_RETRIEVAL)


def _delete_orphan_retrieval_events(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM retrieval_events
        WHERE hash NOT IN (SELECT hash FROM compacted_tool_results)
        """
    )


def _purge_expired(conn: sqlite3.Connection) -> None:
    ttl = _ttl_seconds()
    if ttl <= 0:
        return
    now = time.time()
    cutoff = now - ttl
    conn.execute(
        """
        DELETE FROM compacted_tool_results
        WHERE (expires_at IS NOT NULL AND expires_at < ?)
           OR (expires_at IS NULL AND created_at < ?)
        """,
        (now, cutoff),
    )
    conn.execute("DELETE FROM retrieval_events WHERE created_at < ?", (cutoff,))
    _delete_orphan_retrieval_events(conn)


def _enforce_max_records(conn: sqlite3.Connection) -> None:
    max_records = _max_records()
    stale_hashes = [
        row[0]
        for row in conn.execute(
            """
            SELECT hash FROM compacted_tool_results
            ORDER BY created_at DESC, hash DESC
            LIMIT -1 OFFSET ?
            """,
            (max_records,),
        ).fetchall()
    ]
    if not stale_hashes:
        return
    conn.executemany(
        "DELETE FROM compacted_tool_results WHERE hash = ?",
        [(hash_key,) for hash_key in stale_hashes],
    )
    _delete_orphan_retrieval_events(conn)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    conn = sqlite3.connect(path)
    if _secure_delete_enabled():
        conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS compacted_tool_results (
            hash TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            expires_at REAL,
            session_id TEXT,
            tool_call_id TEXT,
            tool_name TEXT NOT NULL,
            status TEXT,
            original_chars INTEGER NOT NULL,
            preview TEXT NOT NULL,
            original TEXT NOT NULL
        )
        """
    )
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(compacted_tool_results)").fetchall()
    }
    if "expires_at" not in columns:
        conn.execute("ALTER TABLE compacted_tool_results ADD COLUMN expires_at REAL")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_compacted_created_at "
        "ON compacted_tool_results(created_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_compacted_expires_at "
        "ON compacted_tool_results(expires_at)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS retrieval_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            hash TEXT NOT NULL,
            query TEXT,
            mode TEXT,
            content_returned INTEGER NOT NULL DEFAULT 0,
            success INTEGER NOT NULL
        )
        """
    )
    event_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(retrieval_events)").fetchall()
    }
    if "mode" not in event_columns:
        conn.execute("ALTER TABLE retrieval_events ADD COLUMN mode TEXT")
    if "content_returned" not in event_columns:
        conn.execute(
            "ALTER TABLE retrieval_events ADD COLUMN content_returned INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_retrieval_events_hash "
        "ON retrieval_events(hash)"
    )
    _purge_expired(conn)
    _enforce_max_records(conn)
    _ensure_private_store_permissions(path)
    return conn


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _is_secret_key(key: Any) -> bool:
    normalized = _normalized_key(key)
    if normalized in _BENIGN_KEY_NORMALIZED:
        return False
    if normalized in _SECRET_KEY_NORMALIZED:
        return True
    return any(part in normalized for part in _SECRET_KEY_CONTAINS)


def _secret_value_like(value: str) -> bool:
    return bool(_SECRET_VALUE_RE.search(value))


def _json_contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if _is_secret_key(key):
                return True
            if _json_contains_secret(child):
                return True
        return False
    if isinstance(value, list):
        return any(_json_contains_secret(child) for child in value)
    if isinstance(value, str):
        return _secret_value_like(value)
    return False


def _looks_secret_bearing(text: str) -> bool:
    # Parse JSON-shaped tool results so normal words like "token budget" do not
    # suppress compaction while credential keys/values still fail closed.
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    if parsed is not None:
        return _json_contains_secret(parsed)
    return _secret_value_like(text)


def _hash_result(tool_name: str, result: str) -> str:
    h = hashlib.sha256()
    h.update(tool_name.encode("utf-8", "ignore"))
    h.update(b"\0")
    h.update(result.encode("utf-8", "ignore"))
    return h.hexdigest()[:16]


def _store_result(
    *,
    hash_key: str,
    tool_name: str,
    result: str,
    preview: str,
    status: str,
    session_id: str,
    tool_call_id: str,
    created_at: float,
    expires_at: float | None,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO compacted_tool_results
            (hash, created_at, expires_at, session_id, tool_call_id, tool_name,
             status, original_chars, preview, original)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hash_key,
                created_at,
                expires_at,
                session_id,
                tool_call_id,
                tool_name,
                status,
                len(result),
                preview,
                result,
            ),
        )
        _enforce_max_records(conn)


def _load_result(hash_key: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT hash, created_at, expires_at, session_id, tool_call_id,
                   tool_name, status, original_chars, preview, original
            FROM compacted_tool_results
            WHERE hash = ?
            """,
            (hash_key,),
        ).fetchone()
    if row is None:
        return None
    keys = (
        "hash",
        "created_at",
        "expires_at",
        "session_id",
        "tool_call_id",
        "tool_name",
        "status",
        "original_chars",
        "preview",
        "original",
    )
    return dict(zip(keys, row))


def _record_retrieval(
    hash_key: str,
    query: str,
    success: bool,
    *,
    mode: str = "",
    content_returned: bool = False,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO retrieval_events
            (created_at, hash, query, mode, content_returned, success)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                hash_key,
                query,
                mode,
                1 if content_returned else 0,
                1 if success else 0,
            ),
        )


def _query_lines(text: str, query: str, max_lines: int) -> list[dict[str, Any]]:
    needles = [part.casefold() for part in query.split() if part.strip()]
    if not needles:
        return []
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        folded = line.casefold()
        positions = [folded.find(n) for n in needles]
        if all(pos >= 0 for pos in positions):
            first = min(positions)
            start = max(0, first - 500)
            end = min(len(line), first + 1_500)
            snippet = line[start:end]
            hits.append(
                {
                    "line": idx,
                    "text": snippet,
                    "char_start": start,
                    "line_truncated": start > 0 or end < len(line),
                }
            )
            if len(hits) >= max_lines:
                break
    return hits


def _transform_tool_result(**kwargs: Any) -> str | None:
    if not _bool_config("enabled", True):
        return None

    result = kwargs.get("result")
    if not isinstance(result, str):
        return None
    if len(result) < _min_chars():
        return None
    if len(result) > _max_store_chars():
        return None

    status = str(kwargs.get("status") or "")
    # Preserve failures verbatim. Error payloads often contain the one clue the
    # model needs, and compacting them would be a subtle debugging tax.
    if status and status.lower() not in {"success", "ok", "completed"}:
        return None

    tool_name = str(kwargs.get("tool_name") or "unknown_tool")
    if tool_name == TOOL_NAME:
        return None
    if _looks_secret_bearing(result):
        return None

    hash_key = _hash_result(tool_name, result)
    preview = result[:_preview_chars()]
    created_at = time.time()
    retention = _retention_policy(created_at)
    _store_result(
        hash_key=hash_key,
        tool_name=tool_name,
        result=result,
        preview=preview,
        status=status,
        session_id=str(kwargs.get("session_id") or ""),
        tool_call_id=str(kwargs.get("tool_call_id") or ""),
        created_at=created_at,
        expires_at=retention["expires_at"],
    )

    marker = f"{MARKER_PREFIX}{hash_key}>>"
    compacted = {
        "compacted_by": PLUGIN_NAME,
        "hash": hash_key,
        "marker": marker,
        "tool_name": tool_name,
        "original_chars": len(result),
        "preview_chars": len(preview),
        "preview": preview,
        "retention": retention,
        "store_security": {
            "plaintext_sqlite": True,
            "private_store": _bool_config("private_store", DEFAULT_PRIVATE_STORE),
            "secure_delete": _secure_delete_enabled(),
            "max_records": _max_records(),
            "max_store_chars": _max_store_chars(),
            "allow_full_retrieval": _allow_full_retrieval(),
        },
        "retrieval": {
            "tool": TOOL_NAME,
            "hash": hash_key,
            "recommended_first_call": {
                "hash": hash_key,
                "query": "<specific terms>",
            },
            "fallback_full_mode": "Use mode='full' only after targeted search is insufficient.",
        },
        "retrieve_instruction": (
            f"If the omitted tool output is needed, call {TOOL_NAME} with hash={hash_key} "
            "and a specific query first. empty query returns metadata/guidance only; "
            "use mode='full' with confirm_broad_retrieval=true and broad_reason only when search is insufficient and broad content is truly needed."
        ),
    }
    return json.dumps(compacted, ensure_ascii=False)


def _suggested_next_calls(hash_key: str) -> dict[str, dict[str, Any]]:
    return {"search": {"hash": hash_key, "query": "<specific terms>"}}


def _bool_param(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _retrieve_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    hash_key = str(params.get("hash") or "").strip().lower()
    query = str(params.get("query") or "").strip()
    mode_raw = str(params.get("mode") or "").strip().lower()
    confirm_broad = _bool_param(params.get("confirm_broad_retrieval"))
    broad_reason = str(params.get("broad_reason") or "").strip()
    max_chars_raw = params.get("max_chars", _retrieve_max_chars())
    try:
        max_chars = max(1, int(max_chars_raw))
    except (TypeError, ValueError):
        max_chars = _retrieve_max_chars()

    if not hash_key:
        return json.dumps({"success": False, "error": "hash is required"})
    record = _load_result(hash_key)
    if record is None:
        _record_retrieval(hash_key, query, False, mode=mode_raw)
        return json.dumps({"success": False, "error": "hash not found", "hash": hash_key})

    original = str(record.pop("original"))
    if query:
        mode = "search"
    elif mode_raw == "full" and _allow_full_retrieval() and confirm_broad and broad_reason:
        mode = "full"
    elif mode_raw in {"", "metadata", "guide", "guidance", "full"}:
        mode = "metadata"
    else:
        _record_retrieval(hash_key, query, False, mode=mode_raw)
        return json.dumps(
            {
                "success": False,
                "error": "mode must be 'search', 'metadata', or 'full'",
                "hash": hash_key,
                "suggested_next_calls": _suggested_next_calls(hash_key),
            },
            ensure_ascii=False,
        )

    _record_retrieval(
        hash_key,
        query,
        True,
        mode=mode,
        content_returned=mode == "full",
    )
    response: dict[str, Any] = {"success": True, **record, "mode": mode}
    if mode == "search":
        response["query"] = query
        response["content_returned"] = False
        response["matches"] = _query_lines(original, query, _query_max_lines())
        response["match_count"] = len(response["matches"])
        response["truncated"] = False
        if not response["matches"]:
            response["suggested_next_calls"] = _suggested_next_calls(hash_key)
    elif mode == "full":
        response["content_returned"] = True
        response["needs_query"] = False
        response["content"] = original[:max_chars]
        response["truncated"] = len(original) > max_chars
        response["returned_chars"] = len(response["content"])
    else:
        response["content_returned"] = False
        response["needs_query"] = True
        response["guidance"] = (
            "Empty retrievals return metadata only. Call again with a specific "
            "query to search omitted content, or mode='full' with confirm_broad_retrieval=true "
            "and broad_reason when broad content is required."
        )
        if mode_raw == "full" and not _allow_full_retrieval():
            response["requested_mode"] = "full"
            response["full_mode_disabled"] = True
        if mode_raw == "full" and _allow_full_retrieval() and not confirm_broad:
            response["requested_mode"] = "full"
            response["full_mode_requires_confirmation"] = True
        if mode_raw == "full" and _allow_full_retrieval() and confirm_broad and not broad_reason:
            response["requested_mode"] = "full"
            response["full_mode_requires_reason"] = True
        response["suggested_next_calls"] = _suggested_next_calls(hash_key)
    return json.dumps(response, ensure_ascii=False)


def register(ctx):
    schema = {
        "name": TOOL_NAME,
        "description": "Retrieve or search an oversized tool result compacted by the Hermes tool-result compactor plugin.",
        "parameters": {
            "type": "object",
            "properties": {
                "hash": {
                    "type": "string",
                    "description": "Compacted result hash from the <<hermes_compact:...>> marker.",
                },
                "query": {
                    "type": "string",
                    "description": "Specific terms to search within the stored result. Recommended first step; empty query returns metadata/guidance only.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["metadata", "search", "full"],
                    "description": "Retrieval mode. Omit or use search with a query for targeted retrieval. Full mode returns metadata unless allow_full_retrieval is enabled and confirm_broad_retrieval plus broad_reason are provided.",
                },
                "confirm_broad_retrieval": {
                    "type": "boolean",
                    "description": "Required to return broad content with mode=full. Prefer a specific query first.",
                },
                "broad_reason": {
                    "type": "string",
                    "description": "Short reason required with confirm_broad_retrieval=true for mode=full; prevents accidental broad/empty retrievals.",
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Maximum characters to return for full retrieval; default comes from context_compactor.retrieve_max_chars.",
                },
            },
            "required": ["hash"],
        },
    }
    ctx.register_tool(
        name=TOOL_NAME,
        toolset="context_compactor",
        schema=schema,
        handler=_retrieve_handler,
    )
    ctx.register_hook("transform_tool_result", _transform_tool_result)
