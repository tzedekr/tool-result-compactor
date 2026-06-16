from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import stat
import time
from pathlib import Path

PLUGIN_PATH = Path(__file__).resolve().parents[1] / "__init__.py"


def load_plugin(home: Path):
    os.environ["HERMES_HOME"] = str(home)
    os.environ.pop("HERMES_TOOL_COMPACTOR_MIN_CHARS", None)
    spec = importlib.util.spec_from_file_location(
        f"tool_result_compactor_under_test_{time.time_ns()}", PLUGIN_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_config(home: Path, context_compactor: dict) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        "plugins:\n"
        "  enabled:\n"
        "    - tool-result-compactor\n"
        "context_compactor:\n"
        + "".join(f"  {key}: {value!r}\n" for key, value in context_compactor.items()),
        encoding="utf-8",
    )


def invoke_transform(plugin, result: str, *, status: str = "success"):
    return plugin._transform_tool_result(
        tool_name="terminal",
        args={"command": "fixture"},
        result=result,
        status=status,
        task_id="",
        session_id="test-session",
        tool_call_id="test-call",
        turn_id="test-turn",
        api_request_id="test-api",
        duration_ms=1,
        error_type="",
        error_message="",
    )


def test_config_file_controls_min_preview_retrieve_and_query_limits(tmp_path: Path):
    write_config(
        tmp_path,
        {
            "min_chars": 50,
            "preview_chars": 25,
            "retrieve_max_chars": 12,
            "query_max_lines": 1,
            "ttl_seconds": 0,
            "allow_full_retrieval": True,
        },
    )
    plugin = load_plugin(tmp_path)
    result = "\n".join(
        ["needle first line " + "a" * 30]
        + ["ordinary " + "b" * 30 for _ in range(8)]
        + ["needle second line " + "c" * 30]
    )

    compacted_raw = invoke_transform(plugin, result)

    assert compacted_raw is not None
    compacted = json.loads(compacted_raw)
    assert compacted["preview_chars"] == 25
    assert compacted["preview"] == result[:25]

    metadata = json.loads(plugin._retrieve_handler({"hash": compacted["hash"]}))
    assert metadata["success"] is True
    assert metadata["mode"] == "metadata"
    assert metadata["content_returned"] is False
    assert metadata["needs_query"] is True
    assert "content" not in metadata
    assert metadata["suggested_next_calls"]["search"]["query"] == "<specific terms>"

    retrieved = json.loads(
        plugin._retrieve_handler(
            {
                "hash": compacted["hash"],
                "mode": "full",
                "confirm_broad_retrieval": True,
                "broad_reason": "verify retrieve_max_chars full-mode truncation",
            }
        )
    )
    assert retrieved["success"] is True
    assert retrieved["mode"] == "full"
    assert retrieved["returned_chars"] == 12
    assert retrieved["content"] == result[:12]
    assert retrieved["truncated"] is True

    matches = json.loads(plugin._retrieve_handler({"hash": compacted["hash"], "query": "needle"}))
    assert matches["success"] is True
    assert matches["match_count"] == 1
    assert "needle first line" in matches["matches"][0]["text"]


def test_ttl_purges_stale_compacted_results_and_events(tmp_path: Path):
    write_config(tmp_path, {"min_chars": 10, "ttl_seconds": 1})
    plugin = load_plugin(tmp_path)
    old_ts = time.time() - 120
    with plugin._connect() as conn:
        conn.execute(
            """
            INSERT INTO compacted_tool_results
            (hash, created_at, session_id, tool_call_id, tool_name, status,
             original_chars, preview, original)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("deadbeefdeadbeef", old_ts, "s", "tc", "terminal", "success", 4, "old", "old"),
        )
        conn.execute(
            """
            INSERT INTO retrieval_events (created_at, hash, query, success)
            VALUES (?, ?, ?, ?)
            """,
            (old_ts, "deadbeefdeadbeef", "old", 1),
        )

    assert plugin._load_result("deadbeefdeadbeef") is None
    with sqlite3.connect(tmp_path / "cache" / "tool-result-compactor" / "store.sqlite3") as conn:
        assert conn.execute("SELECT COUNT(*) FROM compacted_tool_results").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM retrieval_events").fetchone()[0] == 0


def test_secret_detection_skips_real_secret_values_without_skipping_token_language(tmp_path: Path):
    write_config(tmp_path, {"min_chars": 80, "preview_chars": 30, "ttl_seconds": 0})
    plugin = load_plugin(tmp_path)

    ordinary_token_text = json.dumps(
        {
            "summary": "token budget improved after compaction",
            "rows": ["routine context accounting row"] * 20,
        }
    )
    compacted_raw = invoke_transform(plugin, ordinary_token_text)
    assert compacted_raw is not None, "ordinary token-budget language is not a credential"

    fake_access_env = "AWS_" + "ACCESS_" + "KEY_ID"
    fake_access_value = "AK" + "IA12TESTCDEF"
    secret_value = json.dumps(
        {
            "stdout": f"configured {fake_access_env}={fake_access_value} for a test shell",
            "rows": ["routine context accounting row"] * 20,
        }
    )
    assert invoke_transform(plugin, secret_value) is None

    fake_header = "X-" + "Api-" + "Key"
    fake_secret_value = "sk-" + "testruntimeescaped"
    secret_key = json.dumps(
        {
            "headers": {fake_header: fake_secret_value},
            "rows": ["routine context accounting row"] * 20,
        }
    )
    assert invoke_transform(plugin, secret_key) is None


def test_compacted_payload_contains_structured_retrieval_guidance(tmp_path: Path):
    write_config(tmp_path, {"min_chars": 10, "preview_chars": 40, "ttl_seconds": 3600})
    plugin = load_plugin(tmp_path)
    compacted_raw = invoke_transform(plugin, "structured retrieval guidance row\n" * 20)

    assert compacted_raw is not None
    compacted = json.loads(compacted_raw)
    assert compacted["retrieval"]["tool"] == "context_compactor_retrieve"
    assert compacted["retrieval"]["hash"] == compacted["hash"]
    assert compacted["retrieval"]["recommended_first_call"] == {
        "hash": compacted["hash"],
        "query": "<specific terms>",
    }
    assert "full_content_call" not in compacted["retrieval"]
    assert compacted["retrieval"]["fallback_full_mode"] == "Use mode='full' only after targeted search is insufficient."
    assert "empty query" in compacted["retrieve_instruction"]
    assert "mode='full'" in compacted["retrieve_instruction"]


def test_empty_query_records_guidance_event_without_returning_broad_content(tmp_path: Path):
    write_config(tmp_path, {"min_chars": 10, "ttl_seconds": 3600})
    plugin = load_plugin(tmp_path)
    original = "empty query should not dump broad content\n" * 20
    compacted_raw = invoke_transform(plugin, original)
    assert compacted_raw is not None
    hash_key = json.loads(compacted_raw)["hash"]

    response = json.loads(plugin._retrieve_handler({"hash": hash_key, "query": "   "}))

    assert response["success"] is True
    assert response["mode"] == "metadata"
    assert response["content_returned"] is False
    assert response["needs_query"] is True
    assert "content" not in response
    with plugin._connect() as conn:
        event = conn.execute(
            "SELECT query, success, mode, content_returned FROM retrieval_events WHERE hash = ? ORDER BY id DESC LIMIT 1",
            (hash_key,),
        ).fetchone()
    assert event == ("", 1, "metadata", 0)


def test_full_mode_without_confirmation_returns_guidance_not_broad_content(tmp_path: Path):
    write_config(
        tmp_path,
        {"min_chars": 10, "retrieve_max_chars": 24, "ttl_seconds": 3600, "allow_full_retrieval": True},
    )
    plugin = load_plugin(tmp_path)
    original = "unconfirmed full retrieval row\n" * 20
    compacted_raw = invoke_transform(plugin, original)
    assert compacted_raw is not None
    hash_key = json.loads(compacted_raw)["hash"]

    response = json.loads(plugin._retrieve_handler({"hash": hash_key, "mode": "full"}))

    assert response["success"] is True
    assert response["mode"] == "metadata"
    assert response["requested_mode"] == "full"
    assert response["content_returned"] is False
    assert response["full_mode_requires_confirmation"] is True
    assert "content" not in response
    with plugin._connect() as conn:
        event = conn.execute(
            "SELECT query, success, mode, content_returned FROM retrieval_events WHERE hash = ? ORDER BY id DESC LIMIT 1",
            (hash_key,),
        ).fetchone()
    assert event == ("", 1, "metadata", 0)


def test_full_mode_with_confirmation_but_no_reason_returns_guidance(tmp_path: Path):
    write_config(
        tmp_path,
        {"min_chars": 10, "retrieve_max_chars": 24, "ttl_seconds": 3600, "allow_full_retrieval": True},
    )
    plugin = load_plugin(tmp_path)
    original = "confirmed but reasonless full retrieval row\n" * 20
    compacted_raw = invoke_transform(plugin, original)
    assert compacted_raw is not None
    hash_key = json.loads(compacted_raw)["hash"]

    response = json.loads(
        plugin._retrieve_handler(
            {"hash": hash_key, "mode": "full", "confirm_broad_retrieval": True}
        )
    )

    assert response["success"] is True
    assert response["mode"] == "metadata"
    assert response["content_returned"] is False
    assert response["full_mode_requires_reason"] is True
    assert "content" not in response
    with plugin._connect() as conn:
        event = conn.execute(
            "SELECT query, success, mode, content_returned FROM retrieval_events WHERE hash = ? ORDER BY id DESC LIMIT 1",
            (hash_key,),
        ).fetchone()
    assert event == ("", 1, "metadata", 0)


def test_explicit_full_mode_returns_content_and_records_mode(tmp_path: Path):
    write_config(
        tmp_path,
        {"min_chars": 10, "retrieve_max_chars": 24, "ttl_seconds": 3600, "allow_full_retrieval": True},
    )
    plugin = load_plugin(tmp_path)
    original = "explicit full retrieval row\n" * 20
    compacted_raw = invoke_transform(plugin, original)
    assert compacted_raw is not None
    hash_key = json.loads(compacted_raw)["hash"]

    response = json.loads(
        plugin._retrieve_handler(
            {
                "hash": hash_key,
                "mode": "full",
                "confirm_broad_retrieval": True,
                "broad_reason": "verify explicit full retrieval test behavior",
            }
        )
    )
    assert response["success"] is True
    assert response["mode"] == "full"
    assert response["content_returned"] is True
    assert response["content"] == original[:24]
    assert response["returned_chars"] == 24
    assert response["truncated"] is True
    with plugin._connect() as conn:
        event = conn.execute(
            "SELECT query, success, mode, content_returned FROM retrieval_events WHERE hash = ? ORDER BY id DESC LIMIT 1",
            (hash_key,),
        ).fetchone()
    assert event == ("", 1, "full", 1)


def test_store_path_is_private_and_secure_delete_enabled(tmp_path: Path):
    write_config(tmp_path, {"min_chars": 10, "ttl_seconds": 3600})
    plugin = load_plugin(tmp_path)

    compacted_raw = invoke_transform(plugin, "private storage hardening row\n" * 20)

    assert compacted_raw is not None
    db_path = tmp_path / "cache" / "tool-result-compactor" / "store.sqlite3"
    assert db_path.exists()
    store_mode = stat.S_IMODE(db_path.parent.stat().st_mode)
    db_mode = stat.S_IMODE(db_path.stat().st_mode)
    assert store_mode & 0o077 == 0, oct(store_mode)
    assert db_mode & 0o077 == 0, oct(db_mode)
    with plugin._connect() as conn:
        assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"


def test_zero_ttl_is_bounded_unless_unbounded_retention_is_explicit(tmp_path: Path):
    write_config(tmp_path, {"min_chars": 10, "ttl_seconds": 0})
    plugin = load_plugin(tmp_path)

    compacted_raw = invoke_transform(plugin, "bounded retention row\n" * 20)

    assert compacted_raw is not None
    compacted = json.loads(compacted_raw)
    assert compacted["retention"]["configured_ttl_seconds"] == 0
    assert compacted["retention"]["effective_ttl_seconds"] > 0
    assert compacted["retention"]["unbounded_retention"] is False

    with plugin._connect() as conn:
        row = conn.execute(
            "SELECT created_at, expires_at FROM compacted_tool_results WHERE hash = ?",
            (compacted["hash"],),
        ).fetchone()
    assert row is not None
    created_at, expires_at = row
    assert expires_at is not None
    assert expires_at > created_at

    explicit_home = tmp_path / "explicit"
    write_config(
        explicit_home,
        {"min_chars": 10, "ttl_seconds": 0, "allow_unbounded_retention": True},
    )
    explicit_plugin = load_plugin(explicit_home)
    explicit_raw = invoke_transform(explicit_plugin, "explicit unbounded row\n" * 20)
    assert explicit_raw is not None
    explicit_payload = json.loads(explicit_raw)
    assert explicit_payload["retention"]["effective_ttl_seconds"] == 0
    assert explicit_payload["retention"]["unbounded_retention"] is True
    with explicit_plugin._connect() as conn:
        assert conn.execute(
            "SELECT expires_at FROM compacted_tool_results WHERE hash = ?",
            (explicit_payload["hash"],),
        ).fetchone()[0] is None


def test_max_records_purges_oldest_records_and_orphan_events(tmp_path: Path):
    write_config(
        tmp_path,
        {"min_chars": 10, "ttl_seconds": 3600, "max_records": 2},
    )
    plugin = load_plugin(tmp_path)

    payloads = []
    for idx in range(3):
        raw = invoke_transform(plugin, f"record {idx} retention cap\n" * 20)
        assert raw is not None
        payloads.append(json.loads(raw))
        with plugin._connect() as conn:
            conn.execute(
                "INSERT INTO retrieval_events (created_at, hash, query, success) VALUES (?, ?, ?, ?)",
                (time.time(), payloads[-1]["hash"], "probe", 1),
            )
        time.sleep(0.01)

    with plugin._connect() as conn:
        rows = conn.execute(
            "SELECT hash FROM compacted_tool_results ORDER BY created_at ASC"
        ).fetchall()
        hashes = [row[0] for row in rows]
        event_hashes = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT hash FROM retrieval_events ORDER BY hash"
            ).fetchall()
        ]

    assert len(hashes) == 2
    assert payloads[0]["hash"] not in hashes
    assert hashes == [payloads[1]["hash"], payloads[2]["hash"]]
    assert payloads[0]["hash"] not in event_hashes
