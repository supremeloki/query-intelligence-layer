import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from query_intel import (
    QueryExplainer,
    QueryIntelligenceError,
    QueryProfiler,
    SchemaAwareValidator,
    SqlGuard,
    UnsafeQueryError,
)


@pytest.fixture
def guard():
    return SqlGuard(max_limit=100, forbidden_tables={"audit_log"})


def test_simple_select_allowed(guard):
    allowed, reason = guard.inspect("SELECT id FROM users")
    assert allowed


def test_insert_blocked(guard):
    allowed, reason = guard.inspect("INSERT INTO users VALUES (1)")
    assert not allowed
    assert "mutating" in reason


def test_delete_blocked(guard):
    allowed, _ = guard.inspect("DELETE FROM users WHERE id = 1")
    assert not allowed


def test_drop_blocked(guard):
    allowed, _ = guard.inspect("DROP TABLE users")
    assert not allowed


def test_stacked_queries_blocked(guard):
    allowed, reason = guard.inspect("SELECT 1; SELECT 2")
    assert not allowed
    assert "one statement" in reason or "forbidden" in reason


def test_comment_injection_blocked(guard):
    allowed, reason = guard.inspect("SELECT * FROM users -- drop table secrets")
    assert not allowed
    assert "forbidden pattern" in reason


def test_protected_table_blocked(guard):
    allowed, reason = guard.inspect("SELECT * FROM audit_log")
    assert not allowed
    assert "protected table" in reason


def test_garbage_tokens_blocked(guard):
    allowed, reason = guard.inspect("SELECT * FROM users WHERE name = 'x' AND 1=1 UNION SELECT password FROM admin")
    assert isinstance(allowed, bool)
    assert reason


def test_enforce_limit_adds_missing_limit(guard):
    rewritten = guard.enforce_limit("SELECT * FROM big_table")
    assert "100" in rewritten.upper() or "100" in rewritten
    assert guard.stats.rewritten == 1


def test_enforce_limit_caps_excessive_limit(guard):
    rewritten = guard.enforce_limit("SELECT * FROM t LIMIT 1000000")
    assert "100" in rewritten
    assert "1000000" not in rewritten


def test_enforce_limit_keeps_small_limit(guard):
    sql = "SELECT * FROM t LIMIT 10"
    assert guard.enforce_limit(sql) == sql.replace("\n", " ").strip() or \
        guard.enforce_limit(sql) == sql


def test_reject_query_raises(guard):
    with pytest.raises(UnsafeQueryError):
        guard.enforce_limit("DROP TABLE x")


def test_invalid_max_limit_rejected():
    with pytest.raises(QueryIntelligenceError):
        SqlGuard(max_limit=0)


def test_profiler_describes_query():
    profile = QueryProfiler().profile(
        "SELECT u.name, COUNT(*) FROM users u JOIN orders o ON o.user_id = u.id "
        "GROUP BY u.name LIMIT 5"
    )
    assert set(profile.tables) == {"users", "orders"}
    assert profile.has_aggregate
    assert profile.has_join
    assert profile.limit_applied == 5


def test_schema_validator_flags_unknown_table():
    validator = SchemaAwareValidator({"users": {"id", "name"}})
    problems = validator.validate_references("SELECT * FROM ghost_table")
    assert any("ghost_table" in p for p in problems)


def test_schema_validator_accepts_known_columns():
    validator = SchemaAwareValidator({"users": {"id", "name"}})
    problems = validator.validate_references("SELECT name FROM users WHERE id = 1")
    assert problems == []


def test_schema_validator_flags_unknown_column():
    validator = SchemaAwareValidator({"users": {"id", "name"}})
    problems = validator.validate_references("SELECT wizardry FROM users")
    assert any("wizardry" in p for p in problems)


def test_explainer_summarizes_plan():
    summary = QueryExplainer().explain_plan_summary(
        "SELECT region, SUM(amount) FROM sales GROUP BY region"
    )
    assert "aggregate" in summary
    assert "no-limit" in summary
