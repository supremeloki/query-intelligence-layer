from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import sqlglot
from sqlglot import exp


class QueryIntelligenceError(Exception):
    pass


class UnsafeQueryError(QueryIntelligenceError):
    pass


class ParseFailureError(QueryIntelligenceError):
    pass


MUTATING_TYPES = (exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Alter, exp.Create)


FORBIDDEN_PATTERN: re.Pattern[str] = re.compile(
    r";|--|/\*|\bexec\b|\bxp_\w+\b", re.IGNORECASE
)


@dataclass(frozen=True)
class QueryProfile:
    sql: str
    tables: tuple[str, ...]
    columns: tuple[str, ...]
    has_aggregate: bool
    has_join: bool
    limit_applied: int | None

    @property
    def is_read_only(self) -> bool:
        return True


@dataclass(frozen=True)
class GuardVerdict:
    allowed: bool
    reason: str
    rewritten_sql: str | None = None


@dataclass
class GuardStats:
    checked: int = 0
    blocked: int = 0
    rewritten: int = 0


class SqlGuard:
    def __init__(self, max_limit: int = 1000,
                 forbidden_tables: set[str] | None = None) -> None:
        if max_limit < 1:
            raise QueryIntelligenceError("max_limit must be >= 1")
        self._max_limit = max_limit
        self._forbidden = {t.lower() for t in (forbidden_tables or set())}
        self.stats = GuardStats()

    def inspect(self, sql: str) -> tuple[bool, str]:
        self.stats.checked += 1
        if FORBIDDEN_PATTERN.search(sql):
            self.stats.blocked += 1
            return False, "forbidden pattern detected"
        try:
            statements = sqlglot.parse(sql)
        except Exception as exc:
            self.stats.blocked += 1
            return False, f"parse failure: {exc}"
        if len(statements) != 1 or statements[0] is None:
            self.stats.blocked += 1
            return False, "exactly one statement required"
        statement = statements[0]
        for node in statement.walk():
            if isinstance(node, MUTATING_TYPES):
                self.stats.blocked += 1
                return False, "mutating statements are not allowed"
            if isinstance(node, exp.Table) and node.name.lower() in self._forbidden:
                self.stats.blocked += 1
                return False, f"access to protected table: {node.name}"
        return True, "safe read"

    def enforce_limit(self, sql: str) -> str:
        allowed, _ = self.inspect(sql)
        if not allowed:
            raise UnsafeQueryError("query rejected by guard")
        expression = sqlglot.parse_one(sql)
        if isinstance(expression, exp.Select):
            current_limit = expression.args.get("limit")
            if current_limit is None:
                rewritten = expression.limit(self._max_limit)
                self.stats.rewritten += 1
                return rewritten.sql()
            literal = current_limit.find(exp.Literal)
            if literal is not None and int(str(literal.this)) > self._max_limit:
                rewritten = expression.limit(self._max_limit)
                self.stats.rewritten += 1
                return rewritten.sql()
        return sql


class QueryProfiler:
    def profile(self, sql: str) -> QueryProfile:
        allowed, reason = SqlGuard().inspect(sql)
        if not allowed:
            raise UnsafeQueryError(reason)
        expression = sqlglot.parse_one(sql)
        tables = [t.name for t in expression.find_all(exp.Table)]
        columns = sorted({c.name for c in expression.find_all(exp.Column)})
        aggregates = list(expression.find_all(exp.AggFunc))
        joins = list(expression.find_all(exp.Join))
        limit_arg = expression.args.get("limit")
        applied = None
        if limit_arg is not None:
            literal = limit_arg.find(exp.Literal)
            if literal is not None:
                applied = int(str(literal.this))
        return QueryProfile(
            sql=sql.strip(),
            tables=tuple(dict.fromkeys(tables)),
            columns=tuple(columns),
            has_aggregate=bool(aggregates),
            has_join=bool(joins),
            limit_applied=applied,
        )


class SchemaAwareValidator:
    def __init__(self, schema: dict[str, set[str]]) -> None:
        self._schema = {table.lower(): {c.lower() for c in cols}
                        for table, cols in schema.items()}

    def validate_references(self, sql: str) -> list[str]:
        problems: list[str] = []
        try:
            expression = sqlglot.parse_one(sql)
        except Exception as exc:
            return [f"parse failure: {exc}"]
        for table_node in expression.find_all(exp.Table):
            table_name = table_node.name.lower()
            if self._schema and table_name not in self._schema and table_name != "dual":
                problems.append(f"unknown table: {table_name}")
        alias_map: dict[str, str] = {}
        for table_node in expression.find_all(exp.Table):
            if table_node.alias:
                alias_map[table_node.alias.lower()] = table_node.name.lower()
        for column_node in expression.find_all(exp.Column):
            column_name = column_node.name.lower()
            table_ref = (
                column_node.table.lower() if column_node.table else None
            )
            resolved = alias_map.get(table_ref, table_ref) if table_ref else None
            candidates = (
                [self._schema.get(resolved, set())]
                if resolved
                else list(self._schema.values())
            )
            known_any = any(column_name in cols for cols in candidates if cols)
            full_catalog = {c for cols in self._schema.values() for c in cols}
            if column_name == "*" or column_name in full_catalog or known_any:
                continue
            if not self._schema:
                continue
            problems.append(f"unknown column: {column_name}")
        return problems


class QueryExplainer:
    def explain_plan_summary(self, sql: str) -> str:
        profile = QueryProfiler().profile(sql)
        parts = [f"tables={len(profile.tables)}"]
        if profile.has_join:
            parts.append("join")
        if profile.has_aggregate:
            parts.append("aggregate")
        if profile.limit_applied is not None:
            parts.append(f"limit={profile.limit_applied}")
        else:
            parts.append("no-limit")
        return ", ".join(parts)


__all__ = [
    "GuardVerdict",
    "QueryExplainer",
    "QueryIntelligenceError",
    "QueryProfiler",
    "SchemaAwareValidator",
    "SqlGuard",
    "UnsafeQueryError",
    "ParseFailureError",
]
