# query-intelligence-layer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An intelligence layer over SQL: a safety guard that blocks mutating statements and enforces row limits, an AST profiler, schema-aware column validation, and plain-language plan summaries — the brain between NL answers and the database.

## 🚀 Overview

The flagship AI+Database layer of the 2025 roadmap. When a model generates SQL, something must decide *may this run?* and *what does it actually do?* `query-intelligence-layer` answers both: `SqlGuard` parses with sqlglot's AST (not regex) to reject INSERT/UPDATE/DELETE/DROP, stacked statements, comment injection, and protected tables; then caps or injects LIMIT clauses. `QueryProfiler` describes structure (tables, aggregates, joins), and `SchemaAwareValidator` checks every referenced table/column against a declared schema before execution.

## ✨ Features

- **AST-level guard:** mutation detection via sqlglot node types — immune to keyword tricks
- **Injection patterns:** stacked statements (`;`), SQL comments, `EXEC`/`xp_*` calls rejected by pattern
- **Protected tables:** deny-list checked on every table reference in the AST
- **Automatic LIMIT:** missing limits injected, excessive limits capped; rewrites counted
- **Schema validation:** unknown tables and columns flagged against a declared catalog, alias-aware
- **Profiler + explainer:** structural profile and human-readable one-line plan summary
- **Zero runtime dependencies** beyond sqlglot

## 🚧 Structure

```
query-intelligence-layer/
├── src/query_intel/
│   ├── __init__.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/query-intelligence-layer.git
cd query-intelligence-layer
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- Runtime: `sqlglot >= 20`

## 🏃 Quick Start

```python
from query_intel import QueryProfiler, SchemaAwareValidator, SqlGuard

guard = SqlGuard(max_limit=500, forbidden_tables={"audit_log"})
allowed, reason = guard.inspect("SELECT name FROM users")
safe_sql = guard.enforce_limit("SELECT * FROM events")

validator = SchemaAwareValidator({"users": {"id", "name"}})
problems = validator.validate_references(safe_sql)

profile = QueryProfiler().profile(safe_sql)
print(profile.tables, profile.has_aggregate)
```

## 🔧 Error Handling

```text
QueryIntelligenceError
└── UnsafeQueryError     # enforce_limit() called on rejected SQL
```

Inspection itself never raises — it returns `(allowed, reason)` pairs.

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style)
- Zero comments — names carry the meaning
- AST-based detection tested against 18 attack/usage scenarios

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi**

---

⭐ Star this repo if you find it useful!
