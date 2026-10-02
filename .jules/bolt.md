## 2026-10-02 - SQLite statement caching
**Learning:** By switching `db.prepare()` to `db.prepare_cached()`, we leverage `rusqlite`'s built-in statement caching for long-lived SQLite connections. This improves performance for repeated queries (like manifest checking and trash listing) by avoiding the re-parsing and re-compiling of identical SQL strings.
**Action:** Always consider `prepare_cached()` instead of `prepare()` when a query is repeatedly executed on a persistent SQLite connection.
