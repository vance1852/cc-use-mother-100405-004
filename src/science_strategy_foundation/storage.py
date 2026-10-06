"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bottlenecks (
    bottleneck_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    origin_key TEXT NOT NULL,
    normalized_origin TEXT NOT NULL,
    owner_team TEXT NOT NULL REFERENCES organizations(organization_id),
    security_level TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_unit TEXT NOT NULL,
    metric_direction TEXT NOT NULL CHECK(metric_direction IN ('gte', 'lte')),
    baseline_value REAL NOT NULL,
    target_value REAL NOT NULL,
    metric_revision INTEGER NOT NULL CHECK(metric_revision >= 1),
    estimate_days INTEGER NOT NULL CHECK(estimate_days >= 0),
    status TEXT NOT NULL CHECK(status IN ('pending', 'ready', 'in_progress', 'verified', 'blocked')),
    canonical_id TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS bottlenecks_origin ON bottlenecks(normalized_origin);
CREATE TABLE IF NOT EXISTS bottleneck_dependencies (
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    depends_on TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (bottleneck_id, depends_on)
);
CREATE TABLE IF NOT EXISTS metric_revisions (
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    revision INTEGER NOT NULL,
    target_value REAL NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (bottleneck_id, revision)
);
CREATE TABLE IF NOT EXISTS commitments (
    commitment_id TEXT PRIMARY KEY,
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    team_id TEXT NOT NULL,
    milestone TEXT NOT NULL,
    promised_date TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS solutions (
    solution_id TEXT PRIMARY KEY,
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    required_evidence_json TEXT NOT NULL,
    switch_cost REAL NOT NULL CHECK(switch_cost >= 0),
    status TEXT NOT NULL CHECK(status IN ('candidate', 'active', 'suspended', 'abandoned')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    kind TEXT NOT NULL,
    security_level TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_solution_kind ON evidence(solution_id, kind);
CREATE TABLE IF NOT EXISTS facilities (
    facility_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS facility_windows (
    window_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL REFERENCES facilities(facility_id),
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    freeze_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open', 'frozen', 'closed'))
);
CREATE TABLE IF NOT EXISTS leases (
    lease_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES facility_windows(window_id),
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    team_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active', 'released', 'expired')),
    granted_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS leases_single_active_per_window ON leases(window_id) WHERE state='active';
CREATE TABLE IF NOT EXISTS waitlist (
    entry_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES facility_windows(window_id),
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    team_id TEXT NOT NULL,
    priority INTEGER NOT NULL,
    requested_at TEXT NOT NULL,
    frozen_seq INTEGER,
    status TEXT NOT NULL CHECK(status IN ('waiting', 'promoted', 'expired', 'withdrawn'))
);
CREATE TABLE IF NOT EXISTS test_batches (
    batch_id TEXT PRIMARY KEY,
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    lease_id TEXT REFERENCES leases(lease_id),
    result TEXT NOT NULL CHECK(result IN ('passed', 'failed')),
    metrics_json TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS test_batches_append_only_update BEFORE UPDATE ON test_batches
BEGIN SELECT RAISE(ABORT, '试验批次只允许追加，不能修改'); END;
CREATE TRIGGER IF NOT EXISTS test_batches_append_only_delete BEFORE DELETE ON test_batches
BEGIN SELECT RAISE(ABORT, '试验批次只允许追加，不能删除'); END;
CREATE TABLE IF NOT EXISTS adjudications (
    adjudication_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('alias_merge', 'downgrade_review', 'waitlist_dispute')),
    subject_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
    resolution_json TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT
);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交；多线程并发时串行化事务。"""

        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield self.connection
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
