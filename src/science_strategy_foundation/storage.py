"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
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
    source_key TEXT NOT NULL,
    root_bottleneck_id TEXT,
    owner_team_id TEXT NOT NULL REFERENCES organizations(organization_id),
    confidentiality TEXT NOT NULL CHECK(confidentiality IN ('open','internal','confidential')),
    estimate_days INTEGER NOT NULL CHECK(estimate_days >= 0),
    status TEXT NOT NULL CHECK(status IN ('open','merged')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bottlenecks_source ON bottlenecks(site_id, source_key);
CREATE TABLE IF NOT EXISTS target_metrics (
    metric_id TEXT PRIMARY KEY,
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    name TEXT NOT NULL,
    unit TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('at_least','at_most')),
    target_value REAL NOT NULL,
    degraded INTEGER NOT NULL DEFAULT 0 CHECK(degraded IN (0, 1)),
    version INTEGER NOT NULL CHECK(version >= 1),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dependencies (
    dependency_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    upstream_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    downstream_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(upstream_id, downstream_id)
);
CREATE TABLE IF NOT EXISTS solutions (
    solution_id TEXT PRIMARY KEY,
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    name TEXT NOT NULL,
    required_evidence_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    switch_cost REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK(status IN ('active','standby','failed','replaced')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id TEXT PRIMARY KEY,
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    solution_id TEXT,
    evidence_type TEXT NOT NULL,
    confidentiality TEXT NOT NULL CHECK(confidentiality IN ('open','internal','confidential')),
    payload_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    expired_notified INTEGER NOT NULL DEFAULT 0 CHECK(expired_notified IN (0, 1)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS commitments (
    commitment_id TEXT PRIMARY KEY,
    bottleneck_id TEXT NOT NULL REFERENCES bottlenecks(bottleneck_id),
    team_id TEXT NOT NULL REFERENCES organizations(organization_id),
    promise_date TEXT NOT NULL,
    note TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','fulfilled')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS facility_windows (
    window_id TEXT PRIMARY KEY,
    facility_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open','offered','leased','closed')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    lease_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES facility_windows(window_id),
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    team_id TEXT NOT NULL REFERENCES organizations(organization_id),
    status TEXT NOT NULL CHECK(status IN ('active','released','expired')),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS waitlist_entries (
    entry_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES facility_windows(window_id),
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    team_id TEXT NOT NULL REFERENCES organizations(organization_id),
    position INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('waiting','frozen','promoted','confirmed','lapsed','cancelled')),
    frozen_seq INTEGER,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS adjudications (
    adjudication_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES facility_windows(window_id),
    entry_id TEXT NOT NULL REFERENCES waitlist_entries(entry_id),
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    team_id TEXT NOT NULL REFERENCES organizations(organization_id),
    freeze_seq INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','confirmed','lapsed')),
    offered_at TEXT NOT NULL,
    confirm_by TEXT NOT NULL,
    confirmed_at TEXT
);
CREATE TABLE IF NOT EXISTS test_batches (
    batch_id TEXT PRIMARY KEY,
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    lease_id TEXT NOT NULL REFERENCES leases(lease_id),
    facility_id TEXT NOT NULL,
    result TEXT NOT NULL CHECK(result IN ('pending','passed','failed')),
    measured_json TEXT,
    recorded_by TEXT,
    recorded_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resolutions (
    bottleneck_id TEXT PRIMARY KEY REFERENCES bottlenecks(bottleneck_id),
    solution_id TEXT NOT NULL REFERENCES solutions(solution_id),
    batch_id TEXT NOT NULL REFERENCES test_batches(batch_id),
    resolved_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recompute_events (
    event_id TEXT PRIMARY KEY,
    trigger TEXT NOT NULL,
    affected_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
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

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

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
