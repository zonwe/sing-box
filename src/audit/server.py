#!/usr/bin/env python3
"""sing-box traffic audit service.

The service polls the local sing-box Clash-compatible API, persists traffic
samples and connection metadata in SQLite, and exposes a small read-only web
dashboard/API.  It intentionally uses only the Python standard library.
"""

import argparse
import csv
import datetime
import glob
import hmac
import io
import json
import os
import re
import signal
import sqlite3
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import ProxyHandler, Request, build_opener


SERVICE_VERSION = "1.2.0"
USAGE_BUCKET_SECONDS = 60
RANGES = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
}


def utc_iso(timestamp):
    if not timestamp:
        return None
    return datetime.datetime.fromtimestamp(int(timestamp), datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value, fallback):
    if not value:
        return fallback
    if isinstance(value, (int, float)):
        return int(value)
    if re.fullmatch(r"[0-9]+", str(value)):
        return int(value)
    match = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$",
        str(value),
    )
    if not match:
        return fallback
    try:
        parts = [int(part) for part in match.groups()[:6]]
        fraction = match.group(7) or "0"
        microsecond = int((fraction + "000000")[:6])
        zone = match.group(8) or "Z"
        if zone == "Z":
            timezone = datetime.timezone.utc
        else:
            sign = 1 if zone[0] == "+" else -1
            compact = zone[1:].replace(":", "")
            offset = datetime.timedelta(hours=int(compact[:2]), minutes=int(compact[2:]))
            timezone = datetime.timezone(sign * offset)
        parsed = datetime.datetime(*parts, microsecond=microsecond, tzinfo=timezone)
        return int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError):
        return fallback


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(value, minimum, maximum):
    return max(minimum, min(maximum, value))


class ConfigIdentityResolver:
    """Resolve an inbound tag to its local config file and non-secret user ID."""

    def __init__(self, config_dir):
        self.config_dir = os.path.abspath(config_dir) if config_dir else ""
        self.entries = {}
        self.last_refresh = 0

    @staticmethod
    def _user_identity(user):
        # UUID is the only credential intentionally exposed as an audit identity.
        # Passwords are never copied into the audit database or dashboard.
        return str(user.get("uuid") or user.get("name") or user.get("username") or "")

    def _refresh(self):
        now = time.monotonic()
        if self.last_refresh and now - self.last_refresh < 5:
            return
        self.last_refresh = now
        entries = {}
        if not self.config_dir or not os.path.isdir(self.config_dir):
            self.entries = entries
            return
        for path in glob.glob(os.path.join(self.config_dir, "*.json")):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    config = json.load(handle)
            except (OSError, ValueError):
                continue
            config_name = os.path.basename(path)
            for inbound in config.get("inbounds") or []:
                if not isinstance(inbound, dict):
                    continue
                tag = str(inbound.get("tag") or config_name)
                users = [user for user in (inbound.get("users") or []) if isinstance(user, dict)]
                named_users = {
                    str(user.get("name") or user.get("username") or ""): self._user_identity(user)
                    for user in users
                    if user.get("name") or user.get("username")
                }
                identities = [self._user_identity(user) for user in users]
                identities = [identity for identity in identities if identity]
                entries[tag] = {
                    "config_name": config_name,
                    "named_users": named_users,
                    "single_identity": identities[0] if len(identities) == 1 else "",
                }
        self.entries = entries

    def resolve(self, inbound, api_user):
        self._refresh()
        inbound = os.path.basename(str(inbound or ""))
        api_user = str(api_user or "")
        entry = self.entries.get(inbound)
        if not entry:
            return inbound, api_user
        user = entry["named_users"].get(api_user, api_user) if api_user else entry["single_identity"]
        return entry["config_name"], user


class AuditStore:
    CONNECTION_COLUMNS = (
        "id", "start_time", "end_time", "last_seen", "status", "network",
        "inbound", "inbound_type", "config_name", "source_ip", "source_port", "destination",
        "destination_ip", "destination_port", "host", "user", "protocol",
        "process", "outbound", "chains", "rule", "upload", "download",
    )
    USAGE_EXPORT_COLUMNS = (
        "source_ip", "config_name", "user", "first_seen", "last_seen",
        "connections", "upload", "download", "total",
    )
    CONFIG_USAGE_EXPORT_COLUMNS = (
        "config_name", "first_seen", "last_seen", "clients", "users",
        "connections", "upload", "download", "total",
    )

    def __init__(self, database, retention_days):
        database_dir = os.path.dirname(os.path.abspath(database))
        os.makedirs(database_dir, mode=0o750, exist_ok=True)
        self.database = database
        self.retention_days = clamp(as_int(retention_days, 90), 1, 3650)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self._migrate()
        try:
            os.chmod(database, 0o640)
        except OSError:
            pass

    def _migrate(self):
        with self.lock, self.db:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS traffic_samples (
                    ts INTEGER PRIMARY KEY,
                    upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS connections (
                    id TEXT PRIMARY KEY,
                    start_time INTEGER NOT NULL,
                    end_time INTEGER,
                    last_seen INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    network TEXT NOT NULL DEFAULT '',
                    inbound TEXT NOT NULL DEFAULT '',
                    inbound_type TEXT NOT NULL DEFAULT '',
                    config_name TEXT NOT NULL DEFAULT '',
                    source_ip TEXT NOT NULL DEFAULT '',
                    source_port INTEGER NOT NULL DEFAULT 0,
                    destination TEXT NOT NULL DEFAULT '',
                    destination_ip TEXT NOT NULL DEFAULT '',
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    host TEXT NOT NULL DEFAULT '',
                    user TEXT NOT NULL DEFAULT '',
                    protocol TEXT NOT NULL DEFAULT '',
                    process TEXT NOT NULL DEFAULT '',
                    outbound TEXT NOT NULL DEFAULT '',
                    chains TEXT NOT NULL DEFAULT '[]',
                    rule TEXT NOT NULL DEFAULT '',
                    upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS usage_samples (
                    ts INTEGER NOT NULL,
                    source_ip TEXT NOT NULL DEFAULT '',
                    config_name TEXT NOT NULL DEFAULT '',
                    user TEXT NOT NULL DEFAULT '',
                    upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (ts, source_ip, config_name, user)
                );
                CREATE TABLE IF NOT EXISTS destination_samples (
                    ts INTEGER NOT NULL,
                    destination TEXT NOT NULL,
                    upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (ts, destination)
                );
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connections(last_seen);
                CREATE INDEX IF NOT EXISTS idx_connections_start_time ON connections(start_time);
                CREATE INDEX IF NOT EXISTS idx_connections_status ON connections(status);
                CREATE INDEX IF NOT EXISTS idx_connections_user ON connections(user);
                CREATE INDEX IF NOT EXISTS idx_connections_host ON connections(host);
                CREATE INDEX IF NOT EXISTS idx_usage_samples_ts ON usage_samples(ts);
                CREATE INDEX IF NOT EXISTS idx_usage_samples_source_ip ON usage_samples(source_ip, ts);
                CREATE INDEX IF NOT EXISTS idx_usage_samples_config_name ON usage_samples(config_name, ts);
                CREATE INDEX IF NOT EXISTS idx_usage_samples_user ON usage_samples(user, ts);
                CREATE INDEX IF NOT EXISTS idx_destination_samples_ts ON destination_samples(ts);
                """
            )
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(connections)").fetchall()}
            if "config_name" not in columns:
                self.db.execute("ALTER TABLE connections ADD COLUMN config_name TEXT NOT NULL DEFAULT ''")
            self.db.execute("UPDATE connections SET config_name = inbound WHERE config_name = '' AND inbound != ''")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_connections_config_name ON connections(config_name)")

    def close(self):
        with self.lock:
            self.db.close()

    def _state_get(self, key):
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _state_set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO state(key, value) VALUES (?, ?)", (key, str(value)))

    @staticmethod
    def _connection_record(connection, now, resolver=None):
        metadata = connection.get("metadata") or {}
        chains = connection.get("chains") or []
        if not isinstance(chains, list):
            chains = [str(chains)]
        raw_type = str(metadata.get("type") or metadata.get("inboundType") or "")
        inbound_type = str(metadata.get("inboundType") or "")
        inbound = str(metadata.get("inbound") or metadata.get("inboundName") or "")
        if "/" in raw_type:
            type_name, type_tag = raw_type.split("/", 1)
            inbound_type = inbound_type or type_name
            inbound = inbound or type_tag
        else:
            inbound_type = inbound_type or raw_type
        api_user = str(metadata.get("user") or metadata.get("inboundUser") or "")
        config_name, user = resolver.resolve(inbound, api_user) if resolver else (inbound, api_user)
        destination_ip = str(metadata.get("destinationIP") or metadata.get("remoteDestination") or "")
        host = str(metadata.get("host") or metadata.get("sniffHost") or "")
        destination = host or destination_ip
        outbound = str(chains[0]) if chains else ""
        return {
            "id": str(connection.get("id") or ""),
            "start_time": min(parse_timestamp(connection.get("start"), now), now),
            "end_time": None,
            "last_seen": now,
            "status": "active",
            "network": str(metadata.get("network") or ""),
            "inbound": inbound,
            "inbound_type": inbound_type,
            "config_name": config_name,
            "source_ip": str(metadata.get("sourceIP") or ""),
            "source_port": as_int(metadata.get("sourcePort")),
            "destination": destination,
            "destination_ip": destination_ip,
            "destination_port": as_int(metadata.get("destinationPort")),
            "host": host,
            "user": user,
            "protocol": inbound_type,
            "process": str(metadata.get("processPath") or metadata.get("process") or ""),
            "outbound": outbound,
            "chains": json.dumps(chains, ensure_ascii=False, separators=(",", ":")),
            "rule": str(connection.get("rule") or ""),
            "upload": max(0, as_int(connection.get("upload"))),
            "download": max(0, as_int(connection.get("download"))),
        }

    def capture(self, snapshot, resolver=None):
        sampled_at = time.time()
        now = int(sampled_at)
        connections = snapshot.get("connections") or []
        upload_total = max(0, as_int(snapshot.get("uploadTotal")))
        download_total = max(0, as_int(snapshot.get("downloadTotal")))
        active_ids = set()
        usage_deltas = {}
        destination_deltas = {}

        with self.lock, self.db:
            old_upload = self._state_get("collector_upload_total")
            old_download = self._state_get("collector_download_total")
            previous_sample = float(self._state_get("collector_sample_time") or self._state_get("collector_last_success") or sampled_at)
            sample_seconds = max(0.0, sampled_at - previous_sample)
            initial_snapshot = old_upload is None and old_download is None
            upload_delta = 0 if old_upload is None else (upload_total - as_int(old_upload) if upload_total >= as_int(old_upload) else upload_total)
            download_delta = 0 if old_download is None else (download_total - as_int(old_download) if download_total >= as_int(old_download) else download_total)
            upload_delta = max(0, upload_delta)
            download_delta = max(0, download_delta)
            # Persist the duration and rate together with the counter baseline.
            # A sparse poll must not be treated as a one-second traffic sample.
            self._state_set("collector_upload_speed", int(upload_delta / sample_seconds) if sample_seconds else 0)
            self._state_set("collector_download_speed", int(download_delta / sample_seconds) if sample_seconds else 0)
            self._state_set("collector_sample_seconds", sample_seconds)
            self._state_set("collector_sample_time", sampled_at)
            row = self.db.execute("SELECT upload, download FROM traffic_samples WHERE ts = ?", (now,)).fetchone()
            if row:
                upload_delta += row["upload"]
                download_delta += row["download"]
            self.db.execute(
                "INSERT OR REPLACE INTO traffic_samples(ts, upload, download) VALUES (?, ?, ?)",
                (now, upload_delta, download_delta),
            )
            self._state_set("collector_upload_total", upload_total)
            self._state_set("collector_download_total", download_total)
            self._state_set("collector_last_success", now)

            for connection in connections:
                record = self._connection_record(connection, now, resolver)
                if not record["id"]:
                    continue
                active_ids.add(record["id"])
                existing = self.db.execute(
                    "SELECT start_time, upload, download FROM connections WHERE id = ?", (record["id"],)
                ).fetchone()
                if existing:
                    record["start_time"] = existing["start_time"]
                    upload_delta = record["upload"] - existing["upload"] if record["upload"] >= existing["upload"] else record["upload"]
                    download_delta = record["download"] - existing["download"] if record["download"] >= existing["download"] else record["download"]
                elif initial_snapshot:
                    upload_delta = download_delta = 0
                else:
                    upload_delta = record["upload"]
                    download_delta = record["download"]
                placeholders = ",".join("?" for _ in self.CONNECTION_COLUMNS)
                values = [record[column] for column in self.CONNECTION_COLUMNS]
                self.db.execute(
                    "INSERT OR REPLACE INTO connections ({}) VALUES ({})".format(
                        ",".join(self.CONNECTION_COLUMNS), placeholders
                    ),
                    values,
                )
                if upload_delta or download_delta:
                    usage_key = (record["source_ip"], record["config_name"], record["user"])
                    old_usage = usage_deltas.get(usage_key, (0, 0))
                    usage_deltas[usage_key] = (old_usage[0] + upload_delta, old_usage[1] + download_delta)
                    if record["destination"]:
                        old_destination = destination_deltas.get(record["destination"], (0, 0))
                        destination_deltas[record["destination"]] = (
                            old_destination[0] + upload_delta, old_destination[1] + download_delta,
                        )

            sample_ts = (now // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
            for (source_ip, config_name, user), (sample_upload, sample_download) in usage_deltas.items():
                sample = self.db.execute(
                    "SELECT upload, download FROM usage_samples "
                    "WHERE ts = ? AND source_ip = ? AND config_name = ? AND user = ?",
                    (sample_ts, source_ip, config_name, user),
                ).fetchone()
                if sample:
                    sample_upload += sample["upload"]
                    sample_download += sample["download"]
                self.db.execute(
                    "INSERT OR REPLACE INTO usage_samples "
                    "(ts, source_ip, config_name, user, upload, download) VALUES (?, ?, ?, ?, ?, ?)",
                    (sample_ts, source_ip, config_name, user, sample_upload, sample_download),
                )
            for destination, (sample_upload, sample_download) in destination_deltas.items():
                sample = self.db.execute(
                    "SELECT upload, download FROM destination_samples WHERE ts = ? AND destination = ?",
                    (sample_ts, destination),
                ).fetchone()
                if sample:
                    sample_upload += sample["upload"]
                    sample_download += sample["download"]
                self.db.execute(
                    "INSERT OR REPLACE INTO destination_samples "
                    "(ts, destination, upload, download) VALUES (?, ?, ?, ?)",
                    (sample_ts, destination, sample_upload, sample_download),
                )

            current_rows = self.db.execute("SELECT id FROM connections WHERE status = 'active'").fetchall()
            for row in current_rows:
                if row["id"] not in active_ids:
                    self.db.execute(
                        "UPDATE connections SET status = 'closed', end_time = ? WHERE id = ?",
                        (now, row["id"]),
                    )

            last_cleanup = as_int(self._state_get("last_cleanup"))
            if now - last_cleanup >= 3600:
                self._purge_locked(self.retention_days)
                self._state_set("last_cleanup", now)

    def _purge_locked(self, days):
        cutoff = int(time.time()) - clamp(as_int(days, self.retention_days), 1, 3650) * 86400
        samples = self.db.execute("DELETE FROM traffic_samples WHERE ts < ?", (cutoff,)).rowcount
        connections = self.db.execute(
            "DELETE FROM connections WHERE status != 'active' AND last_seen < ?", (cutoff,)
        ).rowcount
        usage_samples = self.db.execute("DELETE FROM usage_samples WHERE ts < ?", (cutoff,)).rowcount
        destination_samples = self.db.execute("DELETE FROM destination_samples WHERE ts < ?", (cutoff,)).rowcount
        return {
            "samples": samples, "usage_samples": usage_samples, "destination_samples": destination_samples,
            "connections": connections, "cutoff": cutoff,
        }

    def purge(self, days):
        with self.lock, self.db:
            return self._purge_locked(days)

    @staticmethod
    def since_for_range(range_name):
        if range_name == "all":
            return 0
        return int(time.time()) - RANGES.get(range_name, RANGES["24h"])

    @staticmethod
    def time_window(range_name, start=None, end=None):
        now = int(time.time())
        if start or end:
            if not start or not end:
                raise ValueError("自定义时间段必须同时提供 start 和 end")
            since = parse_timestamp(start, None)
            until = parse_timestamp(end, None)
            if since is None or until is None:
                raise ValueError("start 或 end 时间格式无效")
            if since > until:
                raise ValueError("start 不能晚于 end")
            try:
                datetime.datetime.fromtimestamp(since, datetime.timezone.utc)
                datetime.datetime.fromtimestamp(until, datetime.timezone.utc)
            except (OSError, OverflowError, ValueError):
                raise ValueError("start 或 end 超出支持的时间范围")
            return since, until
        return AuditStore.since_for_range(range_name), now

    @staticmethod
    def _params_window(params):
        return AuditStore.time_window(
            params.get("range", ["24h"])[0],
            params.get("start", [None])[0],
            params.get("end", [None])[0],
        )

    def summary(self, range_name, start=None, end=None):
        now = time.time()
        since, until = self.time_window(range_name, start, end)
        with self.lock:
            totals = self.db.execute(
                "SELECT COALESCE(SUM(upload), 0) AS upload, COALESCE(SUM(download), 0) AS download "
                "FROM traffic_samples WHERE ts BETWEEN ? AND ?",
                (since, until),
            ).fetchone()
            sample_time = float(self._state_get("collector_sample_time") or 0)
            sample_seconds = float(self._state_get("collector_sample_seconds") or 0)
            fresh = 0 <= now - sample_time <= max(10, min(sample_seconds, 60) * 3 + 2)
            upload_speed = as_int(self._state_get("collector_upload_speed")) if fresh else 0
            download_speed = as_int(self._state_get("collector_download_speed")) if fresh else 0
            counts = self.db.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active, "
                "COUNT(DISTINCT NULLIF(source_ip, '')) AS clients, "
                "COUNT(DISTINCT NULLIF(CASE WHEN host != '' THEN host ELSE destination END, '')) AS destinations "
                "FROM connections WHERE start_time <= ? AND last_seen >= ?",
                (until, since),
            ).fetchone()
        return {
            "range": range_name,
            "start": utc_iso(since),
            "end": utc_iso(until),
            "upload": totals["upload"],
            "download": totals["download"],
            "total": totals["upload"] + totals["download"],
            "upload_speed": upload_speed,
            "download_speed": download_speed,
            "connections": counts["total"] or 0,
            "active_connections": counts["active"] or 0,
            "unique_clients": counts["clients"] or 0,
            "unique_destinations": counts["destinations"] or 0,
        }

    def timeseries(self, range_name, bucket=None, start=None, end=None):
        since, until = self.time_window(range_name, start, end)
        default_buckets = {"1h": 60, "6h": 300, "24h": 900, "7d": 3600, "30d": 21600, "all": 86400}
        if start or end:
            duration = max(1, until - since)
            default_bucket = max(10, duration // 96)
        else:
            default_bucket = default_buckets.get(range_name, 900)
        bucket = clamp(as_int(bucket, default_bucket), 10, 604800)
        with self.lock:
            rows = self.db.execute(
                "SELECT (ts / ?) * ? AS bucket, SUM(upload) AS upload, SUM(download) AS download "
                "FROM traffic_samples WHERE ts BETWEEN ? AND ? GROUP BY bucket ORDER BY bucket",
                (bucket, bucket, since, until),
            ).fetchall()
        return {
            "bucket_seconds": bucket,
            "points": [
                {"ts": row["bucket"], "time": utc_iso(row["bucket"]), "upload": row["upload"], "download": row["download"]}
                for row in rows
            ],
        }

    def activity(self, range_name, timezone_offset=0, start=None, end=None):
        """Aggregate traffic by local weekday and hour for a compact heatmap."""
        since, until = self.time_window(range_name, start, end)
        # JavaScript getTimezoneOffset is UTC minus local time, so invert it
        # before shifting Unix timestamps for SQLite's UTC-based strftime.
        shift_seconds = -clamp(as_int(timezone_offset, 0), -840, 840) * 60
        with self.lock:
            rows = self.db.execute(
                "SELECT CAST(strftime('%w', ts + ?, 'unixepoch') AS INTEGER) AS weekday, "
                "CAST(strftime('%H', ts + ?, 'unixepoch') AS INTEGER) AS hour, "
                "SUM(upload) AS upload, SUM(download) AS download "
                "FROM traffic_samples WHERE ts BETWEEN ? AND ? GROUP BY weekday, hour ORDER BY weekday, hour",
                (shift_seconds, shift_seconds, since, until),
            ).fetchall()
        return {
            "timezone_offset": -shift_seconds // 60,
            "cells": [
                {
                    "weekday": row["weekday"], "hour": row["hour"],
                    "upload": row["upload"], "download": row["download"],
                    "total": row["upload"] + row["download"],
                }
                for row in rows
            ],
        }

    def top_destinations(self, range_name, limit=8, start=None, end=None):
        since, until = self.time_window(range_name, start, end)
        since = (since // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
        until = (until // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
        limit = clamp(as_int(limit, 8), 1, 50)
        with self.lock:
            rows = self.db.execute(
                "SELECT destination AS name, SUM(upload) AS upload, SUM(download) AS download, 0 AS connections "
                "FROM destination_samples WHERE ts BETWEEN ? AND ? GROUP BY destination HAVING destination != '' "
                "ORDER BY (SUM(upload) + SUM(download)) DESC LIMIT ?",
                (since, until, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def traffic_flow(self, range_name, limit=12, start=None, end=None):
        """Aggregate the busiest connection paths that overlap a time window."""
        since, until = self.time_window(range_name, start, end)
        limit = clamp(as_int(limit, 12), 1, 30)
        with self.lock:
            rows = self.db.execute(
                "SELECT "
                "COALESCE(NULLIF(source_ip, ''), '未知来源') AS source, "
                "COALESCE(NULLIF(config_name, ''), NULLIF(inbound, ''), '未识别') AS config, "
                "COALESCE(NULLIF(outbound, ''), '其他路由') AS route, "
                "COALESCE(NULLIF(host, ''), NULLIF(destination, ''), NULLIF(destination_ip, ''), '未知目标') AS target, "
                "SUM(upload) AS upload, SUM(download) AS download, "
                "SUM(upload) + SUM(download) AS total "
                "FROM connections WHERE start_time <= ? AND last_seen >= ? AND (upload + download) > 0 "
                "GROUP BY source, config, route, target ORDER BY total DESC LIMIT ?",
                (until, since, limit),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "scope": "connections_overlapping_window",
        }

    def options(self, range_name, start=None, end=None):
        since, until = self.time_window(range_name, start, end)
        with self.lock:
            protocols = [row[0] for row in self.db.execute(
                "SELECT DISTINCT protocol FROM connections WHERE start_time <= ? AND last_seen >= ? "
                "AND protocol != '' ORDER BY protocol", (until, since)
            ).fetchall()]
            users = [row[0] for row in self.db.execute(
                "SELECT DISTINCT user FROM connections WHERE start_time <= ? AND last_seen >= ? "
                "AND user != '' ORDER BY user", (until, since)
            ).fetchall()]
            configs = [row[0] for row in self.db.execute(
                "SELECT DISTINCT config_name FROM connections WHERE start_time <= ? AND last_seen >= ? "
                "AND config_name != '' ORDER BY config_name", (until, since)
            ).fetchall()]
        return {"protocols": protocols, "users": users, "configs": configs}

    @staticmethod
    def _connection_where(params):
        since, until = AuditStore._params_window(params)
        clauses = ["start_time <= ?", "last_seen >= ?"]
        values = [until, since]
        for key, column in (("status", "status"), ("protocol", "protocol"), ("user", "user"), ("config", "config_name")):
            value = params.get(key, [""])[0].strip()
            if value:
                clauses.append(column + " = ?")
                values.append(value)
        search = params.get("search", [""])[0].strip()
        if search:
            pattern = "%{}%".format(search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
            clauses.append(
                "(source_ip LIKE ? ESCAPE '\\' OR destination LIKE ? ESCAPE '\\' OR destination_ip LIKE ? ESCAPE '\\' "
                "OR host LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' OR inbound LIKE ? ESCAPE '\\' "
                "OR config_name LIKE ? ESCAPE '\\' OR process LIKE ? ESCAPE '\\')"
            )
            values.extend([pattern] * 8)
        return " AND ".join(clauses), values

    @staticmethod
    def _usage_where(params):
        since, until = AuditStore._params_window(params)
        since = (since // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
        until = (until // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
        clauses = ["ts BETWEEN ? AND ?"]
        values = [since, until]
        for key, column in (("source_ip", "source_ip"), ("config", "config_name"), ("user", "user")):
            value = params.get(key, [""])[0].strip()
            if value:
                clauses.append(column + " = ?")
                values.append(value)
        config_search = params.get("config_search", [""])[0].strip()
        if config_search:
            pattern = "%{}%".format(config_search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
            clauses.append("config_name LIKE ? ESCAPE '\\'")
            values.append(pattern)
        search = params.get("search", [""])[0].strip()
        if search:
            pattern = "%{}%".format(search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
            clauses.append(
                "(source_ip LIKE ? ESCAPE '\\' OR config_name LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\')"
            )
            values.extend([pattern] * 3)
        return " AND ".join(clauses), values

    @staticmethod
    def _usage_select():
        return (
            "SELECT source_ip, config_name, user, MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
            "SUM(upload) AS upload, SUM(download) AS download, "
            "SUM(upload) + SUM(download) AS total FROM usage_samples WHERE "
        )

    @staticmethod
    def _identity_connection_counts(params):
        since, until = AuditStore._params_window(params)
        since = (since // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
        until = (until // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS + USAGE_BUCKET_SECONDS - 1
        clauses = ["start_time <= ?", "last_seen >= ?"]
        values = [until, since]
        for key, column in (("source_ip", "source_ip"), ("config", "config_name"), ("user", "user")):
            value = params.get(key, [""])[0].strip()
            if value:
                clauses.append(column + " = ?")
                values.append(value)
        config_search = params.get("config_search", [""])[0].strip()
        if config_search:
            pattern = "%{}%".format(config_search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
            clauses.append("config_name LIKE ? ESCAPE '\\'")
            values.append(pattern)
        search = params.get("search", [""])[0].strip()
        if search:
            pattern = "%{}%".format(search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
            clauses.append(
                "(source_ip LIKE ? ESCAPE '\\' OR config_name LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\')"
            )
            values.extend([pattern] * 3)
        return (
            "SELECT source_ip, config_name, user, COUNT(*) AS connections FROM connections WHERE "
            + " AND ".join(clauses) + " GROUP BY source_ip, config_name, user",
            values,
        )

    def _connection_count_map(self, params):
        query, values = self._identity_connection_counts(params)
        rows = self.db.execute(query, values).fetchall()
        return {(row["source_ip"], row["config_name"], row["user"]): row["connections"] for row in rows}

    def client_usage(self, params):
        where, values = self._usage_where(params)
        group = " GROUP BY source_ip, config_name, user"
        page = max(1, as_int(params.get("page", [1])[0], 1))
        limit = clamp(as_int(params.get("limit", [50])[0], 50), 1, 200)
        offset = (page - 1) * limit
        with self.lock:
            connection_counts = self._connection_count_map(params)
            total = self.db.execute(
                "SELECT COUNT(*) FROM (SELECT 1 FROM usage_samples WHERE " + where + group + ")", values
            ).fetchone()[0]
            rows = self.db.execute(
                self._usage_select() + where + group + " ORDER BY total DESC, source_ip LIMIT ? OFFSET ?",
                values + [limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["connections"] = connection_counts.get((item["source_ip"], item["config_name"], item["user"]), 0)
            item["first_seen_at"] = utc_iso(item["first_seen"])
            item["last_seen_at"] = utc_iso(item["last_seen"])
            items.append(item)
        return {
            "items": items, "page": page, "limit": limit, "total": total,
            "pages": max(1, (total + limit - 1) // limit), "bucket_seconds": USAGE_BUCKET_SECONDS,
        }

    def _config_connection_count_map(self, params):
        query, values = self._identity_connection_counts(params)
        rows = self.db.execute(query, values).fetchall()
        counts = {}
        for row in rows:
            config_name = row["config_name"]
            counts[config_name] = counts.get(config_name, 0) + row["connections"]
        return counts

    @staticmethod
    def _config_usage_select():
        return (
            "SELECT config_name, MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
            "COUNT(DISTINCT NULLIF(source_ip, '')) AS clients, "
            "COUNT(DISTINCT NULLIF(user, '')) AS users, "
            "SUM(upload) AS upload, SUM(download) AS download, "
            "SUM(upload) + SUM(download) AS total FROM usage_samples WHERE "
        )

    def config_usage(self, params):
        where, values = self._usage_where(params)
        group = " GROUP BY config_name"
        page = max(1, as_int(params.get("page", [1])[0], 1))
        limit = clamp(as_int(params.get("limit", [50])[0], 50), 1, 200)
        offset = (page - 1) * limit
        with self.lock:
            connection_counts = self._config_connection_count_map(params)
            total = self.db.execute(
                "SELECT COUNT(*) FROM (SELECT 1 FROM usage_samples WHERE " + where + group + ")", values
            ).fetchone()[0]
            rows = self.db.execute(
                self._config_usage_select() + where + group + " ORDER BY total DESC, config_name LIMIT ? OFFSET ?",
                values + [limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["connections"] = connection_counts.get(item["config_name"], 0)
            item["first_seen_at"] = utc_iso(item["first_seen"])
            item["last_seen_at"] = utc_iso(item["last_seen"])
            items.append(item)
        return {
            "items": items, "page": page, "limit": limit, "total": total,
            "pages": max(1, (total + limit - 1) // limit), "bucket_seconds": USAGE_BUCKET_SECONDS,
        }

    def connections(self, params):
        where, values = self._connection_where(params)
        page = max(1, as_int(params.get("page", [1])[0], 1))
        limit = clamp(as_int(params.get("limit", [50])[0], 50), 1, 200)
        offset = (page - 1) * limit
        with self.lock:
            total = self.db.execute("SELECT COUNT(*) FROM connections WHERE " + where, values).fetchone()[0]
            rows = self.db.execute(
                "SELECT * FROM connections WHERE " + where + " ORDER BY status = 'active' DESC, last_seen DESC LIMIT ? OFFSET ?",
                values + [limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["start"] = utc_iso(item.pop("start_time"))
            item["end"] = utc_iso(item.pop("end_time"))
            item["last_seen_at"] = utc_iso(item["last_seen"])
            try:
                item["chains"] = json.loads(item["chains"])
            except (TypeError, ValueError):
                item["chains"] = []
            items.append(item)
        return {"items": items, "page": page, "limit": limit, "total": total, "pages": max(1, (total + limit - 1) // limit)}

    def write_export(self, params, export_format, output):
        where, values = self._connection_where(params)
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM connections WHERE " + where + " ORDER BY start_time DESC", values
            )
            if export_format == "csv":
                output.write(b"\xef\xbb\xbf")
                text_output = io.TextIOWrapper(output, encoding="utf-8", newline="", write_through=True)
                writer = csv.DictWriter(text_output, fieldnames=list(self.CONNECTION_COLUMNS), extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))
                text_output.flush()
                text_output.detach()
            else:
                output.write(b"[\n")
                first = True
                for row in rows:
                    if not first:
                        output.write(b",\n")
                    output.write(json.dumps(dict(row), ensure_ascii=False).encode("utf-8"))
                    first = False
                output.write(b"\n]\n")
            return output.tell()

    def write_usage_export(self, params, export_format, output):
        where, values = self._usage_where(params)
        query = self._usage_select() + where + " GROUP BY source_ip, config_name, user ORDER BY total DESC, source_ip"
        with self.lock:
            connection_counts = self._connection_count_map(params)
            rows = self.db.execute(query, values)
            if export_format == "csv":
                output.write(b"\xef\xbb\xbf")
                text_output = io.TextIOWrapper(output, encoding="utf-8", newline="", write_through=True)
                writer = csv.DictWriter(text_output, fieldnames=list(self.USAGE_EXPORT_COLUMNS), extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    item = dict(row)
                    item["connections"] = connection_counts.get((item["source_ip"], item["config_name"], item["user"]), 0)
                    writer.writerow(item)
                text_output.flush()
                text_output.detach()
            else:
                output.write(b"[\n")
                first = True
                for row in rows:
                    if not first:
                        output.write(b",\n")
                    item = dict(row)
                    item["connections"] = connection_counts.get((item["source_ip"], item["config_name"], item["user"]), 0)
                    output.write(json.dumps(item, ensure_ascii=False).encode("utf-8"))
                    first = False
                output.write(b"\n]\n")
            return output.tell()

    def write_config_usage_export(self, params, export_format, output):
        where, values = self._usage_where(params)
        query = self._config_usage_select() + where + " GROUP BY config_name ORDER BY total DESC, config_name"
        with self.lock:
            connection_counts = self._config_connection_count_map(params)
            rows = self.db.execute(query, values)
            if export_format == "csv":
                output.write(b"\xef\xbb\xbf")
                text_output = io.TextIOWrapper(output, encoding="utf-8", newline="", write_through=True)
                writer = csv.DictWriter(
                    text_output, fieldnames=list(self.CONFIG_USAGE_EXPORT_COLUMNS), extrasaction="ignore"
                )
                writer.writeheader()
                for row in rows:
                    item = dict(row)
                    item["connections"] = connection_counts.get(item["config_name"], 0)
                    writer.writerow(item)
                text_output.flush()
                text_output.detach()
            else:
                output.write(b"[\n")
                first = True
                for row in rows:
                    if not first:
                        output.write(b",\n")
                    item = dict(row)
                    item["connections"] = connection_counts.get(item["config_name"], 0)
                    output.write(json.dumps(item, ensure_ascii=False).encode("utf-8"))
                    first = False
                output.write(b"\n]\n")
            return output.tell()


class Collector:
    def __init__(self, store, url, secret, interval, resolver=None):
        self.store = store
        self.url = url.rstrip("/") + "/connections"
        self.secret = secret
        self.interval = clamp(as_int(interval, 1), 1, 60)
        self.resolver = resolver
        self.opener = build_opener(ProxyHandler({}))
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = threading.Lock()
        self.last_success = 0
        self.last_error = "等待首次采集"

    def start(self):
        self.thread = threading.Thread(target=self._run, name="audit-collector", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=self.interval + 3)

    def status(self):
        with self.lock:
            running = bool(self.thread and self.thread.is_alive() and not self.stop_event.is_set())
            return {
                "running": running,
                "connected": bool(running and not self.last_error and self.last_success and time.time() - self.last_success <= self.interval * 3 + 2),
                "last_success": utc_iso(self.last_success),
                "last_error": self.last_error,
                "source": self.url,
                "interval": self.interval,
            }

    def _poll(self):
        headers = {"Accept": "application/json", "User-Agent": "sing-box-audit/" + SERVICE_VERSION}
        if self.secret:
            headers["Authorization"] = "Bearer " + self.secret
        request = Request(self.url, headers=headers)
        with self.opener.open(request, timeout=max(3, self.interval)) as response:
            if response.status != 200:
                raise RuntimeError("sing-box API 返回 HTTP {}".format(response.status))
            snapshot = json.loads(response.read().decode("utf-8"))
        if not isinstance(snapshot, dict) or "connections" not in snapshot:
            raise RuntimeError("sing-box API 返回了无效数据")
        self.store.capture(snapshot, self.resolver)
        with self.lock:
            self.last_success = int(time.time())
            self.last_error = ""

    def _run(self):
        failures = 0
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self._poll()
                failures = 0
            except (HTTPError, URLError, OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                failures += 1
                with self.lock:
                    self.last_error = str(error)
            retry_interval = min(60, max(self.interval, 2 ** min(failures, 6))) if failures else self.interval
            wait_for = max(0.2, retry_interval - (time.monotonic() - started))
            self.stop_event.wait(wait_for)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "sing-box-audit/" + SERVICE_VERSION

    def log_message(self, message, *args):
        # The dashboard refreshes frequently; successful access logs would only
        # flood journald/OpenRC logs. Exceptions are still reported by the server.
        return

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        super().end_headers()

    def _json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        expected = self.server.web_token
        if not expected:
            return True
        supplied = self.headers.get("Authorization", "")
        if supplied.startswith("Bearer "):
            supplied = supplied[7:]
        else:
            supplied = ""
        return hmac.compare_digest(supplied, expected)

    def _require_auth(self):
        if self._authorized():
            return True
        self._json({"error": "unauthorized", "message": "访问令牌无效"}, HTTPStatus.UNAUTHORIZED)
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            collector = self.server.collector.status()
            self._json({
                "ok": True, "service": "sing-box-audit", "version": SERVICE_VERSION,
                "auth_required": bool(self.server.web_token),
                "collector_running": collector["running"], "collector_connected": collector["connected"],
            })
            return
        if parsed.path.startswith("/api/"):
            if not self._require_auth():
                return
            self._handle_api(parsed)
            return
        if parsed.path not in ("/", "/index.html", "/app.js", "/styles.css"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._serve_static("/index.html" if parsed.path == "/" else parsed.path)

    def _serve_static(self, path):
        files = {
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }
        filename, content_type = files[path]
        try:
            with open(os.path.join(self.server.web_root, filename), "rb") as handle:
                body = handle.read()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/auth":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        length = clamp(as_int(self.headers.get("Content-Length")), 0, 4096)
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except ValueError:
            self._json({"ok": False, "message": "请求格式无效"}, HTTPStatus.BAD_REQUEST)
            return
        supplied = str(payload.get("token") or "")
        if self.server.web_token and not hmac.compare_digest(supplied, self.server.web_token):
            self._json({"ok": False, "message": "访问令牌无效"}, HTTPStatus.UNAUTHORIZED)
            return
        self._json({"ok": True})

    def _handle_api(self, parsed):
        params = parse_qs(parsed.query, keep_blank_values=True)
        range_name = params.get("range", ["24h"])[0]
        if range_name not in RANGES and range_name != "all":
            range_name = "24h"
            params["range"] = [range_name]
        start = params.get("start", [None])[0]
        end = params.get("end", [None])[0]
        try:
            self.server.store.time_window(range_name, start, end)
        except ValueError as error:
            self._json({"error": "invalid_time_range", "message": str(error)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path == "/api/summary":
            payload = self.server.store.summary(range_name, start, end)
            payload["collector"] = self.server.collector.status()
            self._json(payload)
        elif parsed.path == "/api/timeseries":
            self._json(self.server.store.timeseries(range_name, params.get("bucket", [None])[0], start, end))
        elif parsed.path == "/api/activity":
            self._json(self.server.store.activity(range_name, params.get("timezone_offset", [0])[0], start, end))
        elif parsed.path == "/api/top-destinations":
            self._json({"items": self.server.store.top_destinations(range_name, params.get("limit", [8])[0], start, end)})
        elif parsed.path == "/api/traffic-flow":
            self._json(self.server.store.traffic_flow(range_name, params.get("limit", [12])[0], start, end))
        elif parsed.path == "/api/options":
            self._json(self.server.store.options(range_name, start, end))
        elif parsed.path == "/api/client-usage":
            self._json(self.server.store.client_usage(params))
        elif parsed.path == "/api/config-usage":
            self._json(self.server.store.config_usage(params))
        elif parsed.path == "/api/connections":
            self._json(self.server.store.connections(params))
        elif parsed.path == "/api/usage-export":
            self._export(params, usage=True)
        elif parsed.path == "/api/config-usage-export":
            self._export(params, config_usage=True)
        elif parsed.path == "/api/export":
            self._export(params)
        else:
            self._json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def _export(self, params, usage=False, config_usage=False):
        export_format = params.get("format", ["csv"])[0].lower()
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        name_part = "config-usage" if config_usage else ("usage" if usage else "connections")
        if export_format == "json":
            content_type = "application/json; charset=utf-8"
            filename = "sing-box-audit-{}-{}.json".format(name_part, stamp)
        elif export_format == "csv":
            content_type = "text/csv; charset=utf-8"
            filename = "sing-box-audit-{}-{}.csv".format(name_part, stamp)
        else:
            self._json({"error": "invalid_format", "message": "仅支持 csv 或 json"}, HTTPStatus.BAD_REQUEST)
            return
        with tempfile.TemporaryFile(mode="w+b") as export_file:
            if config_usage:
                size = self.server.store.write_config_usage_export(params, export_format, export_file)
            elif usage:
                size = self.server.store.write_usage_export(params, export_format, export_file)
            else:
                size = self.server.store.write_export(params, export_format, export_file)
            export_file.seek(0)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(filename))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            while True:
                chunk = export_file.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    required = ("listen", "port", "database", "collector_url")
    missing = [key for key in required if config.get(key) in (None, "")]
    if missing:
        raise ValueError("缺少配置项: " + ", ".join(missing))
    port = as_int(config["port"])
    if port < 1 or port > 65535:
        raise ValueError("port 必须在 1 到 65535 之间")
    if len(str(config.get("web_token") or "")) < 16:
        raise ValueError("web_token 至少需要 16 个字符")
    config["port"] = port
    if not config.get("config_dir"):
        config["config_dir"] = os.path.abspath(os.path.join(os.path.dirname(path), "..", "conf"))
    return config


def build_server(config):
    web_root = config.get("web_root") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    if not os.path.isfile(os.path.join(web_root, "index.html")):
        raise ValueError("找不到前端资源: " + web_root)
    store = AuditStore(config["database"], config.get("retention_days", 90))
    resolver = ConfigIdentityResolver(config.get("config_dir", ""))
    collector = Collector(
        store, config["collector_url"], config.get("collector_secret", ""),
        config.get("poll_interval", 1), resolver,
    )
    server = ThreadingHTTPServer((config["listen"], config["port"]), AuditHandler)
    server.store = store
    server.collector = collector
    server.web_root = web_root
    server.web_token = str(config.get("web_token") or "")
    return server


def main():
    os.umask(0o027)
    parser = argparse.ArgumentParser(description="sing-box 流量审计服务")
    parser.add_argument("--config", required=True, help="配置文件路径")
    parser.add_argument("--check", action="store_true", help="验证配置后退出")
    parser.add_argument("--purge", type=int, metavar="DAYS", help="删除 DAYS 天以前的审计数据")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        if args.check:
            web_root = config.get("web_root") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
            if not os.path.isfile(os.path.join(web_root, "index.html")):
                raise ValueError("找不到前端资源: " + web_root)
            store = AuditStore(config["database"], config.get("retention_days", 90))
            store.close()
            print("配置有效")
            return 0
        if args.purge is not None:
            store = AuditStore(config["database"], config.get("retention_days", 90))
            result = store.purge(args.purge)
            store.close()
            print(json.dumps(result, ensure_ascii=False))
            return 0
        server = build_server(config)
    except (OSError, ValueError, sqlite3.Error) as error:
        sys.stderr.write("启动失败: {}\n".format(error))
        return 1

    stop_requested = threading.Event()

    def stop_handler(_signum, _frame):
        if not stop_requested.is_set():
            stop_requested.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    server.collector.start()
    print("sing-box audit listening on http://{}:{}".format(config["listen"], config["port"]), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.collector.stop()
        server.server_close()
        server.store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
