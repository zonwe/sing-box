#!/usr/bin/env python3
"""sing-box traffic audit service.

The service polls the local sing-box Clash-compatible API, persists traffic
samples and connection metadata in SQLite, and exposes a small read-only web
dashboard/API.  It intentionally uses only the Python standard library.
"""

import argparse
import contextlib
import csv
import datetime
import glob
import hmac
import io
import json
import os
import re
import signal
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import ProxyHandler, Request, build_opener


SERVICE_VERSION = "1.3.4"
USAGE_BUCKET_SECONDS = 60
# destination_samples only ever feeds the "top destinations" ranking, which
# aggregates the whole window and never shows a timestamp, so it does not need
# per-minute resolution.  A five minute bucket cuts the stored rows - and with
# them the range scan the dashboard runs on every refresh - by five.  Client and
# config usage keep the one minute bucket because those views do show first_seen
# and last_seen and support custom windows.
DESTINATION_BUCKET_SECONDS = 300
# flow_samples backs the traffic path chart and follows the same reasoning: the
# chart picks the busiest paths of a whole window, so five minute buckets hold
# every number it shows while keeping the table - and the scan behind each
# dashboard refresh - far smaller than the connection rows it replaces.
FLOW_BUCKET_SECONDS = 300
RANGES = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
}
# The dashboard reloads every few seconds, so a single slow poll must not mark
# the collector as broken for a whole minute.  Keep the HTTP timeout above the
# default interval and cap the retry backoff short enough to recover quickly.
COLLECTOR_POLL_TIMEOUT = 5
COLLECTOR_RETRY_MAX = 15
COLLECTOR_STATUS_GRACE = 15
# The dashboard issues several parallel requests per refresh, which is well
# above the standard-library accept queue of 5.
REQUEST_QUEUE_SIZE = 128
# Idle keep-alive sockets are dropped after this many seconds.
CLIENT_IDLE_TIMEOUT = 30
# Requests that take at least this long are named in the service log.  The
# dashboard refreshes several endpoints in parallel, so a wide range or a very
# large window otherwise shows up only as unexplained CPU time.
SLOW_REQUEST_SECONDS = 1.0
# The dashboard aggregates scan a time window that is far larger than SQLite's
# default 2 MB page cache, so every scanned row used to cost a read syscall and
# the system CPU that goes with it.  A memory map hands those pages to the OS
# page cache instead, which is reclaimable and therefore safe on a small VPS:
# in a benchmark over a month of samples a 24h summary fell from ~230 ms to
# ~40 ms of CPU and a 24h connection list from ~260 ms to ~65 ms.
SQLITE_MMAP_BYTES = 256 * 1024 * 1024
# Used only where a memory map is unavailable (32-bit builds, some container
# filesystems), so the same hot window still fits in an explicit page cache.
SQLITE_FALLBACK_CACHE_KIB = 32 * 1024
# A dashboard refresh fires several aggregate queries at once and every one of
# them needs the same store lock.  Once the database no longer fits in the page
# cache those queries take seconds, so requests pile up in front of the
# collector and the backlog never drains: the browser abandons a request after
# twelve seconds, but the server thread keeps its place in the queue, and the
# queue keeps growing until the whole service thrashes.  A read therefore takes
# one of a small number of slots and waits a bounded time for the lock; work
# that cannot start is refused with a busy error instead of queueing forever.
STORE_READ_SLOTS = 6
STORE_READ_SLOT_WAIT = 2.0
STORE_READ_LOCK_WAIT = 3.0
# Shutdown waits this long for the store lock.  A queued read must never keep
# the service from stopping, or systemd has to SIGKILL it after TimeoutStopSec
# and a restart looks stuck for a minute and a half.
STORE_CLOSE_LOCK_WAIT = 5.0


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
        self.files = {}
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
        files = {}
        if not self.config_dir or not os.path.isdir(self.config_dir):
            self.files = files
            self.entries = entries
            return
        for path in glob.glob(os.path.join(self.config_dir, "*.json")):
            # Re-parsing every config file five times a minute is wasted CPU on
            # a server with many configs, so a file is only read again when its
            # size or modification time changed.
            try:
                info = os.stat(path)
            except OSError:
                continue
            signature = (info.st_mtime_ns, info.st_size)
            cached = self.files.get(path)
            if cached and cached[0] == signature:
                file_entries = cached[1]
            else:
                file_entries = self._read_config(path)
            files[path] = (signature, file_entries)
            entries.update(file_entries)
        self.files = files
        self.entries = entries

    def _read_config(self, path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                config = json.load(handle)
        except (OSError, ValueError):
            return {}
        config_name = os.path.basename(path)
        entries = {}
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
        return entries

    def resolve(self, inbound, api_user):
        self._refresh()
        inbound = os.path.basename(str(inbound or ""))
        api_user = str(api_user or "")
        entry = self.entries.get(inbound)
        if not entry:
            return inbound, api_user
        user = entry["named_users"].get(api_user, api_user) if api_user else entry["single_identity"]
        return entry["config_name"], user


class StoreBusy(RuntimeError):
    """Raised when the store is already loaded and will not accept more work."""


class AuditStore:
    CONNECTION_COLUMNS = (
        "id", "start_time", "end_time", "last_seen", "status", "network",
        "inbound", "inbound_type", "config_name", "source_ip", "source_port", "destination",
        "destination_ip", "destination_port", "host", "user", "protocol",
        "process", "outbound", "chains", "rule", "upload", "download",
    )
    # ``id`` is the lookup key and ``start_time`` never changes once a row
    # exists, so a repeat poll only needs to rewrite the remaining columns.
    # Updating in place also avoids the delete+reinsert that INSERT OR REPLACE
    # performs, which would touch every index twice per connection per second.
    CONNECTION_UPDATE_COLUMNS = tuple(
        column for column in CONNECTION_COLUMNS if column not in ("id", "start_time")
    )
    # Byte counters and last_seen move on every poll; the rest of the metadata
    # (host, user, outbound, chains, ...) is fixed for the lifetime of a
    # connection.  Rewriting all 21 columns made SQLite redo six indexes per
    # connection per second, so a poll now writes the hot columns alone and
    # falls back to the full statement only when the metadata really changed.
    # The two tuples must keep partitioning CONNECTION_UPDATE_COLUMNS, which
    # test_audit checks.  (Like CONNECTION_UPDATE_COLUMNS above, the names are
    # inlined because a comprehension cannot read class attributes.)
    CONNECTION_HOT_COLUMNS = ("last_seen", "upload", "download")
    CONNECTION_META_COLUMNS = tuple(
        column for column in CONNECTION_UPDATE_COLUMNS
        if column not in ("last_seen", "upload", "download")
    )
    CONNECTION_HOT_UPDATE_SQL = "UPDATE connections SET {} WHERE id = ?".format(
        ",".join([column + " = ?" for column in CONNECTION_HOT_COLUMNS])
    )
    # Built once at import time instead of being re-joined for every row of
    # every poll.
    CONNECTION_INSERT_SQL = "INSERT INTO connections ({}) VALUES ({})".format(
        ",".join(CONNECTION_COLUMNS), ",".join(["?"] * len(CONNECTION_COLUMNS))
    )
    CONNECTION_UPDATE_SQL = "UPDATE connections SET {} WHERE id = ?".format(
        ",".join([column + " = ?" for column in CONNECTION_UPDATE_COLUMNS])
    )
    # usage_samples and destination_samples are minute buckets, so a poll that
    # lands in an existing bucket must add to it rather than replace it.
    # UPSERT does that in one statement; the add-then-fill pair below is the
    # fallback for SQLite builds older than 3.24 (see supports_upsert).
    USAGE_UPSERT_SQL = (
        "INSERT INTO usage_samples (ts, source_ip, config_name, user, upload, download) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ts, source_ip, config_name, user) DO UPDATE SET "
        "upload = upload + excluded.upload, download = download + excluded.download"
    )
    DESTINATION_UPSERT_SQL = (
        "INSERT INTO destination_samples (ts, destination, upload, download) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(ts, destination) DO UPDATE SET "
        "upload = upload + excluded.upload, download = download + excluded.download"
    )
    USAGE_ADD_SQL = (
        "UPDATE usage_samples SET upload = upload + ?, download = download + ? "
        "WHERE ts = ? AND source_ip = ? AND config_name = ? AND user = ?"
    )
    USAGE_INSERT_SQL = (
        "INSERT OR IGNORE INTO usage_samples (ts, source_ip, config_name, user, upload, download) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    DESTINATION_ADD_SQL = (
        "UPDATE destination_samples SET upload = upload + ?, download = download + ? "
        "WHERE ts = ? AND destination = ?"
    )
    DESTINATION_INSERT_SQL = (
        "INSERT OR IGNORE INTO destination_samples (ts, destination, upload, download) "
        "VALUES (?, ?, ?, ?)"
    )
    FLOW_UPSERT_SQL = (
        "INSERT INTO flow_samples (ts, source_ip, config_name, route, target, upload, download) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ts, source_ip, config_name, route, target) DO UPDATE SET "
        "upload = upload + excluded.upload, download = download + excluded.download"
    )
    FLOW_ADD_SQL = (
        "UPDATE flow_samples SET upload = upload + ?, download = download + ? "
        "WHERE ts = ? AND source_ip = ? AND config_name = ? AND route = ? AND target = ?"
    )
    FLOW_INSERT_SQL = (
        "INSERT OR IGNORE INTO flow_samples (ts, source_ip, config_name, route, target, upload, download) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    CLOSE_CONNECTION_SQL = "UPDATE connections SET status = 'closed', end_time = ? WHERE id = ?"
    STATE_WRITE_SQL = "INSERT OR REPLACE INTO state(key, value) VALUES (?, ?)"
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
        # Readers take a slot before they queue for the lock; see _read().
        self.read_slots = threading.BoundedSemaphore(STORE_READ_SLOTS)
        # UPSERT syntax arrived in SQLite 3.24 (2018).  Distributions that still
        # ship an older SQLite - CentOS 7, Debian 9, Ubuntu 18.04 - fall back to
        # an add-then-fill pair that writes the same rows.
        self.supports_upsert = sqlite3.sqlite_version_info >= (3, 24, 0)
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self._open_read_cache()
        # Per-thread read-only connections; see _reader().
        self.local = threading.local()
        # Last metadata written for each live connection; see capture().
        self.connection_meta = {}
        self._migrate()
        try:
            os.chmod(database, 0o640)
        except OSError:
            pass

    def _open_read_cache(self, connection=None):
        connection = connection or self.db
        try:
            row = connection.execute("PRAGMA mmap_size={}".format(SQLITE_MMAP_BYTES)).fetchone()
            mapped = row[0] if row else 0
        except sqlite3.Error:
            mapped = 0
        if not mapped:
            connection.execute("PRAGMA cache_size=-{}".format(SQLITE_FALLBACK_CACHE_KIB))

    def _reader(self):
        """Return this thread's read-only connection, opening it on first use.

        WAL mode lets many readers run beside the single writer, so dashboard
        queries no longer queue behind each other and the collector never waits
        for one of them.  Each request thread owns its connection and closes it
        through release_reader() when the request is done.
        """
        connection = getattr(self.local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.database)
            connection.row_factory = sqlite3.Row
            # query_only is a safety net: reads must never write through here.
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            self._open_read_cache(connection)
            self.local.connection = connection
        return connection

    def release_reader(self):
        connection = getattr(self.local, "connection", None)
        if connection is None:
            return
        self.local.connection = None
        try:
            connection.close()
        except sqlite3.Error:
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
                CREATE TABLE IF NOT EXISTS flow_samples (
                    ts INTEGER NOT NULL,
                    source_ip TEXT NOT NULL DEFAULT '',
                    config_name TEXT NOT NULL DEFAULT '',
                    route TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (ts, source_ip, config_name, route, target)
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
        # Never wait for a queued read to finish: the service has to stop
        # promptly even when the dashboard left work behind, otherwise systemd
        # escalates to SIGKILL after TimeoutStopSec.  Skipping the close is
        # safe - SQLite recovers from an open database through the WAL.
        self.release_reader()
        if not self.lock.acquire(timeout=STORE_CLOSE_LOCK_WAIT):
            sys.stderr.write("关闭数据库超时, 跳过 (下次启动由 WAL 恢复)\n")
            return
        try:
            self.db.close()
        finally:
            self.lock.release()

    @contextlib.contextmanager
    def _read(self):
        """Admission control for a dashboard read.

        Readers use their own connection (see _reader), so they no longer wait
        for the collector's lock; the slot only keeps a burst of parallel scans
        from thrashing a slow disk.  Work that cannot get a slot is refused
        instead of queueing, so a busy dashboard cannot bury the service.
        """
        if not self.read_slots.acquire(timeout=STORE_READ_SLOT_WAIT):
            raise StoreBusy("审计服务繁忙, 请稍后重试")
        try:
            yield
        finally:
            self.read_slots.release()

    def _state_get(self, key):
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _state_set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO state(key, value) VALUES (?, ?)", (key, str(value)))

    def _state_all(self):
        # The state table holds a handful of counters; one read is cheaper than
        # the six or more individual lookups a single poll used to issue.
        return {row["key"]: row["value"] for row in self.db.execute("SELECT key, value FROM state").fetchall()}

    def _state_write(self, values):
        self.db.executemany(self.STATE_WRITE_SQL, [(key, str(value)) for key, value in values.items()])

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
        flow_deltas = {}
        connection_updates = []
        connection_hot_updates = []
        connection_inserts = []

        with self.lock, self.db:
            state = self._state_all()
            old_upload = state.get("collector_upload_total")
            old_download = state.get("collector_download_total")
            previous_sample = float(state.get("collector_sample_time") or state.get("collector_last_success") or sampled_at)
            sample_seconds = max(0.0, sampled_at - previous_sample)
            initial_snapshot = old_upload is None and old_download is None
            upload_delta = 0 if old_upload is None else (upload_total - as_int(old_upload) if upload_total >= as_int(old_upload) else upload_total)
            download_delta = 0 if old_download is None else (download_total - as_int(old_download) if download_total >= as_int(old_download) else download_total)
            upload_delta = max(0, upload_delta)
            download_delta = max(0, download_delta)
            # Persist the duration and rate together with the counter baseline.
            # A sparse poll must not be treated as a one-second traffic sample.
            self._state_write({
                "collector_upload_speed": int(upload_delta / sample_seconds) if sample_seconds else 0,
                "collector_download_speed": int(download_delta / sample_seconds) if sample_seconds else 0,
                "collector_sample_seconds": sample_seconds,
                "collector_sample_time": sampled_at,
                "collector_upload_total": upload_total,
                "collector_download_total": download_total,
                "collector_last_success": now,
            })
            row = self.db.execute("SELECT upload, download FROM traffic_samples WHERE ts = ?", (now,)).fetchone()
            if row:
                upload_delta += row["upload"]
                download_delta += row["download"]
            self.db.execute(
                "INSERT OR REPLACE INTO traffic_samples(ts, upload, download) VALUES (?, ?, ?)",
                (now, upload_delta, download_delta),
            )

            # One read covers both the diff baseline for connections that are
            # still alive and the set of connections that vanished, so the poll
            # no longer issues a lookup per connection plus a second full scan.
            active_rows = self.db.execute(
                "SELECT id, start_time, upload, download FROM connections WHERE status = 'active'"
            ).fetchall()
            known = {row["id"]: row for row in active_rows}

            for connection in connections:
                record = self._connection_record(connection, now, resolver)
                if not record["id"]:
                    continue
                active_ids.add(record["id"])
                metadata = tuple(record[column] for column in self.CONNECTION_META_COLUMNS)
                existing = known.get(record["id"])
                if existing is None:
                    # A brand new connection, or one that reappeared after being
                    # closed; only these need a per-id lookup.  A reappearing
                    # row may still be stored as closed, so forget whatever was
                    # cached for it and let the full update path below run.
                    existing = self.db.execute(
                        "SELECT start_time, upload, download FROM connections WHERE id = ?", (record["id"],)
                    ).fetchone()
                    self.connection_meta.pop(record["id"], None)
                if existing:
                    record["start_time"] = existing["start_time"]
                    connection_upload = record["upload"] - existing["upload"] if record["upload"] >= existing["upload"] else record["upload"]
                    connection_download = record["download"] - existing["download"] if record["download"] >= existing["download"] else record["download"]
                    if self.connection_meta.get(record["id"]) == metadata:
                        connection_hot_updates.append(
                            [record[column] for column in self.CONNECTION_HOT_COLUMNS] + [record["id"]]
                        )
                    else:
                        self.connection_meta[record["id"]] = metadata
                        connection_updates.append(
                            [record[column] for column in self.CONNECTION_UPDATE_COLUMNS] + [record["id"]]
                        )
                else:
                    connection_upload = 0 if initial_snapshot else record["upload"]
                    connection_download = 0 if initial_snapshot else record["download"]
                    connection_inserts.append([record[column] for column in self.CONNECTION_COLUMNS])
                    self.connection_meta[record["id"]] = metadata
                if connection_upload or connection_download:
                    usage_key = (record["source_ip"], record["config_name"], record["user"])
                    old_usage = usage_deltas.get(usage_key, (0, 0))
                    usage_deltas[usage_key] = (old_usage[0] + connection_upload, old_usage[1] + connection_download)
                    if record["destination"]:
                        old_destination = destination_deltas.get(record["destination"], (0, 0))
                        destination_deltas[record["destination"]] = (
                            old_destination[0] + connection_upload, old_destination[1] + connection_download,
                        )
                    # The path chart reads this rollup instead of grouping the
                    # connection rows of the whole window on every refresh.
                    flow_key = (
                        record["source_ip"], record["config_name"], record["outbound"],
                        record["host"] or record["destination"],
                    )
                    old_flow = flow_deltas.get(flow_key, (0, 0))
                    flow_deltas[flow_key] = (old_flow[0] + connection_upload, old_flow[1] + connection_download)

            if connection_hot_updates:
                self.db.executemany(self.CONNECTION_HOT_UPDATE_SQL, connection_hot_updates)
            if connection_updates:
                self.db.executemany(self.CONNECTION_UPDATE_SQL, connection_updates)
            if connection_inserts:
                self.db.executemany(self.CONNECTION_INSERT_SQL, connection_inserts)

            if usage_deltas:
                usage_ts = (now // USAGE_BUCKET_SECONDS) * USAGE_BUCKET_SECONDS
                usage_rows = [
                    (usage_ts, source_ip, config_name, user, sample_upload, sample_download)
                    for (source_ip, config_name, user), (sample_upload, sample_download) in usage_deltas.items()
                ]
                if self.supports_upsert:
                    self.db.executemany(self.USAGE_UPSERT_SQL, usage_rows)
                else:
                    self.db.executemany(self.USAGE_ADD_SQL, [
                        (sample_upload, sample_download, ts, source_ip, config_name, user)
                        for ts, source_ip, config_name, user, sample_upload, sample_download in usage_rows
                    ])
                    self.db.executemany(self.USAGE_INSERT_SQL, usage_rows)
            if destination_deltas:
                destination_ts = (now // DESTINATION_BUCKET_SECONDS) * DESTINATION_BUCKET_SECONDS
                destination_rows = [
                    (destination_ts, destination, sample_upload, sample_download)
                    for destination, (sample_upload, sample_download) in destination_deltas.items()
                ]
                if self.supports_upsert:
                    self.db.executemany(self.DESTINATION_UPSERT_SQL, destination_rows)
                else:
                    self.db.executemany(self.DESTINATION_ADD_SQL, [
                        (sample_upload, sample_download, ts, destination)
                        for ts, destination, sample_upload, sample_download in destination_rows
                    ])
                    self.db.executemany(self.DESTINATION_INSERT_SQL, destination_rows)
            if flow_deltas:
                flow_ts = (now // FLOW_BUCKET_SECONDS) * FLOW_BUCKET_SECONDS
                flow_rows = [
                    (flow_ts, source_ip, config_name, route, target, sample_upload, sample_download)
                    for (source_ip, config_name, route, target), (sample_upload, sample_download) in flow_deltas.items()
                ]
                if self.supports_upsert:
                    self.db.executemany(self.FLOW_UPSERT_SQL, flow_rows)
                else:
                    self.db.executemany(self.FLOW_ADD_SQL, [
                        (sample_upload, sample_download, ts, source_ip, config_name, route, target)
                        for ts, source_ip, config_name, route, target, sample_upload, sample_download in flow_rows
                    ])
                    self.db.executemany(self.FLOW_INSERT_SQL, flow_rows)

            stale = [(now, connection_id) for connection_id in known if connection_id not in active_ids]
            if stale:
                self.db.executemany(self.CLOSE_CONNECTION_SQL, stale)
                for _end_time, connection_id in stale:
                    # Rows that ended must not keep a metadata entry alive; an
                    # id that comes back is refreshed by the lookup above.
                    self.connection_meta.pop(connection_id, None)

            last_cleanup = as_int(state.get("last_cleanup"))
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
        flow_samples = self.db.execute("DELETE FROM flow_samples WHERE ts < ?", (cutoff,)).rowcount
        return {
            "samples": samples, "usage_samples": usage_samples, "destination_samples": destination_samples,
            "flow_samples": flow_samples, "connections": connections, "cutoff": cutoff,
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
        rdb = self._reader()
        now = time.time()
        since, until = self.time_window(range_name, start, end)
        with self._read():
            totals = rdb.execute(
                "SELECT COALESCE(SUM(upload), 0) AS upload, COALESCE(SUM(download), 0) AS download "
                "FROM traffic_samples WHERE ts BETWEEN ? AND ?",
                (since, until),
            ).fetchone()
            state = {
                row["key"]: row["value"]
                for row in rdb.execute(
                    "SELECT key, value FROM state WHERE key IN "
                    "('collector_sample_time', 'collector_sample_seconds', "
                    "'collector_upload_speed', 'collector_download_speed')"
                ).fetchall()
            }
            sample_time = float(state.get("collector_sample_time") or 0)
            sample_seconds = float(state.get("collector_sample_seconds") or 0)
            fresh = 0 <= now - sample_time <= max(10, min(sample_seconds, 60) * 3 + 2)
            upload_speed = as_int(state.get("collector_upload_speed")) if fresh else 0
            download_speed = as_int(state.get("collector_download_speed")) if fresh else 0
            counts = rdb.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active, "
                "COUNT(DISTINCT NULLIF(source_ip, '')) AS clients, "
                "COUNT(DISTINCT NULLIF(CASE WHEN host != '' THEN host ELSE destination END, '')) AS destinations "
                "FROM connections INDEXED BY idx_connections_last_seen "
                "WHERE start_time <= ? AND last_seen >= ?",
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
        rdb = self._reader()
        since, until = self.time_window(range_name, start, end)
        default_buckets = {"1h": 60, "6h": 300, "24h": 900, "7d": 3600, "30d": 21600, "all": 86400}
        if start or end:
            duration = max(1, until - since)
            default_bucket = max(10, duration // 96)
        else:
            default_bucket = default_buckets.get(range_name, 900)
        bucket = clamp(as_int(bucket, default_bucket), 10, 604800)
        with self._read():
            rows = rdb.execute(
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
        rdb = self._reader()
        since, until = self.time_window(range_name, start, end)
        # JavaScript getTimezoneOffset is UTC minus local time, so invert it
        # before shifting Unix timestamps into the viewer's local day.
        shift_seconds = -clamp(as_int(timezone_offset, 0), -840, 840) * 60
        with self._read():
            # Plain integer division instead of strftime: weekday and hour are
            # just quotients of the shifted timestamp, and this runs over every
            # sample in the window (a 7d range is over 600k rows).
            # 1970-01-01 was a Thursday, and %w counts Sunday as 0, so the
            # day-of-week needs a +4 rotation.
            rows = rdb.execute(
                "SELECT ((ts + ?) / 86400 + 4) % 7 AS weekday, "
                "((ts + ?) / 3600) % 24 AS hour, "
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
        rdb = self._reader()
        since, until = self.time_window(range_name, start, end)
        # Snap to the bucket destination_samples is stored in, so the boundary
        # buckets are counted whole rather than partially.
        since = (since // DESTINATION_BUCKET_SECONDS) * DESTINATION_BUCKET_SECONDS
        until = (until // DESTINATION_BUCKET_SECONDS) * DESTINATION_BUCKET_SECONDS
        limit = clamp(as_int(limit, 8), 1, 50)
        with self._read():
            rows = rdb.execute(
                "SELECT destination AS name, SUM(upload) AS upload, SUM(download) AS download, 0 AS connections "
                "FROM destination_samples WHERE ts BETWEEN ? AND ? GROUP BY destination HAVING destination != '' "
                "ORDER BY (SUM(upload) + SUM(download)) DESC LIMIT ?",
                (since, until, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def traffic_flow(self, range_name, limit=12, start=None, end=None):
        """Aggregate the busiest connection paths seen inside a time window.

        Reads the five minute rollup the collector writes, so the chart costs a
        scan of sampled paths instead of a GROUP BY over every connection row of
        the window.  Long connections therefore contribute the bytes observed in
        the window rather than their whole lifetime total.
        """
        rdb = self._reader()
        since, until = self.time_window(range_name, start, end)
        since = (since // FLOW_BUCKET_SECONDS) * FLOW_BUCKET_SECONDS
        until = (until // FLOW_BUCKET_SECONDS) * FLOW_BUCKET_SECONDS
        limit = clamp(as_int(limit, 12), 1, 30)
        with self._read():
            rows = rdb.execute(
                "SELECT "
                "COALESCE(NULLIF(source_ip, ''), '未知来源') AS source, "
                "COALESCE(NULLIF(config_name, ''), '未识别') AS config, "
                "COALESCE(NULLIF(route, ''), '其他路由') AS route, "
                "COALESCE(NULLIF(target, ''), '未知目标') AS target, "
                "SUM(upload) AS upload, SUM(download) AS download, "
                "SUM(upload) + SUM(download) AS total "
                "FROM flow_samples WHERE ts BETWEEN ? AND ? AND (upload + download) > 0 "
                "GROUP BY source, config, route, target ORDER BY total DESC LIMIT ?",
                (since, until, limit),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "scope": "paths_sampled_in_window",
        }

    def options(self, range_name, start=None, end=None):
        rdb = self._reader()
        since, until = self.time_window(range_name, start, end)
        with self._read():
            # One pass over the window instead of three separate DISTINCT scans.
            # The distinct values come from a handful of columns, so the number
            # of combinations stays far below the number of matching rows.
            rows = rdb.execute(
                "SELECT DISTINCT protocol, user, config_name FROM connections "
                "INDEXED BY idx_connections_last_seen WHERE start_time <= ? AND last_seen >= ?",
                (until, since),
            ).fetchall()
        protocols = set()
        users = set()
        configs = set()
        for row in rows:
            if row[0]:
                protocols.add(row[0])
            if row[1]:
                users.add(row[1])
            if row[2]:
                configs.add(row[2])
        return {"protocols": sorted(protocols), "users": sorted(users), "configs": sorted(configs)}

    @staticmethod
    def _connection_where(params):
        # The window is "connections that were alive at some point between since
        # and until".  Both bounds are range predicates, so SQLite can only use
        # one index; without a hint it picks start_time, which for a live window
        # (start_time <= now) matches every row and turns each query into a full
        # table scan.  last_seen is the selective side, so every caller pins
        # idx_connections_last_seen via INDEXED BY.
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
    def _connection_counts_query(params, group_columns):
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
            "SELECT " + ", ".join(group_columns) + ", COUNT(*) AS connections FROM connections "
            "INDEXED BY idx_connections_last_seen WHERE "
            + " AND ".join(clauses) + " GROUP BY " + ", ".join(group_columns),
            values,
        )

    @staticmethod
    def _identity_connection_counts(params):
        return AuditStore._connection_counts_query(params, ("source_ip", "config_name", "user"))

    def _connection_count_map(self, params):
        rdb = self._reader()
        query, values = self._identity_connection_counts(params)
        rows = rdb.execute(query, values).fetchall()
        return {(row["source_ip"], row["config_name"], row["user"]): row["connections"] for row in rows}

    def client_usage(self, params):
        rdb = self._reader()
        where, values = self._usage_where(params)
        group = " GROUP BY source_ip, config_name, user"
        page = max(1, as_int(params.get("page", [1])[0], 1))
        limit = clamp(as_int(params.get("limit", [50])[0], 50), 1, 200)
        offset = (page - 1) * limit
        with self._read():
            connection_counts = self._connection_count_map(params)
            # COUNT(*) over the grouped rows and COUNT(*) over the distinct keys
            # give the same total, but the distinct form lets SQLite count
            # through a narrower temp B-tree.
            total = rdb.execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT source_ip, config_name, user "
                "FROM usage_samples WHERE " + where + ")", values
            ).fetchone()[0]
            rows = rdb.execute(
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
        # A config total is the sum over its identities, so grouping the same
        # filtered rows by config_name alone returns the identical number while
        # SQLite sorts a much narrower key.
        rdb = self._reader()
        query, values = self._connection_counts_query(params, ("config_name",))
        return {row["config_name"]: row["connections"] for row in rdb.execute(query, values).fetchall()}

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
        rdb = self._reader()
        where, values = self._usage_where(params)
        group = " GROUP BY config_name"
        page = max(1, as_int(params.get("page", [1])[0], 1))
        limit = clamp(as_int(params.get("limit", [50])[0], 50), 1, 200)
        offset = (page - 1) * limit
        with self._read():
            connection_counts = self._config_connection_count_map(params)
            # SQLite has to group every row of the window before it can order
            # the result, so the grouped rows already are the config list: they
            # give the total for free and save the second full scan that
            # counting distinct keys needed.  Config names come from the config
            # directory, so there are few enough groups to page here.  The
            # identity list in client_usage can be much longer, so it keeps its
            # SQL-side count.
            grouped = rdb.execute(
                self._config_usage_select() + where + group + " ORDER BY total DESC, config_name", values
            ).fetchall()
        total = len(grouped)
        items = []
        for row in grouped[offset:offset + limit]:
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
        rdb = self._reader()
        where, values = self._connection_where(params)
        page = max(1, as_int(params.get("page", [1])[0], 1))
        limit = clamp(as_int(params.get("limit", [50])[0], 50), 1, 200)
        offset = (page - 1) * limit
        with self._read():
            total = rdb.execute(
                "SELECT COUNT(*) FROM connections INDEXED BY idx_connections_last_seen WHERE " + where, values
            ).fetchone()[0]
            rows = self._connection_page(where, values, params.get("status", [""])[0].strip(), limit, offset)
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

    def _connection_page(self, where, values, status, limit, offset):
        """Read one page of connections without sorting the whole time window.

        ``ORDER BY status = 'active' DESC, last_seen DESC`` is not something an
        index can serve, so the previous single statement sorted every row of
        the window before dropping all but one page - about 260 ms of CPU for a
        24h window in the benchmark.  Walking idx_connections_last_seen
        backwards once for the live rows and once for the finished ones returns
        the identical order and stops as soon as the page is full.
        """
        rdb = self._reader()
        def page_query(group):
            return (
                "SELECT * FROM connections INDEXED BY idx_connections_last_seen WHERE " + where + group
                + " ORDER BY last_seen DESC LIMIT ?"
            )

        wanted = limit + offset
        if status:
            # A status filter makes the ordering a plain last_seen sort.
            return rdb.execute(page_query(""), values + [wanted]).fetchall()[offset:]
        active = rdb.execute(page_query(" AND status = 'active'"), values + [wanted]).fetchall()
        finished = rdb.execute(page_query(" AND status != 'active'"), values + [wanted]).fetchall()
        return (active + finished)[offset:offset + limit]

    def write_export(self, params, export_format, output):
        rdb = self._reader()
        where, values = self._connection_where(params)
        with self._read():
            rows = rdb.execute(
                "SELECT * FROM connections INDEXED BY idx_connections_last_seen WHERE " + where
                + " ORDER BY start_time DESC", values
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
        rdb = self._reader()
        where, values = self._usage_where(params)
        query = self._usage_select() + where + " GROUP BY source_ip, config_name, user ORDER BY total DESC, source_ip"
        with self._read():
            connection_counts = self._connection_count_map(params)
            rows = rdb.execute(query, values)
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
        rdb = self._reader()
        where, values = self._usage_where(params)
        query = self._config_usage_select() + where + " GROUP BY config_name ORDER BY total DESC, config_name"
        with self._read():
            connection_counts = self._config_connection_count_map(params)
            rows = rdb.execute(query, values)
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
        self.failures = 0
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
            grace = max(self.interval * 3 + 2, COLLECTOR_STATUS_GRACE)
            return {
                "running": running,
                "connected": bool(running and not self.last_error and self.last_success and time.time() - self.last_success <= grace),
                "failures": self.failures,
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
        with self.opener.open(request, timeout=max(COLLECTOR_POLL_TIMEOUT, self.interval * 3)) as response:
            if response.status != 200:
                raise RuntimeError("sing-box API 返回 HTTP {}".format(response.status))
            # json parses UTF-8 bytes on its own, which skips decoding the whole
            # snapshot into a second string on every poll.
            snapshot = json.loads(response.read())
        if not isinstance(snapshot, dict) or "connections" not in snapshot:
            raise RuntimeError("sing-box API 返回了无效数据")
        self.store.capture(snapshot, self.resolver)
        with self.lock:
            self.last_success = int(time.time())
            self.last_error = ""
            self.failures = 0

    def _run(self):
        failures = 0
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self._poll()
                failures = 0
                with self.lock:
                    self.failures = 0
            except (HTTPError, URLError, OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                failures += 1
                with self.lock:
                    self.failures = failures
                    self.last_error = str(error)
            if failures:
                # Cap the backoff so a transient blip stays visible for seconds
                # instead of leaving the dashboard red for up to a minute.
                retry_interval = max(self.interval, min(COLLECTOR_RETRY_MAX, 2 ** min(failures, 6)))
            else:
                retry_interval = self.interval
            wait_for = max(0.2, retry_interval - (time.monotonic() - started))
            self.stop_event.wait(wait_for)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = REQUEST_QUEUE_SIZE


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "sing-box-audit/" + SERVICE_VERSION
    # Keep the dashboard's frequent polling on reused sockets instead of opening
    # a fresh TCP connection for every request.  Every response sets
    # Content-Length, which HTTP/1.1 keep-alive requires.
    protocol_version = "HTTP/1.1"
    timeout = CLIENT_IDLE_TIMEOUT

    def log_message(self, message, *args):
        # The dashboard refreshes frequently; successful access logs would only
        # flood journald/OpenRC logs. Exceptions are still reported by the server.
        return

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (socket.timeout, TimeoutError, ConnectionResetError, BrokenPipeError):
            # An idle keep-alive socket or a client that vanished between
            # requests is expected; do not log a traceback for it.
            self.close_connection = True

    def _internal_error(self, error):
        sys.stderr.write("请求处理失败: {}: {}\n".format(type(error).__name__, error))
        traceback.print_exc()
        if getattr(self, "response_started", False):
            # Headers are already on the wire, so the response cannot be replaced.
            self.close_connection = True
            return
        try:
            self._json({"error": "internal_error", "message": "审计服务内部错误"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        except OSError:
            self.close_connection = True

    def _run_request(self, handler):
        # Without this guard an unexpected failure closes the socket without a
        # response, which browsers surface as an opaque "Failed to fetch".
        self.response_started = False
        started = time.monotonic()
        try:
            handler()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as error:
            self._internal_error(error)
        finally:
            # The request is over, so give its read-only connection back; a
            # browser that abandons requests must not leak one connection each.
            self.server.store.release_reader()
            self._report_slow_request(time.monotonic() - started)

    def _report_slow_request(self, elapsed):
        # Cheap requests stay quiet, so anything printed here is the endpoint
        # that is worth looking at when the service uses too much CPU.
        if elapsed >= SLOW_REQUEST_SECONDS:
            sys.stderr.write("慢请求 {:.1f}s: {}\n".format(elapsed, self.path))

    def end_headers(self):
        self.response_started = True
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
            # A missing token must never turn into anonymous access to the audit
            # database (source IPs, UUID users, visited hosts).  build_server()
            # refuses such a config, so this is the second line of defence.
            return False
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
        self._run_request(self._do_get)

    def _do_get(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            collector = self.server.collector.status()
            self._json({
                "ok": True, "service": "sing-box-audit", "version": SERVICE_VERSION,
                "auth_required": bool(self.server.web_token),
                "collector_running": collector["running"], "collector_connected": collector["connected"],
                "collector_failures": collector["failures"],
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
        self._run_request(self._do_post)

    def _do_post(self):
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
        try:
            self._dispatch_api(parsed, params, range_name, start, end)
        except StoreBusy as error:
            # Answer immediately instead of letting the request hang until the
            # browser gives up: the dashboard then reports a busy panel and its
            # own backoff slows the next round down.
            self._json({"error": "busy", "message": str(error)}, HTTPStatus.SERVICE_UNAVAILABLE)

    def _dispatch_api(self, parsed, params, range_name, start, end):
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
    # load_config() already refuses a short token, but this is the value the HTTP
    # handler compares against, so refuse an empty one here as well instead of
    # falling back to "authentication disabled".
    web_token = str(config.get("web_token") or "")
    if not web_token:
        raise ValueError("web_token 不能为空")
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
    server.web_token = web_token
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
