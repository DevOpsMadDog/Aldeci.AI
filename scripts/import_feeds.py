#!/usr/bin/env python3
"""Load downloaded CISA KEV and FIRST EPSS data into feeds.db.

    python3 scripts/fetch_feeds.py     # downloads to data/feeds/*.json|.csv.gz
    python3 scripts/import_feeds.py    # loads them into feeds.db  <-- this step

Why this exists: fetch_feeds.py downloaded 4.3 MB of real KEV and EPSS data to
disk and nothing ever read it. Every table in feeds.db stayed at 0 rows and the
API kept reporting

    GET /api/v1/feeds/kev/status  ->  {"status": "empty", "total_entries": 0}

after a successful refresh. Nothing in the tree wrote kev_entries or
epss_scores — the enrichment data used to arrive as a 45 MB feeds.db committed
to git, which is exactly the kind of artifact that should not be in a
repository. Removing it left the documented refresh path downloading files into
a void.

The database is written where the product reads it: FIXOPS_DATA_DIR/feeds when
set, otherwise data/feeds. Both files are optional — importing only KEV, or
only EPSS, is a normal partial refresh and reports what it did.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import pathlib
import sqlite3
import sys
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parents[1]


def _feeds_dir() -> pathlib.Path:
    configured = os.environ.get("FIXOPS_DATA_DIR", "").strip()
    return (pathlib.Path(configured) / "feeds") if configured else (REPO / "data" / "feeds")


def _connect(db: pathlib.Path) -> sqlite3.Connection:
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id TEXT, vendor_project TEXT, product TEXT,
            vulnerability_name TEXT, date_added TEXT, short_description TEXT,
            required_action TEXT, due_date TEXT,
            known_ransomware_campaign_use TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id TEXT, epss REAL, percentile REAL, date TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS feed_metadata (
            feed_name TEXT, last_refresh TEXT, records_count INTEGER,
            status TEXT, category TEXT, error_message TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_kev_cve  ON kev_entries (cve_id);
        CREATE INDEX IF NOT EXISTS idx_epss_cve ON epss_scores (cve_id);
        """
    )
    return conn


def _record_meta(conn: sqlite3.Connection, feed: str, count: int, status: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("DELETE FROM feed_metadata WHERE feed_name = ?", (feed,))
    conn.execute(
        "INSERT INTO feed_metadata "
        "(feed_name, last_refresh, records_count, status, category, error_message) "
        "VALUES (?,?,?,?,?,?)",
        (feed, now, count, status, "exploit_intelligence", None),
    )


def import_kev(conn: sqlite3.Connection, path: pathlib.Path) -> int:
    """CISA KEV catalog JSON -> kev_entries. Replaces the table: KEV is a
    catalog, not an append log, and a stale row is a wrong answer."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("vulnerabilities") or []
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        (
            e.get("cveID"), e.get("vendorProject"), e.get("product"),
            e.get("vulnerabilityName"), e.get("dateAdded"),
            e.get("shortDescription"), e.get("requiredAction"),
            e.get("dueDate"), e.get("knownRansomwareCampaignUse"), now,
        )
        for e in entries
        if e.get("cveID")
    ]
    conn.execute("DELETE FROM kev_entries")
    conn.executemany(
        "INSERT INTO kev_entries VALUES (?,?,?,?,?,?,?,?,?,?)", rows
    )
    _record_meta(conn, "cisa_kev", len(rows), "success")
    return len(rows)


def import_epss(conn: sqlite3.Connection, path: pathlib.Path) -> int:
    """FIRST EPSS daily CSV (gzipped) -> epss_scores.

    The file opens with a '#model_version...' comment line before the header,
    which csv.DictReader would otherwise treat as the header and yield rows
    keyed by a comment.
    """
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        text = handle.read()
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    now = datetime.now(timezone.utc).isoformat()
    today = now[:10]
    rows = []
    for record in reader:
        cve = (record.get("cve") or "").strip()
        if not cve:
            continue
        try:
            rows.append((cve, float(record.get("epss") or 0.0),
                         float(record.get("percentile") or 0.0), today, now))
        except ValueError:
            continue
    conn.execute("DELETE FROM epss_scores")
    conn.executemany("INSERT INTO epss_scores VALUES (?,?,?,?,?)", rows)
    _record_meta(conn, "epss", len(rows), "success")
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feeds-dir", help="defaults to FIXOPS_DATA_DIR/feeds or data/feeds")
    args = parser.parse_args()

    feeds = pathlib.Path(args.feeds_dir) if args.feeds_dir else _feeds_dir()
    db = feeds / "feeds.db"
    kev_file, epss_file = feeds / "kev.json", feeds / "epss.csv.gz"

    if not kev_file.is_file() and not epss_file.is_file():
        print(f"  nothing to import in {feeds}")
        print("  run: python3 scripts/fetch_feeds.py")
        return 1

    conn = _connect(db)
    total = 0
    with conn:
        if kev_file.is_file():
            n = import_kev(conn, kev_file)
            print(f"  CISA KEV : {n:,} entries")
            total += n
        else:
            print("  CISA KEV : kev.json not present — skipped")
        if epss_file.is_file():
            n = import_epss(conn, epss_file)
            print(f"  EPSS     : {n:,} scores")
            total += n
        else:
            print("  EPSS     : epss.csv.gz not present — skipped")
    conn.close()

    print(f"  written  : {db}")
    print(f"  total    : {total:,} rows")
    print("\n  Verify:  GET /api/v1/feeds/kev/status  should no longer say \"empty\".")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
