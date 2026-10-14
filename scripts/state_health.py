#!/usr/bin/env python3
"""Read-only local state health; never creates a missing database or grants authority."""
import argparse
import json
import sqlite3
from pathlib import Path


def inspect(path: Path) -> dict:
    if not path.is_file():
        raise ValueError('state database missing')
    with sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2) as db:
        if db.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('unsupported state schema')
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('database integrity check failed')
        frozen = db.execute('SELECT frozen FROM containment WHERE singleton=1').fetchone()
        if frozen is None:
            raise ValueError('containment state missing')
        counts = dict(db.execute('SELECT status, count(*) FROM reservations GROUP BY status'))
        legacy = db.execute('SELECT count(*) FROM reservations r LEFT JOIN reservation_proposals p '
                            'ON p.reservation_id=r.reservation_id WHERE p.reservation_id IS NULL').fetchone()[0]
    return {'storage': 'readable', 'schema': 1, 'frozen': bool(frozen[0]),
            'reservation_counts': counts, 'legacy_snapshots_missing': legacy,
            'dispatch_authorized': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.database), sort_keys=True))
        return 0
    except (ValueError, sqlite3.Error, OSError):
        # No exception text: SQLite paths and payloads are not operational logs.
        print(json.dumps({'storage': 'unhealthy', 'dispatch_authorized': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
