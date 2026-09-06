"""
Visit / dwell segmentation over a device's raw sighting timeline.

A *visit* (presence session) is a maximal run of sightings for one device whose
successive timestamps are no more than ``gap_seconds`` apart. This module is
pure - it takes plain dicts and returns plain dicts, with no database or config
imports - so the segmentation logic can be unit-tested without any setup.
"""

import statistics

from datetime import datetime, timezone


def _parse_ts(ts: object) -> datetime | None:
    """
    Parse an ISO-8601 timestamp into an aware UTC ``datetime``.

    Tolerates a trailing ``Z`` (``datetime.fromisoformat`` rejects it before
    Python 3.11) and naive strings (assumed UTC). Returns ``None`` for anything
    unparseable so a bad row can be skipped rather than aborting a scan.
    """
    if not isinstance(ts, str):
        return None
    raw = ts.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _finalize(acc: dict) -> dict:
    """Turn an open-run accumulator into a public visit dict."""
    first: datetime = acc["_first_dt"]
    last: datetime = acc["_last_dt"]
    n: int = acc["_rssi_n"]
    return {
        "start": first.isoformat(timespec="seconds"),
        "end": last.isoformat(timespec="seconds"),
        "duration_s": int((last - first).total_seconds()),
        "sighting_count": acc["sighting_count"],
        "sensor_count": len(acc["sensors"]),
        "sensors": sorted(acc["sensors"]),
        "rssi_min": acc["_rssi_min"],
        "rssi_max": acc["_rssi_max"],
        "rssi_mean": round(acc["_rssi_sum"] / n, 1) if n else None,
    }


def segment_visits(sightings: list[dict], gap_seconds: int) -> list[dict]:
    """
    Group a device's sightings into visits.

    ``sightings`` is a list of ``{"ts": str, "rssi": int | None,
    "sensor_id": str | None}`` dicts in ascending ``ts`` order (the SQL query
    guarantees this; the list is not re-sorted here). Rows with an unparseable
    ``ts`` are skipped and do not split a run.

    Returns visit dicts, oldest-first, each carrying ``start``/``end`` (ISO-8601
    UTC, second precision), ``duration_s`` (0 for a lone sighting),
    ``sighting_count``, ``sensor_count``, ``sensors`` (sorted; ``"unknown"`` for
    a null ``sensor_id``) and ``rssi_min``/``rssi_max``/``rssi_mean`` (``None``
    when no sighting in the run carried an RSSI).
    """
    visits: list[dict] = []
    cur: dict | None = None

    for row in sightings:
        dt = _parse_ts(row.get("ts"))
        if dt is None:
            continue

        if cur is not None and (dt - cur["_last_dt"]).total_seconds() > gap_seconds:
            visits.append(_finalize(cur))
            cur = None

        if cur is None:
            cur = {
                "_first_dt": dt,
                "_last_dt": dt,
                "sighting_count": 0,
                "sensors": set(),
                "_rssi_min": None,
                "_rssi_max": None,
                "_rssi_sum": 0,
                "_rssi_n": 0,
            }

        cur["_last_dt"] = dt
        cur["sighting_count"] += 1
        cur["sensors"].add(row.get("sensor_id") or "unknown")

        rssi = row.get("rssi")
        if rssi is not None:
            cur["_rssi_min"] = rssi if cur["_rssi_min"] is None else min(cur["_rssi_min"], rssi)
            cur["_rssi_max"] = rssi if cur["_rssi_max"] is None else max(cur["_rssi_max"], rssi)
            cur["_rssi_sum"] += rssi
            cur["_rssi_n"] += 1

    if cur is not None:
        visits.append(_finalize(cur))

    return visits


def _empty_summary() -> dict:
    return {
        "count": 0,
        "total_dwell_s": 0,
        "median_dwell_s": 0,
        "mean_dwell_s": 0,
        "longest_dwell_s": 0,
        "shortest_dwell_s": 0,
        "first_visit_start": None,
        "last_visit_end": None,
        "span_days": 0.0,
        "visits_per_day": 0.0,
        "sighting_count_total": 0,
        "sensors": [],
        "currently_present": False,
        "seconds_since_last": None,
        "active_visit": None,
    }


def visits_summary(
    visits: list[dict],
    gap_seconds: int,
    *,
    now: datetime | None = None,
) -> dict:
    """
    Window aggregates over a list of visit dicts from :func:`segment_visits`.

    Every value is timezone-independent (counts, durations in seconds, a
    presence flag). Hour-of-day / weekday / per-day bucketing is deliberately
    left to the client so it happens in the viewer's local timezone.

    ``now`` is injectable for deterministic tests; it defaults to
    ``datetime.now(timezone.utc)``. ``currently_present`` is true when the last
    visit ended no more than ``gap_seconds`` ago, and ``active_visit`` is that
    visit when so (else ``None``).
    """
    if now is None:
        now = datetime.now(timezone.utc)

    if not visits:
        return _empty_summary()

    durations = [v["duration_s"] for v in visits]
    first_start = visits[0]["start"]
    last_end = visits[-1]["end"]

    first_dt = _parse_ts(first_start)
    last_dt = _parse_ts(last_end)
    span_seconds = (last_dt - first_dt).total_seconds() if first_dt and last_dt else 0.0
    span_days = max(1.0 / 86400, span_seconds / 86400)

    seconds_since_last: int | None = None
    currently_present = False
    if last_dt is not None:
        seconds_since_last = int((now - last_dt).total_seconds())
        currently_present = seconds_since_last <= gap_seconds

    return {
        "count": len(visits),
        "total_dwell_s": sum(durations),
        "median_dwell_s": statistics.median(durations),
        "mean_dwell_s": round(statistics.fmean(durations), 1),
        "longest_dwell_s": max(durations),
        "shortest_dwell_s": min(durations),
        "first_visit_start": first_start,
        "last_visit_end": last_end,
        "span_days": round(span_days, 4),
        "visits_per_day": round(len(visits) / span_days, 2),
        "sighting_count_total": sum(v["sighting_count"] for v in visits),
        "sensors": sorted({s for v in visits for s in v["sensors"]}),
        "currently_present": currently_present,
        "seconds_since_last": seconds_since_last,
        "active_visit": visits[-1] if currently_present else None,
    }
