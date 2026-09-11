"""
Cross-device correlation ("companion devices") over sighting rows.

Pure - takes plain dicts already fetched from the DB (one per sighting: mac,
ts, sensor_id) and returns which other devices repeatedly co-occur with a
target device on the same sensor within a short time window. No DB or config
imports, so it's unit-testable without a database (see visits.py).
"""

from collections import Counter, defaultdict

from blucifer.analytics.visits import parse_ts

# Sightings on the same sensor within this many seconds of each other are
# treated as "the same occasion". Roughly 2-4x a real scan cycle (BLE scan
# interval + duration, plus classic scan when sequential on one adapter),
# enough to absorb cycle jitter without merging genuinely separate visits.
CORRELATION_WINDOW_SECONDS = 60

# A companion must co-occur with the target at least this many times before
# it's surfaced at all - filters out one-off overlaps.
CORRELATION_MIN_OCCASIONS = 3

# A device present in at least this fraction of *all* occasions in the
# fetched window (not just the target's) is flagged "ubiquitous" rather than
# excluded - e.g. an always-on beacon that's technically correlated with
# everything, but not a meaningful pairing.
CORRELATION_UBIQUITY_THRESHOLD = 0.8

# Max companions returned, most-correlated first.
CORRELATION_RESULT_LIMIT = 15


def correlate_devices(
    rows: list[dict],
    target_mac: str,
    *,
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
    min_occasions: int = CORRELATION_MIN_OCCASIONS,
    ubiquity_threshold: float = CORRELATION_UBIQUITY_THRESHOLD,
    limit: int = CORRELATION_RESULT_LIMIT,
) -> dict:
    """
    Ranks other devices by how often they co-occur with ``target_mac``.

    ``rows`` is a list of ``{"sensor_id": str, "ts": str, "mac": str}`` dicts,
    any order, already restricted upstream to sensors the target was seen on.
    A row missing ``sensor_id``/``mac`` or with an unparseable ``ts`` is
    skipped rather than aborting.

    Sightings are grouped into "occasions" - one per distinct
    ``(sensor_id, floor(ts / window_seconds))`` - and a companion's ``count``
    is how many of the target's occasions it also appears in.

    Returns:
        {
          "target_mac": str,
          "target_occasions": int,   # distinct occasions the target appears in
          "window_seconds": int,
          "companions": [
            {
              "mac": str,
              "count": int,          # co-occasions with the target
              "rate": float,         # count / target_occasions, 0..1
              "ubiquitous": bool,    # present in >= ubiquity_threshold of
                                     # ALL occasions in `rows`, not just the
                                     # target's
            }, ...
          ]  # sorted by rate desc, count desc, mac asc; only entries with
             # count >= min_occasions; capped at `limit`
        }

    If the target has zero occasions in ``rows``, returns
    ``target_occasions=0`` and ``companions=[]``.
    """
    presence: dict[tuple[str, int], set[str]] = defaultdict(set)
    for r in rows:
        sensor_id = r.get("sensor_id")
        mac = r.get("mac")
        if not sensor_id or not mac:
            continue
        dt = parse_ts(r.get("ts"))
        if dt is None:
            continue
        bucket = int(dt.timestamp()) // window_seconds
        presence[(sensor_id, bucket)].add(mac)

    target_keys = [k for k, macs in presence.items() if target_mac in macs]
    n_target = len(target_keys)
    if n_target == 0:
        return {
            "target_mac": target_mac,
            "target_occasions": 0,
            "window_seconds": window_seconds,
            "companions": [],
        }

    co_counts: Counter = Counter()
    for key in target_keys:
        for m in presence[key]:
            if m != target_mac:
                co_counts[m] += 1

    total_occasions = len(presence)
    total_presence: Counter = Counter()
    for macs in presence.values():
        for m in macs:
            total_presence[m] += 1

    companions = []
    for m, count in co_counts.items():
        if count < min_occasions:
            continue
        rate = count / n_target
        ubiquitous = (total_presence[m] / total_occasions) >= ubiquity_threshold
        companions.append({
            "mac": m,
            "count": count,
            "rate": round(rate, 3),
            "ubiquitous": ubiquitous,
        })

    companions.sort(key=lambda c: (-c["rate"], -c["count"], c["mac"]))
    return {
        "target_mac": target_mac,
        "target_occasions": n_target,
        "window_seconds": window_seconds,
        "companions": companions[:limit],
    }
