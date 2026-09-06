"""Unit tests for the pure visit / dwell segmenter in blucifer.analytics.visits."""

from datetime import datetime, timedelta, timezone

from blucifer.analytics.visits import segment_visits, visits_summary

UTC = timezone.utc
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def row(offset_s: int, rssi: int | None = -60, sensor: str | None = "s1") -> dict:
    return {
        "ts": (BASE + timedelta(seconds=offset_s)).isoformat(timespec="seconds"),
        "rssi": rssi,
        "sensor_id": sensor,
    }


# --------------------------------------------------------------------------- #
# segment_visits
# --------------------------------------------------------------------------- #

def test_empty():
    assert segment_visits([], 900) == []


def test_single_sighting():
    (v,) = segment_visits([row(0)], 900)
    assert v["duration_s"] == 0
    assert v["sighting_count"] == 1
    assert v["start"] == v["end"]
    assert v["sensors"] == ["s1"]
    assert v["sensor_count"] == 1
    assert v["rssi_min"] == v["rssi_max"] == -60
    assert v["rssi_mean"] == -60.0


def test_two_within_gap():
    (v,) = segment_visits([row(0), row(600)], 900)
    assert v["duration_s"] == 600
    assert v["sighting_count"] == 2


def test_two_beyond_gap():
    v = segment_visits([row(0), row(1200)], 900)
    assert len(v) == 2
    assert all(x["duration_s"] == 0 for x in v)


def test_exact_boundary_stays_one_visit():
    (v,) = segment_visits([row(0), row(900)], 900)
    assert v["duration_s"] == 900
    assert v["sighting_count"] == 2


def test_multi_sensor_same_cycle():
    (v,) = segment_visits(
        [row(0, -50, "s_a"), row(3, -70, "s_b"), row(10, -52, "s_a")], 900
    )
    assert v["sensors"] == ["s_a", "s_b"]
    assert v["sensor_count"] == 2
    assert v["sighting_count"] == 3
    assert v["rssi_min"] == -70
    assert v["rssi_max"] == -50
    assert v["rssi_mean"] == round((-50 - 70 - 52) / 3, 1)


def test_unparseable_ts_skipped_without_splitting():
    zulu = (BASE + timedelta(seconds=5)).isoformat(timespec="seconds").replace("+00:00", "Z")
    rows = [
        {"ts": "not-a-date", "rssi": -60, "sensor_id": "s1"},
        row(0),
        {"ts": zulu, "rssi": -61, "sensor_id": "s1"},
    ]
    (v,) = segment_visits(rows, 900)
    assert v["sighting_count"] == 2


def test_zulu_equals_offset():
    z = {"ts": "2026-01-01T12:00:00Z", "rssi": -60, "sensor_id": "s1"}
    off = {"ts": "2026-01-01T12:00:00+00:00", "rssi": -60, "sensor_id": "s1"}
    (v,) = segment_visits([z, off], 1)  # same instant -> one visit even at gap=1
    assert v["sighting_count"] == 2
    assert v["duration_s"] == 0


def test_rssi_none_excluded_from_stats():
    (v,) = segment_visits([row(0, None), row(10, -40)], 900)
    assert v["rssi_min"] == v["rssi_max"] == -40
    (v2,) = segment_visits([row(0, None), row(10, None)], 900)
    assert v2["rssi_min"] is None
    assert v2["rssi_max"] is None
    assert v2["rssi_mean"] is None


def test_null_sensor_becomes_unknown():
    (v,) = segment_visits([row(0, -60, None)], 900)
    assert v["sensors"] == ["unknown"]


def test_output_ascending_by_start():
    v = segment_visits([row(0), row(5000), row(10000)], 900)
    assert len(v) == 3
    starts = [x["start"] for x in v]
    assert starts == sorted(starts)


# --------------------------------------------------------------------------- #
# visits_summary
# --------------------------------------------------------------------------- #

def _visit_ending(dt: datetime, dur: int = 0, sensors: list[str] | None = None) -> dict:
    return {
        "start": (dt - timedelta(seconds=dur)).isoformat(timespec="seconds"),
        "end": dt.isoformat(timespec="seconds"),
        "duration_s": dur,
        "sighting_count": 2,
        "sensor_count": len(sensors or ["s1"]),
        "sensors": sensors or ["s1"],
        "rssi_min": None,
        "rssi_max": None,
        "rssi_mean": None,
    }


def test_summary_empty():
    s = visits_summary([], 900)
    assert s["count"] == 0
    assert s["median_dwell_s"] == 0
    assert s["currently_present"] is False
    assert s["visits_per_day"] == 0
    assert s["active_visit"] is None
    assert s["seconds_since_last"] is None


def test_summary_basic():
    visits = [
        _visit_ending(datetime(2026, 1, 1, tzinfo=UTC), dur=0),
        _visit_ending(datetime(2026, 1, 2, tzinfo=UTC), dur=600),
        _visit_ending(datetime(2026, 1, 3, tzinfo=UTC), dur=1200, sensors=["s2"]),
    ]
    s = visits_summary(visits, 900, now=datetime(2026, 2, 1, tzinfo=UTC))
    assert s["count"] == 3
    assert s["median_dwell_s"] == 600
    assert s["longest_dwell_s"] == 1200
    assert s["shortest_dwell_s"] == 0
    assert s["total_dwell_s"] == 1800
    assert s["sensors"] == ["s1", "s2"]
    assert s["currently_present"] is False


def test_currently_present_true():
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    last = _visit_ending(now - timedelta(seconds=60), dur=300)
    s = visits_summary([_visit_ending(now - timedelta(days=2)), last], 900, now=now)
    assert s["currently_present"] is True
    assert s["active_visit"] is last
    assert s["seconds_since_last"] == 60


def test_currently_present_false():
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    s = visits_summary([_visit_ending(now - timedelta(seconds=7200))], 900, now=now)
    assert s["currently_present"] is False
    assert s["active_visit"] is None


def test_visits_per_day_over_ten_days():
    start = datetime(2026, 6, 1, tzinfo=UTC)
    now = datetime(2026, 6, 25, tzinfo=UTC)
    visits = [_visit_ending(start)]
    visits += [_visit_ending(start + timedelta(hours=1, minutes=i)) for i in range(18)]
    visits.append(_visit_ending(start + timedelta(days=10)))
    s = visits_summary(visits, 900, now=now)
    assert len(visits) == 20
    assert s["span_days"] == 10.0
    assert s["visits_per_day"] == 2.0


def test_now_injection_is_deterministic():
    now = datetime(2026, 6, 1, tzinfo=UTC)
    visits = [_visit_ending(datetime(2026, 5, 1, tzinfo=UTC))]
    assert visits_summary(visits, 900, now=now) == visits_summary(visits, 900, now=now)
