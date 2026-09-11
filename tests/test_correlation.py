"""Unit tests for the pure co-occurrence ranker in blucifer.analytics.correlation."""

from datetime import datetime, timedelta, timezone

from blucifer.analytics.correlation import correlate_devices

UTC = timezone.utc
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)  # epoch is a multiple of 60


def row(sensor: str | None, offset_s: int, mac: str | None) -> dict:
    return {
        "sensor_id": sensor,
        "ts": (BASE + timedelta(seconds=offset_s)).isoformat(timespec="seconds"),
        "mac": mac,
    }


# --------------------------------------------------------------------------- #
# correlate_devices
# --------------------------------------------------------------------------- #

def test_empty_rows_returns_zero_occasions():
    result = correlate_devices([], "AA")
    assert result["target_occasions"] == 0
    assert result["companions"] == []


def test_target_absent_returns_zero_occasions():
    rows = [row("s1", 0, "BB")]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 0
    assert result["companions"] == []


def test_single_occasion_no_companions():
    rows = [row("s1", 0, "AA")]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 1
    assert result["companions"] == []


def test_below_min_occasions_excluded():
    offsets = [0, 3600, 7200, 10800, 14400]
    rows = [row("s1", o, "AA") for o in offsets]
    # BB only co-occurs twice - below the default min_occasions=3.
    rows += [row("s1", 0, "BB"), row("s1", 3600, "BB")]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 5
    assert result["companions"] == []


def test_companion_meets_threshold_included_with_correct_rate():
    offsets = [0, 3600, 7200, 10800, 14400]
    rows = [row("s1", o, "AA") for o in offsets]
    # BB co-occurs in 4 of the target's 5 occasions.
    rows += [row("s1", o, "BB") for o in offsets[:4]]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 5
    (bb,) = result["companions"]
    assert bb["mac"] == "BB"
    assert bb["count"] == 4
    assert bb["rate"] == 0.8


def test_multi_sensor_same_wallclock_counted_as_separate_occasions():
    # AA+BB overlap at the same instant on two different sensors, plus once
    # more on s1 a minute later - three distinct (sensor_id, bucket) occasions.
    rows = [
        row("s1", 0, "AA"), row("s1", 0, "BB"),
        row("s2", 0, "AA"), row("s2", 0, "BB"),
        row("s1", 60, "AA"), row("s1", 60, "BB"),
    ]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 3
    (bb,) = result["companions"]
    assert bb["count"] == 3
    assert bb["rate"] == 1.0


def test_window_boundary_straddle_not_correlated():
    # Three clean co-occurrences, then a fourth where AA and BB land one
    # second apart but in different 60s buckets - not counted together.
    rows = [
        row("s1", 0, "AA"), row("s1", 0, "BB"),
        row("s1", 3600, "AA"), row("s1", 3600, "BB"),
        row("s1", 7200, "AA"), row("s1", 7200, "BB"),
        row("s1", 10859, "AA"),  # bucket boundary at :10860
        row("s1", 10861, "BB"),  # next bucket
    ]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 4
    (bb,) = result["companions"]
    assert bb["count"] == 3
    assert bb["rate"] == 0.75


def test_deterministic_ordering_tie_break():
    offsets = [0, 3600, 7200]
    rows = [row("s1", o, "AA") for o in offsets]
    # BB and CC co-occur with AA identically (same count/rate) - mac order breaks the tie.
    for o in offsets:
        rows.append(row("s1", o + 5, "CC"))
        rows.append(row("s1", o + 5, "BB"))
    result = correlate_devices(rows, "AA")
    assert [c["mac"] for c in result["companions"]] == ["BB", "CC"]


def test_ubiquitous_flag_not_excluded():
    offsets = [0, 3600, 7200, 10800, 14400]
    rows = [row("s1", o, "AA") for o in offsets[:3]]  # AA in 3 of 5 total occasions
    rows += [row("s1", o, "BB") for o in offsets[:4]]  # BB in 4 of 5 total occasions
    rows += [row("s1", 14400, "CC")]  # a 5th occasion unrelated to AA or BB
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 3
    (bb,) = result["companions"]
    assert bb["count"] == 3
    assert bb["ubiquitous"] is True


def test_result_limit_caps_output():
    offsets = [0, 60, 120, 180, 240, 300]  # 6 distinct, contiguous occasions
    rows = [row("s1", o, "AA") for o in offsets]
    rows += [row("s1", o, "DD") for o in offsets]        # count 6, rate 1.0
    rows += [row("s1", o, "EE") for o in offsets[:5]]     # count 5, rate 0.833
    rows += [row("s1", o, "FF") for o in offsets[:4]]     # count 4, rate 0.667
    rows += [row("s1", o, "GG") for o in offsets[:3]]     # count 3, rate 0.5
    result = correlate_devices(rows, "AA", limit=2)
    assert [c["mac"] for c in result["companions"]] == ["DD", "EE"]


def test_malformed_rows_skipped_without_raising():
    rows = [
        {"sensor_id": "s1", "ts": "not-a-date", "mac": "AA"},
        {"sensor_id": None, "ts": row("s1", 0, "AA")["ts"], "mac": "AA"},
        {"sensor_id": "s1", "ts": row("s1", 0, "AA")["ts"], "mac": None},
        row("s1", 0, "AA"),
    ]
    result = correlate_devices(rows, "AA")
    assert result["target_occasions"] == 1
    assert result["companions"] == []
