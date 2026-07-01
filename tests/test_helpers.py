"""Tests for the small pure helpers in hardax/__init__.py that underpin
classification and output filtering."""
import hardax


def test_bucket_from_level():
    assert hardax.bucketFromLevel("critical") == "critical"
    assert hardax.bucketFromLevel("high") == "critical"
    assert hardax.bucketFromLevel("warning") == "warning"
    assert hardax.bucketFromLevel("medium") == "warning"
    assert hardax.bucketFromLevel("info") == "info"
    assert hardax.bucketFromLevel("low") == "info"
    assert hardax.bucketFromLevel("verify") == "info"
    assert hardax.bucketFromLevel("") == "info"


def test_is_adb_transport_error():
    assert hardax.isAdbTransportError("device offline")
    assert hardax.isAdbTransportError("error: device unauthorized")
    assert hardax.isAdbTransportError("no devices/emulators found")
    assert not hardax.isAdbTransportError("")
    assert not hardax.isAdbTransportError("perfectly normal command output")


def test_is_service_error():
    assert hardax.isServiceError("cmd: can't find service")
    assert hardax.isServiceError("Can't find service: bluetooth_manager")
    assert not hardax.isServiceError("")
    assert not hardax.isServiceError("normal output")


def test_is_null_response():
    for s in ("null", "NULL", "(null)", "none", "(none)"):
        assert hardax.isNullResponse(s)
    assert not hardax.isNullResponse("a real value")
    assert not hardax.isNullResponse("")


def test_is_empty_or_error():
    assert hardax.isEmptyOrError("")
    assert hardax.isEmptyOrError("not found")
    assert hardax.isEmptyOrError("permission denied")
    assert not hardax.isEmptyOrError("uid=0(root)")


def test_normalize_for_match_line_endings():
    assert hardax.normalizeForMatch("a\r\nb\rc") == "a\nb\nc"
    assert hardax.normalizeForMatch("") == ""


def test_apply_filters_grep_single():
    out = "alpha\nbeta\ngamma"
    assert hardax.applyFilters(out, "cmd | grep beta") == "beta"


def test_apply_filters_grep_invert():
    out = "keep1\ndrop\nkeep2"
    assert hardax.applyFilters(out, "cmd | grep -v drop") == "keep1\nkeep2"


def test_apply_filters_head_and_tail():
    out = "1\n2\n3\n4\n5"
    assert hardax.applyFilters(out, "cmd | head -2") == "1\n2"
    assert hardax.applyFilters(out, "cmd | tail -2") == "4\n5"


def test_apply_filters_no_pipe_returns_input():
    out = "line1\nline2"
    assert hardax.applyFilters(out, "plaincommand") == out
