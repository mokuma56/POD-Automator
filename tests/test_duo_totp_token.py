"""Tests for the Duo hardware-token (TOTP) provisioning guards.

Regression cover for the bug that left POD-5 with no second factor and no student
login page on 2026-09-02.

The token serial is derived from the org number alone (POD<org>-PROCTOR), and SCC
orgs are REUSED across lab sessions — so the second session on any org gets
40003 "Duplicate resource" from POST /admin/v1/tokens. It cannot be cleaned up
either: GET /admin/v1/tokens reports 0 tokens to that Admin API application while
the POST is still rejected, so the conflicting token is invisible.

The retry that handles this was itself broken on the first attempt, and that is
what these tests exist for: it matched on str(exc), but requests raises only
"400 Client Error: Bad Request for url: ..." while Duo's 40003 lives in the
RESPONSE BODY. So the retry never fired and the failure surfaced as a bare 400 —
which then cascaded into "jumphost page: FAILED — no TOTP secret", because the
student login page needs the secret the token provisions.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from duo_automation import duo_is_duplicate_resource, duo_unique_serial  # noqa: E402


class _Resp:
    """Minimal stand-in for a requests Response."""

    def __init__(self, text):
        self._text = text

    @property
    def text(self):
        if self._text is None:
            raise RuntimeError("body could not be read")
        return self._text


def _http_error(message, body):
    """A requests-style HTTPError: terse message, detail only in .response."""
    exc = Exception(message)
    exc.response = _Resp(body)
    return exc


# The exact pair observed on POD-5 / org 524.
REAL_MESSAGE = ("400 Client Error: Bad Request for url: "
                "https://api-demodemo.duosecurity.com/admin/v1/tokens")
REAL_BODY = '{"code": 40003, "message": "Duplicate resource", "stat": "FAIL"}'


def test_duplicate_detected_from_response_body():
    """THE regression: the message says nothing, the body says 40003."""
    assert duo_is_duplicate_resource(_http_error(REAL_MESSAGE, REAL_BODY)) is True


def test_message_alone_would_not_have_matched():
    """Proves the test above is meaningful rather than trivially true.

    If this ever starts finding the marker in the message, the body-based check
    is no longer what makes the retry work and this suite has stopped guarding
    the real defect.
    """
    assert "40003" not in REAL_MESSAGE
    assert "Duplicate resource" not in REAL_MESSAGE


def test_duplicate_detected_when_body_is_interpolated_into_the_message():
    """Some callers stringify the body into the error; still a duplicate."""
    exc = Exception(f"token provisioning failed: {REAL_MESSAGE} {REAL_BODY}")
    assert duo_is_duplicate_resource(exc) is True


def test_unrelated_400_is_not_treated_as_duplicate():
    """A genuine bad request must propagate, not silently retry under a new
    serial and mask whatever is actually wrong."""
    body = '{"code": 40002, "message": "Invalid request parameters", "stat": "FAIL"}'
    assert duo_is_duplicate_resource(_http_error(REAL_MESSAGE, body)) is False


def test_permission_error_is_not_treated_as_duplicate():
    body = '{"code": 40301, "message": "Access forbidden", "stat": "FAIL"}'
    assert duo_is_duplicate_resource(_http_error("403 Client Error", body)) is False


def test_exception_with_no_response_does_not_raise():
    """A timeout has no .response at all — must return False, not explode.

    POD-5 hit exactly this on the retry: HTTPSConnectionPool ... Read timed out.
    """
    exc = Exception("HTTPSConnectionPool(host='api-demodemo.duosecurity.com', "
                    "port=443): Read timed out. (read timeout=20)")
    assert duo_is_duplicate_resource(exc) is False


def test_unreadable_body_does_not_raise():
    """.text can throw; the guard must degrade to False rather than propagate."""
    exc = _http_error("400 Client Error", None)
    assert duo_is_duplicate_resource(exc) is False


def test_unique_serial_differs_and_keeps_the_readable_prefix():
    base = "POD524-PROCTOR"
    out = duo_unique_serial(base)
    assert out != base
    assert out.startswith(base + "-")
    # 4-digit suffix, so it stays legible in the Duo admin UI.
    assert out[len(base) + 1:].isdigit()
    assert len(out[len(base) + 1:]) == 4


def test_unique_serial_is_idempotent_in_shape():
    """Applying it twice must not produce something unbounded — a retry loop
    should not grow the serial without limit."""
    once = duo_unique_serial("POD524-PROCTOR")
    twice = duo_unique_serial(once)
    assert twice.startswith(once + "-")
    assert len(twice) < 64      # Duo rejects absurd serials
