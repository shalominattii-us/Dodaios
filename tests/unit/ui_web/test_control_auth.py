"""Auth for the Jarvis Control API (step 5).

``require_control_key`` guards every /api/control/* route with a Bearer key.
``require_control_key_or_session`` additionally accepts an authenticated UI
session so the desktop Settings panel can fetch or rotate the key.
``assert_bind_safe`` is the fail-closed boot check: never expose a non-loopback
bind without a key (the key, not the bind address, is the boundary).
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from dodaios.core import control_key as ck
from dodaios.ui.web import control_auth as ca


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(
        self,
        *,
        auth: str | None = None,
        host: str = "testclient",
        session_token: str | None = None,
    ) -> None:
        self.headers: dict[str, str] = {}
        if auth is not None:
            self.headers["authorization"] = auth
        self.client = _FakeClient(host)
        self.cookies = {}
        if session_token is not None:
            self.cookies[ca.COOKIE_NAME] = session_token
        # Mirror the ASGI scope a real starlette Request carries; the
        # open-access check inspects Host header + client peer on it.
        self.scope = {
            "type": "http",
            "headers": [(b"host", host.encode("ascii"))],
            "client": (host, 50_000),
        }


@pytest.fixture
def stored_key(monkeypatch):
    monkeypatch.setattr(ck, "get_control_key", lambda: "jctl_realkey")
    return "jctl_realkey"


# --- require_control_key (Bearer only) ---


async def test_rejects_missing_header(stored_key) -> None:
    with pytest.raises(HTTPException) as exc:
        await ca.require_control_key(_FakeRequest())
    assert exc.value.status_code == 401


async def test_rejects_wrong_key(stored_key) -> None:
    with pytest.raises(HTTPException) as exc:
        await ca.require_control_key(_FakeRequest(auth="Bearer jctl_wrong"))
    assert exc.value.status_code == 401


async def test_accepts_valid_bearer(stored_key) -> None:
    # Must not raise.
    await ca.require_control_key(_FakeRequest(auth="Bearer jctl_realkey"))


async def test_loopback_does_not_bypass_main_guard(stored_key) -> None:
    # A loopback caller still needs the key on the main endpoints — otherwise
    # the key would be pointless for local agents on desktop.
    with pytest.raises(HTTPException):
        await ca.require_control_key(_FakeRequest(host="127.0.0.1"))


# --- require_control_key_or_session (key-reveal / rotate) ---


async def test_raw_loopback_does_not_bypass_session_guard(stored_key) -> None:
    with pytest.raises(HTTPException):
        await ca.require_control_key_or_session(_FakeRequest(host="127.0.0.1"))


async def test_session_guard_denies_remote_without_key(stored_key) -> None:
    with pytest.raises(HTTPException):
        await ca.require_control_key_or_session(_FakeRequest(host="203.0.113.7"))


async def test_session_guard_allows_remote_with_valid_key(stored_key) -> None:
    await ca.require_control_key_or_session(
        _FakeRequest(auth="Bearer jctl_realkey", host="203.0.113.7")
    )


async def test_session_guard_accepts_registered_ui_session(stored_key) -> None:
    from dodaios.ui.web.missions_auth import register_token, revoke_token

    token = "ui-session-token"  # noqa: S105
    register_token(token)
    try:
        await ca.require_control_key_or_session(_FakeRequest(session_token=token))
    finally:
        revoke_token(token)


async def test_session_guard_grants_loopback_when_browser_lock_off(stored_key) -> None:
    # Browser lock OFF (the product default): the loopback UI has no session
    # cookie, yet must reach the key panel — otherwise the user could never
    # see the key needed to turn the lock ON.
    from dodaios.ui.web.surface_security import set_browser_login_required

    set_browser_login_required(False)
    await ca.require_control_key_or_session(_FakeRequest(host="127.0.0.1"))


async def test_session_guard_still_denies_remote_when_browser_lock_off(stored_key) -> None:
    from dodaios.ui.web.surface_security import set_browser_login_required

    set_browser_login_required(False)
    with pytest.raises(HTTPException):
        await ca.require_control_key_or_session(_FakeRequest(host="203.0.113.7"))


# --- assert_bind_safe (fail-closed) ---


def test_bind_safe_allows_loopback_without_key() -> None:
    ca.assert_bind_safe("127.0.0.1", None)  # no raise


def test_bind_safe_allows_non_loopback_with_key() -> None:
    ca.assert_bind_safe("0.0.0.0", "jctl_realkey")  # noqa: S104 — test input, no real bind


def test_bind_safe_refuses_non_loopback_without_key() -> None:
    with pytest.raises(RuntimeError):
        ca.assert_bind_safe("0.0.0.0", None)  # noqa: S104 — test input, no real bind


# --- person_at_window (administration stays on the far side of nothing) ---


def _window_request(
    *,
    host: str = "127.0.0.1",
    session_token: str | None = None,
    auth: str | None = None,
    same_origin: bool = False,
    relay_header: str | None = None,
) -> _FakeRequest:
    """A request shaped like one the desktop WebView or a relayed caller sends."""
    import base64

    request = _FakeRequest(host=host, session_token=session_token, auth=auth)
    headers = list(request.scope["headers"])
    if same_origin:
        request.headers["sec-fetch-site"] = "same-origin"
        headers.append((b"sec-fetch-site", b"same-origin"))
    if relay_header is not None:
        # Base64 the value so ``auth`` and ``relay_header`` never look like the
        # same key; the guard only reads presence, not the value.
        headers.append((relay_header.encode("ascii"), base64.b64encode(b"203.0.113.7")))
    request.scope["headers"] = headers
    return request


def test_person_at_window_accepts_the_local_ui(stored_key) -> None:
    assert ca.person_at_window(_window_request(same_origin=True)) is True


def test_person_at_window_accepts_a_local_session(stored_key) -> None:
    from dodaios.ui.web.missions_auth import register_token, revoke_token

    token = "ui-session-token"  # noqa: S105
    register_token(token)
    try:
        assert ca.person_at_window(_window_request(session_token=token)) is True
    finally:
        revoke_token(token)


@pytest.mark.parametrize(
    "relay_header", ["cf-connecting-ip", "x-forwarded-for", "x-real-ip", "true-client-ip"]
)
def test_person_at_window_refuses_an_edge_forwarded_session(stored_key, relay_header) -> None:
    # The Cloudflare edge in front of the host relays the owner's own session
    # cookie. It proves who signed in, not that anyone is at this machine, so
    # it must never be able to approve an administration decision.
    from dodaios.ui.web.missions_auth import register_token, revoke_token

    token = "ui-session-token"  # noqa: S105
    register_token(token)
    try:
        request = _window_request(session_token=token, relay_header=relay_header)
        assert ca.person_at_window(request) is False
    finally:
        revoke_token(token)


def test_person_at_window_refuses_a_relayed_local_origin(stored_key) -> None:
    # Even the browser-shaped local signal is refused once a relay stamped the
    # request: the peer socket is the relay's, so "same-origin" describes the
    # relay's page, not the machine's WebView.
    assert ca.person_at_window(
        _window_request(same_origin=True, relay_header="cf-connecting-ip")
    ) is False


def test_relay_forwarded_reads_the_same_header_set() -> None:
    from dodaios.ui.web.surface_security import relay_forwarded

    assert relay_forwarded(_window_request(relay_header="cf-connecting-ip").scope) is True
    assert relay_forwarded(_window_request(same_origin=True).scope) is False
