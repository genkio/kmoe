"""Tests for kmoe.auth module."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

from kmoe.auth import load_session, login, save_session
from kmoe.constants import URLTemplate
from kmoe.exceptions import AuthError
from kmoe.models import UserStatus

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def _session_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect session storage to a temporary directory."""
    session_path = tmp_path / "session.enc"
    monkeypatch.setattr("kmoe.auth._get_session_path", lambda: session_path)


@pytest.mark.usefixtures("_session_dir")
def test_save_and_load_roundtrip() -> None:
    """Cookies survive a save -> load roundtrip."""
    cookies = {"session_id": "abc123", "token": "xyz789"}
    save_session(cookies)
    assert load_session() == cookies


@pytest.mark.usefixtures("_session_dir")
def test_load_missing_file() -> None:
    """Returns None when session file does not exist."""
    assert load_session() is None


@pytest.mark.usefixtures("_session_dir")
def test_load_corrupted_file(tmp_path: Path) -> None:
    """Returns None when session file contains garbage."""
    (tmp_path / "session.enc").write_bytes(b"not-valid-fernet-data")
    assert load_session() is None


@pytest.mark.usefixtures("_session_dir")
def test_load_wrong_machine_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when machine identity changes after save."""
    save_session({"session_id": "abc123"})

    # Simulate a different machine by swapping the key
    wrong_key = base64.urlsafe_b64encode(b"\x00" * 32)
    monkeypatch.setattr("kmoe.auth._get_machine_key", lambda: wrong_key)

    assert load_session() is None


def _mock_client(post_text: str) -> AsyncMock:
    """Build a mock KmoeClient whose login POST returns the given body."""
    client = AsyncMock()
    client.post.return_value.text = post_text
    client.get.return_value.text = ""
    client.get_cookies = MagicMock(return_value={"VOLSKEY": "tok"})
    return client


@pytest.mark.usefixtures("_session_dir")
async def test_login_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful login posts to login_act.php, saves session, returns status."""
    client = _mock_client('{"ret":0,"msgid":"m100"}')
    status = UserStatus(uin="1", username="1", level=3, is_vip=False)
    monkeypatch.setattr("kmoe.auth._build_user_status", AsyncMock(return_value=status))

    result = await login(client, "user@example.com", "pw")

    assert result is status
    assert client.post.await_args.args[0] == URLTemplate.LOGIN
    assert client.post.await_args.kwargs["data"] == {
        "email": "user@example.com",
        "passwd": "pw",
    }
    assert load_session() == {"VOLSKEY": "tok"}


async def test_login_bad_credentials() -> None:
    """Non-m100 msgid raises AuthError carrying the server message."""
    client = _mock_client('{"ret":-1,"msg":"郵箱帳號或密碼錯誤。","msgid":"e400"}')

    with pytest.raises(AuthError, match="郵箱帳號或密碼錯誤"):
        await login(client, "user@example.com", "wrong")

    client.get_cookies.assert_not_called()


async def test_login_non_json_response() -> None:
    """A non-JSON body raises AuthError instead of crashing."""
    client = _mock_client('<script>parent.display_codeinfo( "e400", 0 );</script>')

    with pytest.raises(AuthError, match="unexpected server response"):
        await login(client, "user@example.com", "pw")
