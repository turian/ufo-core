import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from ufo.sdk.credentials import deploy_env
from ufo_ext_matrix.wire import (
    BOT_TOKEN_ENV,
    HOMESERVER_ENV,
    SyncBatch,
)

CLIENT_PATH_PREFIX = "/_matrix/client/v3"
WHOAMI_PATH = f"{CLIENT_PATH_PREFIX}/account/whoami"
SYNC_PATH = f"{CLIENT_PATH_PREFIX}/sync"
JOIN_PATH = f"{CLIENT_PATH_PREFIX}/join"
ALIAS_PATH = f"{CLIENT_PATH_PREFIX}/directory/room"
ROOMS_PATH = f"{CLIENT_PATH_PREFIX}/rooms"
UPLOAD_PATH = "/_matrix/media/v3/upload"
MEDIA_DOWNLOAD_PATH = "/_matrix/client/v1/media/download"
MEDIA_CHUNK_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 60.0
SYNC_POLL_TIMEOUT_MS = "30000"
RETRY_AFTER_MS_KEY = "retry_after_ms"
UNKNOWN_TOKEN_ERRORS = frozenset({"M_UNKNOWN_TOKEN", "M_FATAL_UNKNOWN_TOKEN"})


class MatrixAuthError(RuntimeError):
    """The homeserver refuses this bot's token: a permanent failure the listener parks on and no
    retry repairs."""


class MatrixApiError(RuntimeError):
    """A homeserver call that failed: `status` is the HTTP status the server answered, None when
    the request never got an answer, and a rate limit carries when to try again. `transient` is
    whether the same call can succeed later."""

    def __init__(
        self, message: str, *, status: int | None, retry_after_seconds: int | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after_seconds = retry_after_seconds

    @property
    def transient(self) -> bool:
        return self.status is None or self.status == 429 or self.status >= 500


@dataclass(frozen=True)
class DeploySettings:
    homeserver: str
    bot_token: str


def deploy_settings() -> DeploySettings:
    """The two deploy keys the provider account answers with, read at the call site so a deploy
    that adds them later answers without a restart: missing is a mis-deployment, not a fallback."""
    homeserver = deploy_env(HOMESERVER_ENV)
    if homeserver is None:
        raise ValueError(f"matrix deploy key missing from the environment: {HOMESERVER_ENV}")
    bot_token = deploy_env(BOT_TOKEN_ENV)
    if bot_token is None:
        raise ValueError(f"matrix deploy key missing from the environment: {BOT_TOKEN_ENV}")
    return DeploySettings(homeserver=homeserver, bot_token=bot_token)


def _require_string(payload: dict[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise MatrixApiError(f"matrix request answered no {field}", status=200)
    return value


def _transport_failure(error: httpx.TransportError) -> MatrixApiError:
    return MatrixApiError(f"matrix request got no answer: {type(error).__name__}", status=None)


class MatrixClient:
    """One bot's client-server session on its homeserver. Sends carry the stable `txn` ids their
    callers chose, which is what makes a re-post after a crash return the event it already made
    instead of a second one."""

    def __init__(self, settings: DeploySettings) -> None:
        self._base = settings.homeserver.rstrip("/")
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {settings.bot_token}"},
            timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def whoami(self) -> str:
        return _require_string(await self._request("GET", WHOAMI_PATH), "user_id")

    async def sync(self, since: str | None) -> SyncBatch:
        """One long-poll: the server holds the request until a room changes or its timeout runs,
        so a quiet deploy costs one outstanding connection and a message lands when published."""
        params: dict[str, str] = {"timeout": SYNC_POLL_TIMEOUT_MS}
        if since is not None:
            params["since"] = since
        return SyncBatch.model_validate(await self._request("GET", SYNC_PATH, params=params))

    async def join(self, room_id_or_alias: str) -> str:
        payload = await self._request("POST", f"{JOIN_PATH}/{quote(room_id_or_alias, safe='')}")
        return _require_string(payload, "room_id")

    async def resolve_room(self, room: str) -> str:
        """The room id one address names: an id as written, an alias through the directory."""
        if room.startswith("!"):
            return room
        payload = await self._request("GET", f"{ALIAS_PATH}/{quote(room, safe='')}")
        return _require_string(payload, "room_id")

    async def send(self, room_id: str, txn_id: str, content: dict[str, object]) -> str:
        """Send one room event under a transaction id: a re-send of the same transaction, while
        the homeserver keeps it (Synapse: 24 hours), returns the event the first send made, so a
        crashed and re-driven delivery says it once."""
        payload = await self._request(
            "PUT",
            f"{ROOMS_PATH}/{quote(room_id, safe='')}/send/m.room.message/{quote(txn_id, safe='')}",
            json_body=content,
        )
        return _require_string(payload, "event_id")

    async def upload_media(self, data: bytes, media_type: str, filename: str) -> str:
        payload = await self._request(
            "POST",
            UPLOAD_PATH,
            params={"filename": filename},
            content=data,
            headers={"Content-Type": media_type},
        )
        return _require_string(payload, "content_uri")

    async def download_media(self, content_uri: str) -> AsyncIterator[bytes]:
        parts = content_uri.removeprefix("mxc://").split("/")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise MatrixApiError(f"media uri {content_uri!r} names no server and file", status=400)
        server, media_id = (quote(part, safe="") for part in parts)
        request = self._client.build_request(
            "GET", f"{self._base}{MEDIA_DOWNLOAD_PATH}/{server}/{media_id}"
        )
        try:
            response = await self._client.send(request, stream=True)
            try:
                if response.status_code >= 400:
                    await response.aread()
                    self._raise_for(response)
                async for chunk in response.aiter_bytes(MEDIA_CHUNK_BYTES):
                    yield chunk
            finally:
                await response.aclose()
        except httpx.TransportError as error:
            raise _transport_failure(error) from error

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        json_body: dict[str, object] | None = None,
    ) -> dict[str, object]:
        try:
            response = await self._client.request(
                method,
                f"{self._base}{path}",
                params=params,
                content=content,
                headers=headers,
                json=json_body,
            )
        except httpx.TransportError as error:
            raise _transport_failure(error) from error
        self._raise_for(response)
        payload: object = response.json()
        if not isinstance(payload, dict):
            raise MatrixApiError("matrix request answered no object", status=response.status_code)
        return payload

    def _raise_for(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        if response.status_code == 401:
            raise MatrixAuthError("the homeserver refused the bot token (HTTP 401)")
        try:
            body: object = response.json()
        except json.JSONDecodeError:
            body = None
        detail = body.get("error") if isinstance(body, dict) else None
        matrix_code = body.get("errcode") if isinstance(body, dict) else None
        if matrix_code in UNKNOWN_TOKEN_ERRORS:
            raise MatrixAuthError(
                f"the homeserver no longer accepts this bot's token: {matrix_code}"
            )
        retry_after: int | None = None
        if response.status_code == 429 and isinstance(body, dict):
            allowed = body.get(RETRY_AFTER_MS_KEY)
            if isinstance(allowed, (int, float)) and allowed >= 0:
                retry_after = int(max(allowed // 1000, 1))
        message = detail if isinstance(detail, str) else f"HTTP {response.status_code}"
        raise MatrixApiError(
            f"matrix request failed: {message}",
            status=response.status_code,
            retry_after_seconds=retry_after,
        )
