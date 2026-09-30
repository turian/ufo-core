from urllib.parse import quote

from ufo.sdk.surfaces import BlobStore

STATE_PREFIX = "surface/matrix/matrix-e2ee"
ACCOUNT_KEY = f"{STATE_PREFIX}/account"
PINS_KEY = f"{STATE_PREFIX}/pins"
SINCE_KEY = f"{STATE_PREFIX}/since"
WATCHES_KEY = f"{STATE_PREFIX}/watches"


def _olm_key(sender_key: str) -> str:
    return f"{STATE_PREFIX}/olm/{quote(sender_key, safe='')}"


def _inbound_key(room_id: str, session_id: str) -> str:
    return f"{STATE_PREFIX}/inbound/{quote(room_id, safe='')}/{quote(session_id, safe='')}"


class CryptoState:
    """The deploy's E2EE state at rest, under one fleet-store prefix the surface owns. Bytes in,
    bytes out — every blob is already a keyed pickle — and the listener loop is the only writer,
    so deliveries and other replicas read it and never race it."""

    def __init__(self, store: BlobStore) -> None:
        self._store = store

    async def account(self) -> bytes | None:
        return await self._read(ACCOUNT_KEY)

    async def save_account(self, pickle: bytes) -> None:
        await self._store.put(ACCOUNT_KEY, pickle)

    async def olm_sessions(self, sender_key: str) -> bytes | None:
        return await self._read(_olm_key(sender_key))

    async def save_olm_sessions(self, sender_key: str, blob: bytes) -> None:
        await self._store.put(_olm_key(sender_key), blob)

    async def inbound_session(self, room_id: str, session_id: str) -> bytes | None:
        return await self._read(_inbound_key(room_id, session_id))

    async def save_inbound_session(self, room_id: str, session_id: str, pickle: bytes) -> None:
        await self._store.put(_inbound_key(room_id, session_id), pickle)

    async def pins(self) -> bytes | None:
        return await self._read(PINS_KEY)

    async def save_pins(self, blob: bytes) -> None:
        await self._store.put(PINS_KEY, blob)

    async def since(self) -> bytes | None:
        return await self._read(SINCE_KEY)

    async def save_since(self, since: bytes) -> None:
        await self._store.put(SINCE_KEY, since)

    async def watches(self) -> bytes | None:
        return await self._read(WATCHES_KEY)

    async def save_watches(self, blob: bytes) -> None:
        await self._store.put(WATCHES_KEY, blob)

    async def clear(self) -> None:
        """Everything this surface owns, dropped — the re-key path, since sessions and pins and
        the cursor of a dead device are worse than useless to its replacement."""
        for entry in await self._store.list(f"{STATE_PREFIX}/"):
            await self._store.delete(entry.key)

    async def _read(self, key: str) -> bytes | None:
        try:
            return await self._store.get(key)
        except KeyError:
            return None
