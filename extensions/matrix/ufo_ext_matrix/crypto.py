import json
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ufo.sdk.o11y import warn
from ufo.sdk.surfaces import BlobStore
from ufo_ext_matrix.client import MatrixClient
from ufo_ext_matrix.state import CryptoState
from ufo_ext_matrix.wire import (
    ENCRYPTED_MESSAGE_TYPE,
    MEGOLM_ALGORITHM,
    OLM_ALGORITHM,
    ROOM_KEY_EVENT_TYPE,
    pickle_key,
)

try:
    import vodozemac
except ImportError:  # pragma: no cover - the plain build carries no backend
    vodozemac = None

if TYPE_CHECKING:
    from vodozemac import Account, Session

E2EE_AVAILABLE = vodozemac is not None
OTK_TARGET_COUNT = 32
OTK_TOPUP_COOLDOWN_SECONDS = 30.0
OLM_PREKEY_TYPE = 0
INBOUND_CACHE_LIMIT = 512


class E2eeUnavailable(RuntimeError):
    """The surface met an encrypted room with no crypto backend installed."""


def canonical_json(payload: dict[str, object]) -> bytes:
    """The byte form a Matrix signature covers: sorted keys, no whitespace, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class DeviceKeys:
    """One member device the deploy pinned on first sight."""

    user_id: str
    device_id: str
    curve25519: str
    ed25519: str


class CryptoRuntime:
    """The deploy's one Olm identity and everything keyed to it: the account, the olm sessions
    per sender device, the megolm inbound sessions per (room, session), and the TOFU pins. The
    listener loop owns every write — it is the lease holder — and deliveries hold the same
    object read-only, so one process sees one identity and the fleet store carries one pickled
    truth. With no backend installed the runtime does not exist and the surface runs plaintext
    rooms only, warning at the first encrypted event it sees."""

    def __init__(
        self,
        store: CryptoState,
        account: "Account",
        pickle_key: bytes,
        device_id: str,
        pins: dict[str, DeviceKeys],
        refused: frozenset[str],
    ) -> None:
        self._store = store
        self._account = account
        self._pickle_key = pickle_key
        self.device_id = device_id
        self._pins = pins
        self._refused = set(refused)
        self._olm: dict[str, list[Session]] = {}
        self._inbound: dict[tuple[str, str], object | None] = {}
        self.encrypted_rooms: set[str] = set()
        self._published = False
        self._otk_uploaded_at = 0.0

    @property
    def curve25519(self) -> str:
        return self._account.curve25519_key.to_base64()

    @property
    def ed25519(self) -> str:
        return self._account.ed25519_key.to_base64()

    def olm_session_to(self, curve25519: str, one_time_key: str) -> "Session":
        """A fresh olm channel to one device, opened on its claimed one-time key. The session
        lives in the caller's hand only — a delivery's channel is ephemeral, so nothing of it
        persists and no ratchet is ever shared between writers."""
        return self._account.create_outbound_session(
            vodozemac.Curve25519PublicKey.from_base64(curve25519),
            vodozemac.Curve25519PublicKey.from_base64(one_time_key),
        )

    @classmethod
    async def load(
        cls, store: BlobStore, bot_token: str, device_id: str
    ) -> "CryptoRuntime":
        state = CryptoState(store)
        key = pickle_key(bot_token)
        raw = await state.account()
        try:
            account = (
                vodozemac.Account.from_pickle(raw.decode(), key)
                if raw is not None
                else None
            )
        except vodozemac.PickleException:
            account = None
        if account is None:
            if raw is not None:
                # The pickle no longer opens under this deploy's key: the token was rotated or
                # the state was written by another deploy. The device is gone — re-key, and the
                # sessions, pins, and cursor of the old device mean nothing.
                await state.clear()
                warn("matrix.crypto_rekeyed", device_id=device_id)
            account = vodozemac.Account()
            await state.save_account(account.pickle(key).encode())
        envelope = json.loads(pins) if (pins := await state.pins()) else {}
        return cls(
            store=state,
            account=account,
            pickle_key=key,
            device_id=device_id,
            pins={
                tag: DeviceKeys(
                    user_id=device["user_id"],
                    device_id=device["device_id"],
                    curve25519=device["curve25519"],
                    ed25519=device["ed25519"],
                )
                for tag, device in envelope.get("devices", {}).items()
            },
            refused=frozenset(envelope.get("refused", ())),
        )

    async def publish(
        self, client: MatrixClient, bot_id: str, otk_count: int | None
    ) -> None:
        """The device the deploy speaks as, made known to the network: identity keys once, and
        one-time keys whenever the server's count runs under target — each claimed OTK is one
        delivery's olm channel, so the pool is what keeps encrypted sends possible."""
        if not self._published:
            await client.keys_upload(device_keys=self._signed_device_keys(bot_id))
            self._published = True
        now = time.monotonic()
        if otk_count is not None and otk_count < OTK_TARGET_COUNT:
            if now - self._otk_uploaded_at < OTK_TOPUP_COOLDOWN_SECONDS:
                return
            self._otk_uploaded_at = now
            await client.keys_upload(
                one_time_keys=await self.mint_otks(OTK_TARGET_COUNT - otk_count)
            )

    async def restore_since(self) -> str | None:
        """Where the deploy's `/sync` stream stood when the listener last wrote it, so a restart
        resumes its own head instead of full-syncing the account. The stream cursor ask — core's
        seam holds an int — is why this lives in surface state at all."""
        raw = await self._store.since()
        return raw.decode() if raw is not None else None

    async def save_watches(self, blob: bytes) -> None:
        await self._store.save_watches(blob)

    async def restore_watches(self) -> bytes | None:
        return await self._store.watches()

    async def save_since(self, since: str) -> None:
        await self._store.save_since(since.encode())

    async def mint_otks(self, count: int) -> dict[str, str]:
        """A batch of one-time keys for the server: minted, published, and the account re-pickled
        in one step, since an OTK claimed after a crash must decrypt to what the pickle says."""
        self._account.generate_one_time_keys(count)
        keys = {
            f"signed_curve25519:{key_id}": key.to_base64()
            for key_id, key in self._account.one_time_keys.items()
        }
        self._account.mark_keys_as_published()
        await self._store.save_account(self._account.pickle(self._pickle_key).encode())
        return keys

    def _signed_device_keys(self, bot_id: str) -> dict[str, object]:
        payload: dict[str, object] = {
            "user_id": bot_id,
            "device_id": self.device_id,
            "algorithms": [OLM_ALGORITHM, MEGOLM_ALGORITHM],
            "keys": {
                f"curve25519:{self.device_id}": self.curve25519,
                f"ed25519:{self.device_id}": self.ed25519,
            },
        }
        signature = self._account.sign(canonical_json(payload))
        payload["signatures"] = {
            bot_id: {f"ed25519:{self.device_id}": signature.to_base64()}
        }
        return payload

    async def pin(
        self, user_id: str, device_id: str, keys: dict[str, str]
    ) -> DeviceKeys | None:
        """TOFU on one device: first sight pins its keys, same keys pass, changed keys refuse the
        device from then on — a pinned device never silently becomes another device."""
        tag = f"{user_id}|{device_id}"
        curve = keys.get(f"curve25519:{device_id}")
        ed = keys.get(f"ed25519:{device_id}")
        if not curve or not ed:
            return None
        known = self._pins.get(tag)
        if known is not None:
            if known.curve25519 == curve and known.ed25519 == ed:
                return known
            if tag not in self._refused:
                self._refused.add(tag)
                await self._save_pins()
                warn("matrix.device_key_changed", user_id=user_id, device_id=device_id)
            return None
        device = DeviceKeys(user_id=user_id, device_id=device_id, curve25519=curve, ed25519=ed)
        self._pins[tag] = device
        await self._save_pins()
        return device

    async def decrypt_olm(self, sender_key: str, body_type: int, body: str) -> dict | None:
        """One to-device olm payload opened: an existing session's ratchet if one matches, else a
        prekey message minting the session the sender started. The advanced sessions persist —
        the listener is their only writer."""
        try:
            message = vodozemac.AnyOlmMessage.from_parts(body_type, b64decode(body))
        except (vodozemac.DecodeException, ValueError):
            return None
        sessions = await self._sessions(sender_key)
        for session in sessions:
            try:
                plaintext = session.decrypt(message)
            except vodozemac.OlmDecryptionException:
                continue
            await self._save_sessions(sender_key, sessions)
            return json.loads(plaintext)
        prekey = message.to_pre_key()
        if prekey is None:
            return None
        try:
            session, plaintext = self._account.create_inbound_session(
                vodozemac.Curve25519PublicKey.from_base64(sender_key), prekey
            )
        except (
            vodozemac.DecodeException,
            vodozemac.KeyException,
            vodozemac.OlmDecryptionException,
            vodozemac.SessionCreationException,
        ):
            return None
        sessions.append(session)
        await self._save_sessions(sender_key, sessions)
        return json.loads(plaintext)

    async def store_room_key(self, payload: dict) -> bool:
        """One megolm inbound session from a room key the sender olm'd us: keyed by (room,
        session), kept once — senders re-share keys they have already shared."""
        if payload.get("algorithm") != MEGOLM_ALGORITHM:
            return False
        room_id = payload.get("room_id")
        session_id = payload.get("session_id")
        session_key = payload.get("session_key")
        if not (
            isinstance(room_id, str)
            and isinstance(session_id, str)
            and isinstance(session_key, str)
        ):
            return False
        if await self._inbound_session(room_id, session_id) is not None:
            return False
        session = vodozemac.InboundGroupSession(vodozemac.SessionKey(session_key))
        await self._store.save_inbound_session(
            room_id, session_id, session.pickle(self._pickle_key).encode()
        )
        self._note_inbound(room_id, session_id, session)
        return True

    async def decrypt_megolm(
        self, room_id: str, session_id: str, ciphertext: str
    ) -> dict | None:
        session = await self._inbound_session(room_id, session_id)
        if session is None:
            return None
        try:
            decrypted = session.decrypt(vodozemac.MegolmMessage.from_base64(ciphertext))
        except (
            vodozemac.MegolmDecryptionException,
            vodozemac.DecodeException,
        ):
            return None
        return json.loads(decrypted.plaintext)

    async def _sessions(self, sender_key: str) -> list["Session"]:
        sessions = self._olm.get(sender_key)
        if sessions is not None:
            return sessions
        raw = await self._store.olm_sessions(sender_key)
        envelope = json.loads(raw) if raw else {"sessions": []}
        loaded = [
            vodozemac.Session.from_pickle(entry["pickle"], self._pickle_key)
            for entry in envelope["sessions"]
        ]
        self._olm[sender_key] = loaded
        return loaded

    async def _save_sessions(self, sender_key: str, sessions: list["Session"]) -> None:
        await self._store.save_olm_sessions(
            sender_key,
            json.dumps(
                {
                    "sessions": [
                        {"id": session.session_id, "pickle": session.pickle(self._pickle_key)}
                        for session in sessions
                    ]
                }
            ).encode(),
        )

    async def _inbound_session(self, room_id: str, session_id: str) -> object | None:
        held = self._inbound.get((room_id, session_id))
        if held is not None or (room_id, session_id) in self._inbound:
            return held
        raw = await self._store.inbound_session(room_id, session_id)
        session = (
            vodozemac.InboundGroupSession.from_pickle(raw.decode(), self._pickle_key)
            if raw is not None
            else None
        )
        self._note_inbound(room_id, session_id, session)
        return session

    def _note_inbound(self, room_id: str, session_id: str, session: object | None) -> None:
        if len(self._inbound) >= INBOUND_CACHE_LIMIT:
            self._inbound.pop(next(iter(self._inbound)))
        self._inbound[(room_id, session_id)] = session

    async def _save_pins(self) -> None:
        await self._store.save_pins(
            json.dumps(
                {
                    "devices": {
                        tag: {
                            "user_id": device.user_id,
                            "device_id": device.device_id,
                            "curve25519": device.curve25519,
                            "ed25519": device.ed25519,
                        }
                        for tag, device in self._pins.items()
                    },
                    "refused": sorted(self._refused),
                }
            ).encode()
        )


@dataclass(frozen=True)
class OutboundCrypto:
    """One encrypted send: a megolm session minted for this event alone, its key olm'd to every
    pinned member device, then the event. Nothing of the ratchet persists — deliveries run on any
    replica, so a shared outbound session would ratchet from many writers at once; a session per
    send keeps every ratchet single-writer by construction and re-shares cost nothing the second
    time, when a redriven delivery reuses the transaction id and the homeserver returns the event
    it already made."""

    client: MatrixClient
    runtime: CryptoRuntime

    async def send(self, room_id: str, txn_id: str, payload: dict[str, object]) -> str:
        group = vodozemac.GroupSession()
        session_key = group.session_key.to_base64()
        session_id = group.session_id
        devices = await self._devices(room_id)
        await self._share(room_id, session_id, session_key, devices, txn_id)
        event: dict[str, object] = {
            "algorithm": MEGOLM_ALGORITHM,
            "sender_key": self.runtime.curve25519,
            "ciphertext": group.encrypt(canonical_json(payload)).to_base64(),
            "session_id": session_id,
            "device_id": self.runtime.device_id,
        }
        return await self.client.send(
            room_id, txn_id, event, event_type=ENCRYPTED_MESSAGE_TYPE
        )

    async def _devices(self, room_id: str) -> list[DeviceKeys]:
        members = await self.client.joined_members(room_id)
        devices = await self.client.keys_query(tuple(members))
        pinned = []
        for user_id, per_device in devices.items():
            for device_id, keys in per_device.items():
                device = await self.runtime.pin(user_id, device_id, keys.get("keys", {}))
                if device is not None:
                    pinned.append(device)
        return pinned

    async def _share(
        self,
        room_id: str,
        session_id: str,
        session_key: str,
        devices: list[DeviceKeys],
        txn_id: str,
    ) -> None:
        if not devices:
            raise MatrixNoDevices(room_id)
        claimed = await self.client.keys_claim(
            {
                device.user_id: {device.device_id: "signed_curve25519"}
                for device in devices
            }
        )
        room_key = {
            "type": ROOM_KEY_EVENT_TYPE,
            "content": {
                "algorithm": MEGOLM_ALGORITHM,
                "room_id": room_id,
                "session_id": session_id,
                "session_key": session_key,
            },
        }
        messages: dict[str, dict[str, object]] = {}
        for device in devices:
            one_time = claimed.get(device.user_id, {}).get(device.device_id)
            if not one_time:
                warn("matrix.share_skipped", user_id=device.user_id, device_id=device.device_id)
                continue
            key = next(iter(one_time.values()))
            session = self.runtime.olm_session_to(device.curve25519, key)
            tag, raw = session.encrypt(canonical_json(room_key)).to_parts()
            messages.setdefault(device.user_id, {})[device.device_id] = {
                "algorithm": OLM_ALGORITHM,
                "sender_key": self.runtime.curve25519,
                "ciphertext": {
                    device.curve25519: {
                        "type": tag,
                        "body": b64encode(raw).decode(),
                    }
                },
            }
        await self.client.send_to_device(
            "m.room.encrypted", f"ufo-key-{session_id}", messages
        )


class MatrixNoDevices(RuntimeError):
    """No member device of the room could be pinned and claimed, so there is nobody to share the
    room key with and the event cannot go out encrypted."""
