from base64 import b64encode
from pathlib import Path

import pytest
from ufo_ext_matrix.crypto import CryptoRuntime, canonical_json
from ufo_ext_matrix.media import decrypt_attachment, encrypt_attachment
from ufo_ext_matrix.state import CryptoState
from ufo_ext_matrix.wire import (
    ENCRYPTED_MESSAGE_TYPE,
    MEGOLM_ALGORITHM,
    ROOM_KEY_EVENT_TYPE,
    SyncEvent,
    ToDeviceEvent,
)

from ufo.blob import FilesystemBlobStore, FleetBlobStore

pytest.importorskip("vodozemac")

import vodozemac
from ufo_ext_matrix.surface import _consume_to_device, _inbound_messages

BOT_TOKEN = "bot-token"
MEMBER_TOKEN = "member-token"
ROOM_ID = "!room:hs.org"


def _store(tmp_path: Path) -> FleetBlobStore:
    return FleetBlobStore(backend=FilesystemBlobStore(root=tmp_path))


async def _runtime(tmp_path: Path, token: str = BOT_TOKEN) -> CryptoRuntime:
    return await CryptoRuntime.load(_store(tmp_path), token, device_id="UFO")


async def _share_room_key(
    sender: CryptoRuntime, receiver: CryptoRuntime, room_id: str
) -> vodozemac.GroupSession:
    """The member side of the protocol, over the same primitives the wire carries."""
    group = vodozemac.GroupSession()
    payload = {
        "type": ROOM_KEY_EVENT_TYPE,
        "content": {
            "algorithm": MEGOLM_ALGORITHM,
            "room_id": room_id,
            "session_id": group.session_id,
            "session_key": group.session_key.to_base64(),
        },
    }
    (one_time_key,) = [
        k["key"] for k in (await receiver.mint_otks(1, "@2ambot:matrix.org")).values()
    ]
    session = sender.olm_session_to(receiver.curve25519, one_time_key)
    tag, raw = session.encrypt(canonical_json(payload)).to_parts()
    opened = await receiver.decrypt_olm(sender.curve25519, tag, b64encode(raw).decode())
    assert opened is not None and opened["type"] == ROOM_KEY_EVENT_TYPE
    assert await receiver.store_room_key(opened["content"]) is True
    return group


def _room_event(
    event_id: str, group: vodozemac.GroupSession, body: str, sender: CryptoRuntime
) -> SyncEvent:
    return SyncEvent.model_validate(
        {
            "event_id": event_id,
            "type": ENCRYPTED_MESSAGE_TYPE,
            "sender": "@member:hs.org",
            "content": {
                "algorithm": MEGOLM_ALGORITHM,
                "ciphertext": group.encrypt(
                    canonical_json({"msgtype": "m.text", "body": body})
                ).to_base64(),
                "sender_key": sender.curve25519,
                "session_id": group.session_id,
                "device_id": "MEMBER",
            },
        }
    )


async def test_account_persists_across_restart(tmp_path: Path) -> None:
    first = await _runtime(tmp_path)
    again = await _runtime(tmp_path)
    assert again.curve25519 == first.curve25519
    assert again.ed25519 == first.ed25519


async def test_a_token_rotation_rekeys_the_device(tmp_path: Path) -> None:
    old = await _runtime(tmp_path, "old-token")
    group = await _share_room_key(await _runtime(tmp_path / "member"), old, ROOM_ID)
    assert len(group.session_id) > 0
    fresh = await CryptoRuntime.load(_store(tmp_path), "rotated-token", "UFO")
    assert fresh.curve25519 != old.curve25519
    reloaded = await CryptoRuntime.load(_store(tmp_path), "rotated-token", "UFO")
    assert reloaded.curve25519 == fresh.curve25519
    assert await CryptoState(_store(tmp_path)).since() is None


async def test_room_key_then_megolm_roundtrip(tmp_path: Path) -> None:
    bot = await _runtime(tmp_path / "bot")
    member = await _runtime(tmp_path / "member")
    group = await _share_room_key(member, bot, ROOM_ID)
    payload = await bot.decrypt_megolm(
        ROOM_ID,
        group.session_id,
        group.encrypt(canonical_json({"msgtype": "m.text", "body": "hello"})).to_base64(),
    )
    assert payload == {"msgtype": "m.text", "body": "hello"}


async def test_inbound_session_survives_restart(tmp_path: Path) -> None:
    bot_dir = tmp_path / "bot"
    member = await _runtime(tmp_path / "member")
    group = await _share_room_key(member, await _runtime(bot_dir), ROOM_ID)
    ciphertext = group.encrypt(canonical_json({"msgtype": "m.text", "body": "two"})).to_base64()
    restarted = await _runtime(bot_dir)
    payload = await restarted.decrypt_megolm(ROOM_ID, group.session_id, ciphertext)
    assert payload == {"msgtype": "m.text", "body": "two"}


async def test_second_olm_message_opens_on_the_stored_session(tmp_path: Path) -> None:
    bot = await _runtime(tmp_path / "bot")
    member = await _runtime(tmp_path / "member")
    (one_time_key,) = [k["key"] for k in (await bot.mint_otks(1, "@2ambot:matrix.org")).values()]
    session = member.olm_session_to(bot.curve25519, one_time_key)
    tag, raw = session.encrypt(canonical_json({"n": 1})).to_parts()
    assert await bot.decrypt_olm(member.curve25519, tag, b64encode(raw).decode()) == {"n": 1}
    tag, raw = session.encrypt(canonical_json({"n": 2})).to_parts()
    assert await bot.decrypt_olm(member.curve25519, tag, b64encode(raw).decode()) == {"n": 2}


async def test_undecryptable_traffic_answers_none(tmp_path: Path) -> None:
    bot = await _runtime(tmp_path)
    group = await _share_room_key(await _runtime(tmp_path / "member"), bot, ROOM_ID)
    assert await bot.decrypt_megolm(ROOM_ID, "unknown-session", "AwgA") is None
    assert await bot.decrypt_megolm(ROOM_ID, group.session_id, "not-a-message") is None
    stranger = await _runtime(tmp_path / "stranger")
    (one_time_key,) = [k["key"] for k in (await bot.mint_otks(1, "@2ambot:matrix.org")).values()]
    tag, raw = stranger.olm_session_to(bot.curve25519, one_time_key).encrypt(b"x").to_parts()
    assert await bot.decrypt_olm("no-such-sender-key", tag, b64encode(raw).decode()) is None


async def test_pin_tofu_refuses_changed_keys(tmp_path: Path) -> None:
    bot = await _runtime(tmp_path)
    keys = {"curve25519:DEV": "c1", "ed25519:DEV": "e1"}
    changed = {"curve25519:DEV": "c2", "ed25519:DEV": "e2"}
    assert await bot.pin("@member:hs.org", "DEV", keys) is not None
    assert await bot.pin("@member:hs.org", "DEV", keys) is not None
    assert await bot.pin("@member:hs.org", "DEV", changed) is None
    reloaded = await _runtime(tmp_path)
    assert await reloaded.pin("@member:hs.org", "DEV", changed) is None


async def test_listener_message_path_merges_plaintext_and_decrypted(tmp_path: Path) -> None:
    bot = await _runtime(tmp_path / "bot")
    member = await _runtime(tmp_path / "member")
    group = await _share_room_key(member, bot, ROOM_ID)
    plain = SyncEvent.model_validate(
        {
            "event_id": "e-plain",
            "type": "m.room.message",
            "sender": "@member:hs.org",
            "content": {"msgtype": "m.text", "body": "open words"},
        }
    )
    secret = _room_event("e-secret", group, "closed words", member)
    lost = _room_event("e-lost", vodozemac.GroupSession(), "unreadable", member)
    malformed = SyncEvent.model_validate(
        {"event_id": "e-bad", "type": ENCRYPTED_MESSAGE_TYPE, "sender": "@member:hs.org"}
    )
    messages = await _inbound_messages(bot, ROOM_ID, (plain, secret, lost, malformed))
    assert [message.content.body for message in messages] == ["open words", "closed words"]


async def test_to_device_room_key_lands_before_the_room_event(tmp_path: Path) -> None:
    bot = await _runtime(tmp_path / "bot")
    member = await _runtime(tmp_path / "member")
    group = vodozemac.GroupSession()
    payload = {
        "type": ROOM_KEY_EVENT_TYPE,
        "content": {
            "algorithm": MEGOLM_ALGORITHM,
            "room_id": ROOM_ID,
            "session_id": group.session_id,
            "session_key": group.session_key.to_base64(),
        },
    }
    (one_time_key,) = [k["key"] for k in (await bot.mint_otks(1, "@2ambot:matrix.org")).values()]
    session = member.olm_session_to(bot.curve25519, one_time_key)
    tag, raw = session.encrypt(canonical_json(payload)).to_parts()
    event = ToDeviceEvent.model_validate(
        {
            "type": ENCRYPTED_MESSAGE_TYPE,
            "sender": "@member:hs.org",
            "content": {
                "algorithm": "m.olm.v1.curve25519-aes-sha2",
                "sender_key": member.curve25519,
                "ciphertext": {bot.curve25519: {"type": tag, "body": b64encode(raw).decode()}},
            },
        }
    )
    await _consume_to_device(bot, (event,))
    message = await bot.decrypt_megolm(
        ROOM_ID,
        group.session_id,
        group.encrypt(canonical_json({"msgtype": "m.text", "body": "via sync"})).to_base64(),
    )
    assert message == {"msgtype": "m.text", "body": "via sync"}


async def test_state_roundtrips_every_blob(tmp_path: Path) -> None:
    state = CryptoState(_store(tmp_path))
    assert await state.account() is None
    await state.save_account(b"account-pickle")
    await state.save_olm_sessions("sender+key/=", b"olm-envelope")
    await state.save_inbound_session("!room:hs.org", "session+id=", b"inbound-pickle")
    await state.save_pins(b"pins-json")
    await state.save_since(b"s12_34_0")
    reloaded = CryptoState(_store(tmp_path))
    assert await reloaded.account() == b"account-pickle"
    assert await reloaded.olm_sessions("sender+key/=") == b"olm-envelope"
    assert await reloaded.inbound_session("!room:hs.org", "session+id=") == b"inbound-pickle"
    assert await reloaded.pins() == b"pins-json"
    assert await reloaded.olm_sessions("other") is None
    runtime = await _runtime(tmp_path / "runtime")
    assert await runtime.restore_since() is None
    await runtime.save_since("s13_0")
    restarted = await CryptoRuntime.load(_store(tmp_path / "runtime"), BOT_TOKEN, "UFO")
    assert await restarted.restore_since() == "s13_0"


async def test_attachments_travel_encrypted_and_refuse_tampering() -> None:
    data = b"attachment bytes" * 100
    ciphertext, file_dict = encrypt_attachment(data)
    assert ciphertext != data
    assert decrypt_attachment(ciphertext, file_dict) == data
    file_dict["hashes"]["sha256"] = b64encode(b"\x00" * 32).rstrip(b"=").decode()
    with pytest.raises(ValueError):
        decrypt_attachment(ciphertext, file_dict)
    with pytest.raises(KeyError):
        decrypt_attachment(ciphertext, {})
