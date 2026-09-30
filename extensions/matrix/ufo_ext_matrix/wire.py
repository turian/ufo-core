import hmac
from base64 import b32encode
from dataclasses import dataclass, field
from dataclasses import replace as dataclasses_replace
from hashlib import sha256
from re import compile as re_compile
from urllib.parse import quote, unquote
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ufo.sdk.audience import Audience, conversation_audience, foreign_room_audience, room_audience
from ufo.sdk.surfaces import (
    AskUserInput,
    ConnectRequest,
    CredentialRequest,
    Writeback,
)

SURFACE_NAME = "matrix"
HOMESERVER_ENV = "MATRIX_HOMESERVER"
BOT_TOKEN_ENV = "MATRIX_BOT_TOKEN"
DEVICE_ID_ENV = "MATRIX_DEVICE_ID"
CLAIM_TTL_SECONDS = 15 * 60
MAX_ARTIFACT_UPLOAD_BYTES = 50 * 1024 * 1024
AMBIENT_DIGEST_LIMIT = 8
PROOF_CODE_LENGTH = 8
PERMALINK_BASE = "https://matrix.to"
POST_TXN_PREFIX = "ufo-post-"
ATTACH_TXN_PREFIX = "ufo-attach-"
SPEAK_TXN_PREFIX = "ufo-mid-"
CLAIM_PROOF_MESSAGE = "ufo.matrix.claim"
PROOF_TOKEN_RE = re_compile(r"\b([a-z2-7]{8})\b")
MATRIX_TO_PILL_RE = re_compile(r"https://matrix\.to/#/([^\"'<>\s?]+)")
MESSAGE_TYPE = "m.room.message"
ENCRYPTED_MESSAGE_TYPE = "m.room.encrypted"
ENCRYPTION_STATE_TYPE = "m.room.encryption"
MEGOLM_ALGORITHM = "m.megolm.v1.aes-sha2"
OLM_ALGORITHM = "m.olm.v1.curve25519-aes-sha2"
ROOM_KEY_EVENT_TYPE = "m.room_key"
STATE_EVENT_TYPES = frozenset(
    {
        "m.room.create",
        "m.room.member",
        "m.room.name",
        "m.room.canonical_alias",
        ENCRYPTION_STATE_TYPE,
    }
)
MEMBERSHIP_JOINED = "join"
MEMBERSHIP_INVITED = "invite"
CONTENT_EXTRA_KEY = "content"


def claim_proof_code(bot_token: str, room_id: str, member_id: UUID) -> str:
    """The eight characters the claiming member sends in the room to prove the claim: keyed by
    the bot token, the room, and the member, so its possession is the proof and it never leaves
    the deriving deploy."""
    digest = hmac.new(
        bot_token.encode(),
        f"{CLAIM_PROOF_MESSAGE}|{room_id}|{member_id}".encode(),
        sha256,
    ).digest()
    return b32encode(digest)[:PROOF_CODE_LENGTH].decode().lower()


def proof_matches(body: str, bot_token: str, room_id: str, member_id: UUID) -> bool:
    """Whether a room message carries the claim's proof as a whole token: case-insensitively, so
    a client that upper-cases it still proves, and never as a fragment of other words."""
    code = claim_proof_code(bot_token, room_id, member_id)
    return any(match.group(1) == code for match in PROOF_TOKEN_RE.finditer(body.casefold()))


PICKLE_KEY_INFO = b"ufo.matrix.olm.pickle"
PICKLE_KEY_BYTES = 32


def pickle_key(bot_token: str) -> bytes:
    """The key the Olm account pickles under, HKDF-derived from the bot token: the deploy key the
    surface already holds is the only secret a deploy needs, and a rotated token re-keys."""
    prk = hmac.new(b"", bot_token.encode(), sha256).digest()
    return hmac.new(prk, PICKLE_KEY_INFO + b"\x01", sha256).digest()[:PICKLE_KEY_BYTES]


def room_key(room_id: str) -> str:
    """A room id with its colon percent-encoded: the audience key grammar takes no colon and
    the encoding is reversible, so the conversation key and the audience name one record."""
    return room_id.replace(":", "%3A")


def matrix_permalink(room_id: str, event_id: str) -> str:
    return f"{PERMALINK_BASE}/#/{quote(room_id, safe='')}/{quote(event_id, safe='')}"


class Mentions(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_ids: tuple[str, ...] = ()


class MediaInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    size: int | None = None
    filename: str | None = None


class MediaKey(BaseModel):
    """The AES key an encrypted attachment travels under, as the JWK the Matrix spec fixes."""

    model_config = ConfigDict(extra="allow")

    k: str
    alg: str = "A256CTR"
    ext: bool = True
    kty: str = "oct"


class EncryptedFile(BaseModel):
    """One attachment sent inside the encrypted payload: the ciphertext's mxc address and the
    material that decrypts it, both carried inside the megolm message, never in the clear."""

    model_config = ConfigDict(extra="allow")

    url: str
    key: MediaKey
    iv: str
    hashes: dict[str, str] = {}
    v: str = "2"


class MessageContent(BaseModel):
    """One room message's content, typed at the fields the surface reads and open at the rest,
    since homeservers carry extensions the spec leaves to clients."""

    model_config = ConfigDict(extra="allow")

    msgtype: str | None = None
    body: str = ""
    url: str | None = None
    file: EncryptedFile | None = None
    info: MediaInfo | None = None
    formatted_body: str | None = None
    mentions: Mentions | None = Field(default=None, alias="m.mentions")


class EncryptedContent(BaseModel):
    """The payload an `m.room.encrypted` event carries. `ciphertext` is the megolm message for
    room events; to-device olm events carry a per-recipient map instead, which the listener reads
    straight off the event."""

    model_config = ConfigDict(extra="allow")

    algorithm: str
    ciphertext: str = ""
    sender_key: str | None = None
    session_id: str | None = None
    device_id: str | None = None


class SyncEvent(BaseModel):
    """One raw /sync event: the fields every kind carries, the rest — each event's `content` in
    its own grammar — open."""

    model_config = ConfigDict(extra="allow")

    event_id: str
    type: str
    sender: str | None = None
    state_key: str | None = None
    origin_server_ts: int = 0


class SyncEventList(BaseModel):
    model_config = ConfigDict(extra="allow")

    events: tuple[SyncEvent, ...] = ()


class SyncRoom(BaseModel):
    model_config = ConfigDict(extra="allow")

    state: SyncEventList = Field(default_factory=SyncEventList)
    timeline: SyncEventList = Field(default_factory=SyncEventList)


class SyncRooms(BaseModel):
    model_config = ConfigDict(extra="allow")

    invite: dict[str, SyncRoom] = {}
    join: dict[str, SyncRoom] = {}
    leave: dict[str, SyncRoom] = {}


class ToDeviceEvent(BaseModel):
    """One event addressed to the bot's account rather than a room — under encryption, the
    channel olm sessions and megolm room keys arrive on. The `content` rides model_extra."""

    model_config = ConfigDict(extra="allow")

    type: str
    sender: str | None = None


class SyncToDevice(BaseModel):
    model_config = ConfigDict(extra="allow")

    events: tuple[ToDeviceEvent, ...] = ()


class SyncBatch(BaseModel):
    model_config = ConfigDict(extra="allow")

    next_batch: str
    rooms: SyncRooms = Field(default_factory=SyncRooms)
    to_device: SyncToDevice = Field(default_factory=SyncToDevice)
    device_one_time_keys_count: dict[str, int] = Field(default_factory=dict)


@dataclass(frozen=True)
class RoomState:
    """A room as one listener has observed it: each member's latest membership, what each member
    has called themselves, and the latest name and alias. Every field is bounded by the room's
    own roster, so a room outlives the events that named it."""

    id: str
    members: dict[str, str] = field(default_factory=dict)
    displaynames: dict[str, str] = field(default_factory=dict)
    name: str | None = None
    alias: str | None = None
    creator: str | None = None
    encryption: str | None = None


@dataclass(frozen=True)
class InboundMessage:
    """One room message the bot's account did not send."""

    room_id: str
    event_id: str
    sender: str
    content: MessageContent


def event_content(event: SyncEvent | ToDeviceEvent) -> dict[str, object]:
    extra = event.model_extra or {}
    content = extra.get(CONTENT_EXTRA_KEY)
    return content if isinstance(content, dict) else {}


def _membership(event: SyncEvent) -> str | None:
    value = event_content(event).get("membership")
    return value if isinstance(value, str) else None


def _string_content(event: SyncEvent, field_name: str) -> str | None:
    value = event_content(event).get(field_name)
    return value if isinstance(value, str) and value else None


def room_state_from_events(room_id: str, events: tuple[SyncEvent, ...]) -> RoomState:
    return amend_room_state(RoomState(id=room_id), events)


def amend_room_state(state: RoomState, events: tuple[SyncEvent, ...]) -> RoomState:
    for event in events:
        state = _apply_state_event(state, event)
    return state


def _apply_state_event(state: RoomState, event: SyncEvent) -> RoomState:
    match event.type:
        case "m.room.member":
            if event.state_key is None:
                return state
            membership = _membership(event)
            if membership is None:
                return state
            replaced = dataclasses_replace(
                state, members={**state.members, event.state_key: membership}
            )
            displayname = _string_content(event, "displayname")
            if displayname is None:
                return replaced
            return dataclasses_replace(
                replaced, displaynames={**state.displaynames, event.state_key: displayname}
            )
        case "m.room.name":
            name = _string_content(event, "name")
            return state if name is None else dataclasses_replace(state, name=name)
        case "m.room.create":
            return (
                state if event.sender is None else dataclasses_replace(state, creator=event.sender)
            )
        case "m.room.canonical_alias":
            alias = _string_content(event, "alias")
            return state if alias is None else dataclasses_replace(state, alias=alias)
        case "m.room.encryption":
            algorithm = _string_content(event, "algorithm")
            return state if algorithm is None else dataclasses_replace(state, encryption=algorithm)
        case _:
            return state


def room_state_events(events: tuple[SyncEvent, ...]) -> tuple[SyncEvent, ...]:
    return tuple(event for event in events if event.type in STATE_EVENT_TYPES)


def room_participants(state: RoomState) -> frozenset[str]:
    """The room's current members: the joiners and the invited, each under its latest state, the
    leavers dropped with it."""
    return frozenset(
        member
        for member, membership in state.members.items()
        if membership in (MEMBERSHIP_JOINED, MEMBERSHIP_INVITED)
    )


def is_direct_message(state: RoomState, sender: str, bot_id: str) -> bool:
    """The room is the two of them: the bot and the speaker, nobody else."""
    return room_participants(state) - {bot_id} == {sender}


def sender_display_name(state: RoomState, sender: str) -> str:
    return state.displaynames.get(sender, sender)


def mentions_bot(content: MessageContent, bot_id: str) -> bool:
    """An explicit address to the bot: the `m.mentions` user list the clients attach, or a
    matrix.to pill naming the account in the formatted body, percent-encoded or not — never a word
    match on the plain text."""
    if content.mentions is not None and bot_id in content.mentions.user_ids:
        return True
    if content.formatted_body is None:
        return False
    return any(
        unquote(match.group(1)) == bot_id
        for match in MATRIX_TO_PILL_RE.finditer(content.formatted_body)
    )


def room_label(state: RoomState) -> str:
    if state.alias:
        return state.alias
    if state.name:
        return state.name
    return f"Matrix room {state.id}"


def audience_for(state: RoomState, sender: str, bot_id: str, member_id: UUID | None) -> Audience:
    """The conversation one room message answers into: a linked member's DM is theirs alone; a
    room is the shared room audience; a room anyone outside it reached from another server seals
    as foreign before it is admitted."""
    if member_id is not None and is_direct_message(state, sender, bot_id):
        return conversation_audience(member_id)
    if any_participant_is_foreign(state, bot_id):
        return foreign_room_audience(SURFACE_NAME, room_key(state.id))
    return room_audience(SURFACE_NAME, room_key(state.id))


def any_participant_is_foreign(state: RoomState, bot_id: str) -> bool:
    """Whether anyone but the bot is from a server other than the creator's. Room ids from
    version 12 on name no server, so the creator is the room's home; unknown, the room seals."""
    if state.creator is None:
        return True
    home = state.creator.partition(":")[2]
    return any(
        member != bot_id and member.partition(":")[2] != home for member in room_participants(state)
    )


def ambient_digest(messages: tuple[str, ...]) -> str:
    return "\n".join(messages[-AMBIENT_DIGEST_LIMIT:])


def inbound_message_from_event(room_id: str, event: SyncEvent) -> InboundMessage | None:
    if event.type != MESSAGE_TYPE or event.sender is None:
        return None
    return InboundMessage(
        room_id=room_id,
        event_id=event.event_id,
        sender=event.sender,
        content=MessageContent.model_validate(event_content(event)),
    )


def inbound_messages_from_events(
    room_id: str, events: tuple[SyncEvent, ...]
) -> tuple[InboundMessage, ...]:
    return tuple(
        message
        for event in events
        if (message := inbound_message_from_event(room_id, event)) is not None
    )


def encrypted_room_events(
    events: tuple[SyncEvent, ...],
) -> tuple[tuple[SyncEvent, EncryptedContent], ...]:
    """The room events the surface cannot read as sent: megolm ciphertexts, each paired with the
    content that names the session able to open it. Olm-encrypted room events are not a thing the
    surface speaks, and unknown algorithms are the server's problem, not ours."""
    pairs = []
    for event in events:
        if event.type != ENCRYPTED_MESSAGE_TYPE or event.sender is None:
            continue
        content = EncryptedContent.model_validate(event_content(event))
        if content.algorithm == MEGOLM_ALGORITHM:
            pairs.append((event, content))
    return tuple(pairs)


def inbound_message_from_decrypted(
    room_id: str, event: SyncEvent, payload: dict[str, object]
) -> InboundMessage | None:
    """One decrypted megolm payload as the message the rest of the surface already knows: the
    payload is whatever the sender encrypted — an `m.room.message`-shaped dict — and anything
    that does not validate as one is a message the surface skips."""
    if event.sender is None:
        return None
    return InboundMessage(
        room_id=room_id,
        event_id=event.event_id,
        sender=event.sender,
        content=MessageContent.model_validate(payload),
    )


def question_lines(question: AskUserInput) -> tuple[str, ...]:
    lines = [question.title]
    for index, item in enumerate(question.questions, start=1):
        lines.append(f"{index}. {item.question}")
        if item.options is not None and item.free_text_only is not True:
            for number, option in enumerate(item.options, start=1):
                detail = f" — {option.description}" if option.description else ""
                lines.append(f"   {number}) {option.label}{detail}")
            lines.append("Reply with your choice.")
        else:
            lines.append("Reply with your answer.")
    return tuple(lines)


def connect_notice(request: ConnectRequest, home: str | None) -> str:
    where = f" Open {home}" if home else " Open the portal"
    return f"To connect {request.provider}{where} and approve the request."


def credential_notice(request: CredentialRequest, home: str | None) -> str:
    where = f" {home}" if home else ""
    return f"Private input needed: {request.reason}. Send the values in the portal{where}."


def render_terminal(writeback: Writeback, home: str | None) -> str:
    parts = [writeback.terminal.text]
    terminal = writeback.terminal
    if terminal.question is not None:
        parts.append("\n".join(question_lines(terminal.question)))
    if terminal.connect_request is not None:
        parts.append(connect_notice(terminal.connect_request, home))
    if terminal.credential_request is not None:
        parts.append(credential_notice(terminal.credential_request, home))
    return "\n\n".join(part for part in parts if part)
