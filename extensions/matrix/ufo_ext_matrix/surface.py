import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from ufo.sdk.o11y import log, log_error, warn
from ufo.sdk.surfaces import (
    AMBIENT_HISTORY_MESSAGES,
    NOTHING_DELIVERED,
    WORKSPACE_WRITE_MAX_BYTES,
    AmbientMessage,
    BlobStore,
    MidTurnReply,
    NothingDelivered,
    SurfaceContext,
    SurfaceDeliveryError,
    SurfaceListenerContext,
    TurnContext,
    Writeback,
    fence_member_message,
    inbox_name,
    mint_marker,
    writeback_says_nothing,
)
from ufo_ext_matrix.client import MatrixApiError, MatrixClient, deploy_settings
from ufo_ext_matrix.crypto import (
    E2EE_AVAILABLE,
    CryptoRuntime,
    MatrixNoDevices,
    OutboundCrypto,
)
from ufo_ext_matrix.media import decrypt_attachment, encrypt_attachment
from ufo_ext_matrix.wire import (
    ATTACH_TXN_PREFIX,
    ENCRYPTED_MESSAGE_TYPE,
    MAX_ARTIFACT_UPLOAD_BYTES,
    MEGOLM_ALGORITHM,
    OLM_ALGORITHM,
    POST_TXN_PREFIX,
    ROOM_KEY_EVENT_TYPE,
    SPEAK_TXN_PREFIX,
    EncryptedContent,
    InboundMessage,
    MessageContent,
    RoomState,
    SyncBatch,
    SyncEvent,
    SyncRoom,
    ToDeviceEvent,
    ambient_digest,
    amend_room_state,
    audience_for,
    encrypted_room_events,
    event_content,
    inbound_message_from_decrypted,
    inbound_message_from_event,
    inbound_messages_from_events,
    is_direct_message,
    matrix_permalink,
    mentions_bot,
    proof_matches,
    render_terminal,
    room_label,
    room_state_events,
    room_state_from_events,
    sender_display_name,
)

INBOUND_UPLOAD_REL = "uploads"
FILE_MESSAGE_TYPES = frozenset({"m.image", "m.file", "m.audio", "m.video"})
SYNC_RETRY_FALLBACK_SECONDS = 5
SYNC_RETRY_CAP_SECONDS = 60
REJOIN_COOLDOWN_SECONDS = 60

_boot_store: BlobStore | None = None
_runtime: asyncio.Task | None = None
_e2ee_warned = False


def matrix_boot(store: BlobStore) -> None:
    """The fleet store the surface keeps its crypto state under, stashed for the runtime the
    listener and the deliveries share. An unkeyed deploy stashes nothing and runs as the
    plaintext surface this always was."""
    global _boot_store
    try:
        deploy_settings()
    except ValueError:
        return
    _boot_store = store


async def e2ee_runtime() -> CryptoRuntime | None:
    """The process's one crypto identity, built once on first use and awaited by everything
    after. None is a plain surface: no backend installed, or no fleet store stashed."""
    global _runtime
    if not E2EE_AVAILABLE or _boot_store is None:
        return None
    if _runtime is None:
        settings = deploy_settings()
        _runtime = asyncio.create_task(CryptoRuntime.load(_boot_store, settings.bot_token))
    return await _runtime


def _warn_e2ee_unavailable() -> None:
    global _e2ee_warned
    if not _e2ee_warned:
        _e2ee_warned = True
        warn("matrix.e2ee_unavailable")


async def _consume_to_device(runtime: CryptoRuntime, events: tuple[ToDeviceEvent, ...]) -> None:
    """The account's private channel, read before any room: room keys arrive olm-encrypted here,
    and a room event is only decryptable if its key landed first."""
    for event in events:
        if event.type != ENCRYPTED_MESSAGE_TYPE:
            continue
        content = event_content(event)
        if content.get("algorithm") != OLM_ALGORITHM:
            continue
        sender_key = content.get("sender_key")
        ciphertext = content.get("ciphertext")
        addressed = ciphertext.get(runtime.curve25519) if isinstance(ciphertext, dict) else None
        if (
            not isinstance(sender_key, str)
            or not isinstance(addressed, dict)
            or not isinstance(addressed.get("type"), int)
            or not isinstance(addressed.get("body"), str)
        ):
            continue
        payload = await runtime.decrypt_olm(
            sender_key, addressed["type"], addressed["body"]
        )
        if payload is None:
            warn("matrix.to_device_undecryptable", sender_key=sender_key)
            continue
        if payload.get("type") == ROOM_KEY_EVENT_TYPE and isinstance(
            payload.get("content"), dict
        ):
            await runtime.store_room_key(payload["content"])


async def _room_encrypted(
    runtime: CryptoRuntime, client: MatrixClient, room_id: str
) -> bool:
    if room_id in runtime.encrypted_rooms:
        return True
    algorithm = await client.room_encryption(room_id)
    if algorithm == MEGOLM_ALGORITHM:
        runtime.encrypted_rooms.add(room_id)
        return True
    return False


async def _send_room_message(
    client: MatrixClient, room_id: str, txn_id: str, payload: dict[str, object]
) -> str:
    """One turn message into its room: megolm where the room is encrypted, plaintext where it is
    not, and never plaintext into an encrypted room — a room that reads encrypted with no
    runtime to speak it skips the message instead of leaking it."""
    runtime = await e2ee_runtime()
    if runtime is None:
        if await client.room_encryption(room_id) == MEGOLM_ALGORITHM:
            _warn_e2ee_unavailable()
            raise SurfaceDeliveryError(f"room {room_id} is encrypted and no backend is installed")
        return await client.send(room_id, txn_id, payload)
    if await _room_encrypted(runtime, client, room_id):
        return await OutboundCrypto(client, runtime).send(room_id, txn_id, payload)
    return await client.send(room_id, txn_id, payload)


def _media_message_type(media_type: str) -> str:
    match media_type.partition("/")[0]:
        case "image":
            return "m.image"
        case "video":
            return "m.video"
        case "audio":
            return "m.audio"
        case _:
            return "m.file"


def _delivery_error(error: MatrixApiError) -> SurfaceDeliveryError:
    return SurfaceDeliveryError(str(error), retry_after_seconds=error.retry_after_seconds)


@dataclass(frozen=True)
class _RoomWatch:
    state: RoomState
    history: tuple[AmbientMessage, ...] = ()


@dataclass(frozen=True)
class _InboundFile:
    key: str
    line: str


def _push_history(
    history: tuple[AmbientMessage, ...], message: InboundMessage, bot_id: str
) -> tuple[AmbientMessage, ...]:
    entry = AmbientMessage(
        speaker=message.sender, text=message.content.body, own=message.sender == bot_id
    )
    return (*history, entry)[-AMBIENT_HISTORY_MESSAGES:]


def _observed(watches: dict[str, _RoomWatch], batch: SyncBatch) -> dict[str, _RoomWatch]:
    observed = dict(watches)
    for room_id, room in batch.rooms.join.items():
        current = observed.get(room_id)
        state = room_state_events((*room.state.events, *room.timeline.events))
        if current is None:
            observed[room_id] = _RoomWatch(state=room_state_from_events(room_id, state))
        else:
            observed[room_id] = _RoomWatch(
                state=amend_room_state(current.state, state), history=current.history
            )
    for room_id in batch.rooms.leave:
        observed.pop(room_id, None)
    return observed


async def matrix_post(ctx: SurfaceContext, writeback: Writeback) -> str | NothingDelivered:
    """A finished turn into its room: one message under the turn's own transaction id, so the
    delivery that crashes and re-drives finds the event it already made instead of sending a
    second."""
    if writeback_says_nothing(writeback):
        return NOTHING_DELIVERED
    client = MatrixClient(deploy_settings())
    try:
        return await _send_room_message(
            client,
            writeback.queue_key,
            f"{POST_TXN_PREFIX}{writeback.turn_id.hex}",
            {"msgtype": "m.text", "body": render_terminal(writeback, ctx.home_url())},
        )
    except MatrixApiError as error:
        raise _delivery_error(error) from error
    except MatrixNoDevices as error:
        warn("matrix.send_skipped_no_devices", room_id=writeback.queue_key)
        raise SurfaceDeliveryError(str(error)) from error
    finally:
        await client.aclose()


async def matrix_attach(ctx: SurfaceContext, writeback: Writeback, reply_ref: str) -> None:
    """The turn's files into its room, one message apiece, in order: each upload and send runs
    under the artifact's own transaction id, so a redriven delivery reuses the event it already
    made, and a file the homeserver rejects costs that file while the rest still land. Into an
    encrypted room each file travels encrypted — ciphertext on the media repo, the key inside
    the megolm payload."""
    files = tuple(artifact for artifact in writeback.artifacts if artifact.role == "file")
    if not files:
        return
    client = MatrixClient(deploy_settings())
    try:
        runtime = await e2ee_runtime()
        room_id = writeback.queue_key
        if runtime is None and await client.room_encryption(room_id) == MEGOLM_ALGORITHM:
            _warn_e2ee_unavailable()
            return
        encrypted = runtime is not None and await _room_encrypted(runtime, client, room_id)
        for artifact in files:
            if artifact.size_bytes > MAX_ARTIFACT_UPLOAD_BYTES:
                warn(
                    "matrix.attach_skipped",
                    filename=artifact.filename,
                    size_bytes=artifact.size_bytes,
                )
                continue
            try:
                buffer = bytearray()
                async for chunk in ctx.blob.get_stream(artifact.blob_key):
                    buffer.extend(chunk)
                data = bytes(buffer)
                content: dict[str, object] = {
                    "msgtype": _media_message_type(artifact.media_type),
                    "body": artifact.filename,
                    "info": {"mimetype": artifact.media_type, "size": artifact.size_bytes},
                }
                if encrypted and runtime is not None:
                    ciphertext, file_dict = encrypt_attachment(data)
                    content_uri = await client.upload_media(
                        ciphertext, "application/octet-stream", artifact.filename
                    )
                    content["file"] = {**file_dict, "url": content_uri}
                else:
                    content["url"] = await client.upload_media(
                        data, artifact.media_type, artifact.filename
                    )
                await client.send(
                    writeback.queue_key,
                    f"{ATTACH_TXN_PREFIX}{artifact.id.hex}",
                    content,
                )
            except MatrixApiError as error:
                warn(
                    "matrix.attach_failed",
                    filename=artifact.filename,
                    error_class=type(error).__name__,
                )
    finally:
        await client.aclose()


async def matrix_speak(ctx: SurfaceContext, mid: MidTurnReply) -> str:
    """One line from a running turn, sent under the reply's own transaction id for the same reason
    post is."""
    client = MatrixClient(deploy_settings())
    try:
        return await _send_room_message(
            client,
            mid.queue_key,
            f"{SPEAK_TXN_PREFIX}{mid.id.hex}",
            {"msgtype": "m.text", "body": mid.text},
        )
    except MatrixApiError as error:
        raise _delivery_error(error) from error
    except MatrixNoDevices as error:
        warn("matrix.speak_skipped_no_devices", room_id=mid.queue_key)
        raise SurfaceDeliveryError(str(error)) from error
    finally:
        await client.aclose()


async def matrix_listener(listener: SurfaceListenerContext) -> None:
    """The deploy's Matrix stream: one /sync long-poll held for the listener's whole life. Each
    batch re-observes the rooms it carries; the account's private channel is read before the
    rooms, so a room key lands before the event it opens; a room speaks under the workspace whose
    claim answers its address; an unproved claim stays inert until its code arrives in the room; a
    room that loses the bot wins it back once a claim still stands for it. The first batch of a
    listener's life replays each room's recent timeline, so it admits only what addresses the bot,
    keyed on the event id a turn already answered. An event the account cannot decrypt is skipped
    with a warn and never parks the listener. Transient homeserver trouble waits the server's own
    said-so and re-polls the same batch; a message the server refuses for good is skipped; a token
    the server refuses parks the listener."""
    settings = deploy_settings()
    client = MatrixClient(settings)
    try:
        bot_id = await client.whoami()
        runtime = await e2ee_runtime()
        watches: dict[str, _RoomWatch] = {}
        rejoined_until: dict[str, datetime] = {}
        since: str | None = None
        while True:
            try:
                batch = await client.sync(since)
                if runtime is not None:
                    await _consume_to_device(runtime, batch.to_device.events)
                    await runtime.publish(
                        client, bot_id, batch.device_one_time_keys_count.get("signed_curve25519")
                    )
                observed = _observed(watches, batch)
                if runtime is not None:
                    runtime.encrypted_rooms.update(
                        room_id
                        for room_id, watch in observed.items()
                        if watch.state.encryption == MEGOLM_ALGORITHM
                    )
                for room_id in (*batch.rooms.invite, *batch.rooms.leave):
                    await _join_when_claimed(listener, client, room_id, rejoined_until)
                for room_id, room in batch.rooms.join.items():
                    observed[room_id] = await _deliver_batch(
                        listener,
                        client,
                        bot_id,
                        settings.bot_token,
                        runtime,
                        room,
                        observed[room_id],
                        replay=since is None,
                    )
            except MatrixApiError as error:
                seconds = error.retry_after_seconds or SYNC_RETRY_FALLBACK_SECONDS
                warn(
                    "matrix.listener_wait",
                    error_class=type(error).__name__,
                    http_status=error.status,
                )
                await asyncio.sleep(min(seconds, SYNC_RETRY_CAP_SECONDS))
                continue
            watches = observed
            since = batch.next_batch
    except Exception as error:
        log_error("matrix.listener_bailed", error_class=type(error).__name__)
        raise
    finally:
        await client.aclose()


async def _inbound_messages(
    runtime: CryptoRuntime | None, room_id: str, events: tuple[SyncEvent, ...]
) -> tuple[InboundMessage, ...]:
    """The batch's messages in timeline order, plaintext and decrypted side by side: an event the
    account cannot open is a warn and a skip, never a park and never a second path."""
    if runtime is None:
        if encrypted_room_events(events):
            _warn_e2ee_unavailable()
        return inbound_messages_from_events(room_id, events)
    messages = []
    for event in events:
        if event.type == ENCRYPTED_MESSAGE_TYPE:
            content = EncryptedContent.model_validate(event_content(event))
            if content.algorithm != MEGOLM_ALGORITHM:
                continue
            payload = await runtime.decrypt_megolm(
                room_id, content.session_id or "", content.ciphertext
            )
            if payload is None:
                warn(
                    "matrix.message_undecryptable",
                    room_id=room_id,
                    event_id=event.event_id,
                    session_id=content.session_id,
                )
                continue
            message = inbound_message_from_decrypted(room_id, event, payload)
        else:
            message = inbound_message_from_event(room_id, event)
        if message is not None:
            messages.append(message)
    return tuple(messages)


async def _join_when_claimed(
    listener: SurfaceListenerContext,
    client: MatrixClient,
    room_id: str,
    rejoined_until: dict[str, datetime],
) -> None:
    now = datetime.now(UTC)
    until = rejoined_until.get(room_id)
    if until is not None and until > now:
        return
    if not await _claim_stands(listener, room_id):
        return
    try:
        await client.join(room_id)
    except MatrixApiError as error:
        rejoined_until[room_id] = now + timedelta(seconds=REJOIN_COOLDOWN_SECONDS)
        warn("matrix.join_failed", room_id=room_id, error_class=type(error).__name__)
    else:
        rejoined_until.pop(room_id, None)


async def _claim_stands(listener: SurfaceListenerContext, room_id: str) -> bool:
    async with listener.addressed(room_id) as ctx:
        return ctx is not None


async def _deliver_batch(
    listener: SurfaceListenerContext,
    client: MatrixClient,
    bot_id: str,
    bot_token: str,
    runtime: CryptoRuntime | None,
    room: SyncRoom,
    watch: _RoomWatch,
    *,
    replay: bool,
) -> _RoomWatch:
    room_id = watch.state.id
    messages = await _inbound_messages(runtime, room_id, room.timeline.events)
    if not messages:
        return watch
    async with listener.addressed(room_id) as ctx:
        if ctx is None:
            return watch
        claim = await ctx.address_claim(room_id)
        proved = (
            claim is not None
            and claim.proved_by is not None
            and claim.proved_by not in {message.event_id for message in messages}
        )
        history = watch.history
        for message in messages:
            prior = history
            history = _push_history(history, message, bot_id)
            if message.sender == bot_id or claim is None:
                continue
            if message.event_id == claim.proved_by:
                proved = True
                continue
            if not proved:
                if (
                    claim.proved_by is None
                    and claim.claim_expires_at is not None
                    and claim.claim_expires_at > datetime.now(UTC)
                    and proof_matches(message.content.body, bot_token, room_id, claim.member_id)
                ):
                    await ctx.confirm_address(room_id, message.event_id)
                    await ctx.link_member_id(message.sender, claim.member_id)
                    log("matrix.room_proved", room_id=room_id, event_id=message.event_id)
                    proved = True
                continue
            try:
                await _admit_message(ctx, client, bot_id, message, watch.state, prior, replay)
            except MatrixApiError as error:
                if error.transient:
                    raise
                warn(
                    "matrix.message_skipped",
                    room_id=room_id,
                    event_id=message.event_id,
                    http_status=error.status,
                )
    return _RoomWatch(state=watch.state, history=history)


async def _admit_message(
    ctx: SurfaceContext,
    client: MatrixClient,
    bot_id: str,
    message: InboundMessage,
    state: RoomState,
    prior_history: tuple[AmbientMessage, ...],
    replay: bool,
) -> None:
    content = message.content
    if not content.body and content.url is None:
        return
    addressed = is_direct_message(state, message.sender, bot_id) or mentions_bot(content, bot_id)
    if not addressed and (
        replay
        or not await ctx.ambient_reply_wanted(
            AmbientMessage(speaker=message.sender, text=content.body),
            prior_history,
        )
    ):
        return
    speaker = await ctx.linked_member(message.sender)
    audience = audience_for(state, message.sender, bot_id, speaker)
    conversation_id = await ctx.conversation_for(message.room_id, audience, label=room_label(state))
    inbound = await _collect_inbound_file(ctx, client, conversation_id, content)
    ambient = ""
    if not addressed:
        ambient = ambient_digest(
            tuple(
                f"{sender_display_name(state, entry.speaker)}: {entry.text}"
                for entry in prior_history
                if entry.text
            )
        )
    fenced = fence_member_message(
        mint_marker(), ambient, content.body, inbound.line if inbound is not None else ""
    )
    admitted = await ctx.admit(
        conversation_id,
        fenced,
        idempotency_key=message.event_id,
        context=TurnContext(
            sender=sender_display_name(state, message.sender),
            source=matrix_permalink(message.room_id, message.event_id),
        ),
        speaker_member_id=speaker,
    )
    if admitted.opened_run and inbound is not None:
        await ctx.attach_member_files(admitted.turn_id, (inbound.key,), member_id=speaker)


async def _collect_inbound_file(
    ctx: SurfaceContext,
    client: MatrixClient,
    conversation_id: UUID,
    content: MessageContent,
) -> _InboundFile | None:
    if content.msgtype not in FILE_MESSAGE_TYPES:
        return None
    if content.info is not None and (content.info.size or 0) > WORKSPACE_WRITE_MAX_BYTES:
        warn("matrix.inbound_file_skipped", size_bytes=content.info.size)
        return None
    filename = content.body or "file"
    if content.info is not None and content.info.filename:
        filename = content.info.filename
    if content.file is not None:
        ciphertext = bytearray()
        async for chunk in client.download_media(content.file.url):
            ciphertext.extend(chunk)
            if len(ciphertext) > WORKSPACE_WRITE_MAX_BYTES:
                warn("matrix.inbound_file_skipped", size_bytes=len(ciphertext))
                return None
        try:
            data = decrypt_attachment(bytes(ciphertext), content.file.model_dump())
        except ValueError:
            warn("matrix.inbound_file_tampered", filename=filename)
            return None
        key = await ctx.store_inbound_file(filename, _chunks(data))
    else:
        if content.url is None:
            return None
        key = await ctx.store_inbound_file(filename, client.download_media(content.url))
    rel = f"{INBOUND_UPLOAD_REL}/{inbox_name(filename, set())}"
    await ctx.deliver_attachment(conversation_id, key, rel)
    return _InboundFile(key=key, line=rel)


async def _chunks(data: bytes) -> AsyncIterator[bytes]:
    yield data
