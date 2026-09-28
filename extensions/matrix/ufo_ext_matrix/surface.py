import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from ufo.sdk.o11y import log, log_error, warn
from ufo.sdk.surfaces import (
    AMBIENT_HISTORY_MESSAGES,
    NOTHING_DELIVERED,
    WORKSPACE_WRITE_MAX_BYTES,
    AmbientMessage,
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
from ufo_ext_matrix.wire import (
    ATTACH_TXN_PREFIX,
    MAX_ARTIFACT_UPLOAD_BYTES,
    POST_TXN_PREFIX,
    SPEAK_TXN_PREFIX,
    InboundMessage,
    MessageContent,
    RoomState,
    SyncBatch,
    SyncRoom,
    ambient_digest,
    amend_room_state,
    audience_for,
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
        return await client.send(
            writeback.queue_key,
            f"{POST_TXN_PREFIX}{writeback.turn_id.hex}",
            {"msgtype": "m.text", "body": render_terminal(writeback, ctx.home_url())},
        )
    except MatrixApiError as error:
        raise _delivery_error(error) from error
    finally:
        await client.aclose()


async def matrix_attach(ctx: SurfaceContext, writeback: Writeback, reply_ref: str) -> None:
    """The turn's files into its room, one message apiece, in order: each upload and send runs
    under the artifact's own transaction id, so a redriven delivery reuses the event it already
    made, and a file the homeserver rejects costs that file while the rest still land."""
    files = tuple(artifact for artifact in writeback.artifacts if artifact.role == "file")
    if not files:
        return
    client = MatrixClient(deploy_settings())
    try:
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
                content_uri = await client.upload_media(
                    bytes(buffer), artifact.media_type, artifact.filename
                )
                await client.send(
                    writeback.queue_key,
                    f"{ATTACH_TXN_PREFIX}{artifact.id.hex}",
                    {
                        "msgtype": _media_message_type(artifact.media_type),
                        "body": artifact.filename,
                        "url": content_uri,
                        "info": {"mimetype": artifact.media_type, "size": artifact.size_bytes},
                    },
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
        return await client.send(
            mid.queue_key,
            f"{SPEAK_TXN_PREFIX}{mid.id.hex}",
            {"msgtype": "m.text", "body": mid.text},
        )
    except MatrixApiError as error:
        raise _delivery_error(error) from error
    finally:
        await client.aclose()


async def matrix_listener(listener: SurfaceListenerContext) -> None:
    """The deploy's Matrix stream: one /sync long-poll held for the listener's whole life. Each
    batch re-observes the rooms it carries; a room speaks under the workspace whose claim answers
    its address; an unproved claim stays inert until its code arrives in the room; a room that
    loses the bot wins it back once a claim still stands for it. The first batch of a listener's
    life replays each room's recent timeline, so it admits only what addresses the bot, keyed on
    the event id a turn already answered. Transient homeserver trouble waits the server's own
    said-so and re-polls the same batch; a message the server refuses for good is skipped; a token
    the server refuses parks the listener."""
    settings = deploy_settings()
    client = MatrixClient(settings)
    try:
        bot_id = await client.whoami()
        watches: dict[str, _RoomWatch] = {}
        rejoined_until: dict[str, datetime] = {}
        since: str | None = None
        while True:
            try:
                batch = await client.sync(since)
                observed = _observed(watches, batch)
                for room_id in (*batch.rooms.invite, *batch.rooms.leave):
                    await _join_when_claimed(listener, client, room_id, rejoined_until)
                for room_id, room in batch.rooms.join.items():
                    observed[room_id] = await _deliver_batch(
                        listener,
                        client,
                        bot_id,
                        settings.bot_token,
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
    room: SyncRoom,
    watch: _RoomWatch,
    *,
    replay: bool,
) -> _RoomWatch:
    room_id = watch.state.id
    messages = inbound_messages_from_events(room_id, room.timeline.events)
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
    if content.url is None or content.msgtype not in FILE_MESSAGE_TYPES:
        return None
    if content.info is not None and (content.info.size or 0) > WORKSPACE_WRITE_MAX_BYTES:
        warn("matrix.inbound_file_skipped", size_bytes=content.info.size)
        return None
    filename = content.body or "file"
    if content.info is not None and content.info.filename:
        filename = content.info.filename
    key = await ctx.store_inbound_file(filename, client.download_media(content.url))
    rel = f"{INBOUND_UPLOAD_REL}/{inbox_name(filename, set())}"
    await ctx.deliver_attachment(conversation_id, key, rel)
    return _InboundFile(key=key, line=rel)
