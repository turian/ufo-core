from uuid import uuid4

from ufo_ext_matrix.wire import (
    AMBIENT_DIGEST_LIMIT,
    MessageContent,
    RoomState,
    SyncBatch,
    SyncEvent,
    ambient_digest,
    amend_room_state,
    any_participant_is_foreign,
    audience_for,
    claim_proof_code,
    inbound_messages_from_events,
    is_direct_message,
    matrix_permalink,
    mentions_bot,
    pickle_key,
    proof_matches,
    render_terminal,
    room_key,
    room_label,
    room_participants,
    room_state_events,
    room_state_from_events,
)

from ufo.schema.records import (
    AskQuestion,
    AskUserInput,
    ConnectRequest,
    CredentialPrompt,
    CredentialRequest,
    QuestionOption,
    TerminalFrame,
)
from ufo.sdk.audience import (
    conversation_audience,
    foreign_room_audience,
    room_audience,
)
from ufo.sdk.surfaces import Writeback

BOT_ID = "@ufo:hs.org"
MEMBER = uuid4()
OTHER = uuid4()


def _event(
    event_id: str, event_type: str, sender: str | None = None, **content: object
) -> SyncEvent:
    return SyncEvent(
        event_id=event_id,
        type=event_type,
        sender=sender,
        state_key=sender,
        origin_server_ts=1,
        content=content,
    )


def _dm_state(*extra: SyncEvent) -> RoomState:
    return room_state_from_events(
        "!room:hs.org",
        (
            _event("e-create", "m.room.create", "@alice:hs.org"),
            *extra,
            _event("e-bot", "m.room.member", BOT_ID, membership="join"),
        ),
    )


def test_proof_code_is_deterministic_and_bounded() -> None:
    first = claim_proof_code("token", "!room:hs.org", MEMBER)
    again = claim_proof_code("token", "!room:hs.org", MEMBER)
    assert first == again
    assert len(first) == 8
    assert set(first) <= set("abcdefghijklmnopqrstuvwxyz234567")
    assert first != claim_proof_code("token", "!room:hs.org", OTHER)
    assert first != claim_proof_code("token", "!other:hs.org", MEMBER)
    assert first != claim_proof_code("other-token", "!room:hs.org", MEMBER)


def test_pickle_key_is_deterministic_and_keyed() -> None:
    assert pickle_key("token") == pickle_key("token")
    assert len(pickle_key("token")) == 32
    assert pickle_key("token") != pickle_key("other-token")
    assert (
        pickle_key("test-bot-token").hex()
        == "bdf238a77af61ce8aebcc5ad44f90f3bb05debbc391205bfa6d6176f55b308ca"
    )


def test_proof_never_matches_a_fragment_or_wrong_proof() -> None:
    code = claim_proof_code("token", "!room:hs.org", MEMBER)
    foreign = claim_proof_code("token", "!room:hs.org", OTHER)
    assert proof_matches(code, "token", "!room:hs.org", MEMBER)
    assert proof_matches(code.upper(), "token", "!room:hs.org", MEMBER)
    assert proof_matches(f"please join {code} thanks", "token", "!room:hs.org", MEMBER)
    assert proof_matches(f"{foreign} {code}", "token", "!room:hs.org", MEMBER)
    assert not proof_matches(f"x{code}", "token", "!room:hs.org", MEMBER)
    assert not proof_matches(code[:7], "token", "!room:hs.org", MEMBER)
    assert not proof_matches(foreign, "token", "!room:hs.org", MEMBER)
    assert not proof_matches("hello world", "token", "!room:hs.org", MEMBER)


def test_room_key_and_permalink_encode_the_colons() -> None:
    assert room_key("!abc:matrix.org") == "!abc%3Amatrix.org"
    assert (
        matrix_permalink("!abc:matrix.org", "$e123")
        == "https://matrix.to/#/%21abc%3Amatrix.org/%24e123"
    )


def test_sync_batch_defaults_and_events() -> None:
    batch = SyncBatch.model_validate({"next_batch": "tok"})
    assert batch.next_batch == "tok"
    assert batch.rooms.join == {}
    event = _event("$e1", "m.room.message", "@alice:hs.org", body="hi").model_dump()
    payload = {
        "next_batch": "t2",
        "rooms": {
            "invite": {"!inv:hs.org": {"invite_state": {"events": [event]}}},
            "join": {"!r:hs.org": {"timeline": {"events": [event]}}},
            "leave": {"!old:hs.org": {"timeline": {"events": ()}}},
        },
    }
    parsed = SyncBatch.model_validate(payload)
    assert set(parsed.rooms.invite) == {"!inv:hs.org"}
    assert parsed.rooms.join["!r:hs.org"].timeline.events[0].event_id == "$e1"
    assert set(parsed.rooms.leave) == {"!old:hs.org"}


def test_room_state_tracks_memberships_displaynames_and_names_latest_wins() -> None:
    state = room_state_from_events(
        "!room:hs.org",
        (
            _event("e1", "m.room.member", "@alice:hs.org", membership="join", displayname="Alice"),
            _event("e2", "m.room.name", None, name="Ops"),
            _event("e3", "m.room.canonical_alias", None, alias="#ops:hs.org"),
            _event("e4", "m.room.member", "@alice:hs.org", membership="invite"),
            _event("e5", "m.room.member", "@carl:hs.org", membership="join"),
            _event("e6", "m.room.message", "@alice:hs.org", body="noise"),
        ),
    )
    assert room_participants(state) == {"@alice:hs.org", "@carl:hs.org"}
    assert state.displaynames["@alice:hs.org"] == "Alice"
    assert state.name == "Ops"
    assert state.alias == "#ops:hs.org"
    assert room_label(state) == "#ops:hs.org"
    renamed = amend_room_state(state, (_event("e7", "m.room.name", None, name="On-call"),))
    assert renamed.name == "On-call"
    assert state.name == "Ops"


def test_room_state_events_keeps_only_state_types() -> None:
    events = (
        _event("e1", "m.room.member", "@alice:hs.org", membership="join"),
        _event("e2", "m.room.message", "@alice:hs.org", body="hi"),
        _event("e3", "m.reaction", "@alice:hs.org"),
        _event("e4", "m.room.name", None, name="N"),
    )
    assert room_state_events(events) == (events[0], events[3])


def test_direct_message_is_the_two_of_them() -> None:
    state = _dm_state(_event("e2", "m.room.member", "@alice:hs.org", membership="join"))
    assert is_direct_message(state, "@alice:hs.org", BOT_ID)
    grouped = amend_room_state(
        state, (_event("e3", "m.room.member", "@bob:hs.org", membership="join"),)
    )
    assert not is_direct_message(grouped, "@alice:hs.org", BOT_ID)


def test_mentions_need_the_pill_never_the_word() -> None:
    word = MessageContent(body=f"{BOT_ID} hi")
    assert not mentions_bot(word, BOT_ID)
    pill = MessageContent(
        body="hi",
        formatted_body=f'<a href="https://matrix.to/#/{BOT_ID}">@ufo</a> hi',
    )
    assert mentions_bot(pill, BOT_ID)
    other = MessageContent(formatted_body="https://matrix.to/#/@notbot:hs.org")
    assert not mentions_bot(other, BOT_ID)
    encoded = MessageContent(formatted_body='<a href="https://matrix.to/#/%40ufo%3Ahs.org">ufo</a>')
    assert mentions_bot(encoded, BOT_ID)
    ported = MessageContent(
        formatted_body='<a href="https://matrix.to/#/@ufo:localhost:8008?via=x">ufo</a>'
    )
    assert mentions_bot(ported, "@ufo:localhost:8008")
    assert not mentions_bot(ported, "@ufo:localhost")
    structured = MessageContent.model_validate(
        {"msgtype": "m.text", "body": "hi", "m.mentions": {"user_ids": [BOT_ID]}}
    )
    assert mentions_bot(structured, BOT_ID)
    assert not mentions_bot(MessageContent.model_validate({"m.mentions": {}}), BOT_ID)


def test_audience_splits_dm_room_and_foreign() -> None:
    dm = _dm_state(_event("t2", "m.room.member", "@alice:hs.org", membership="join"))
    assert audience_for(dm, "@alice:hs.org", BOT_ID, MEMBER) == conversation_audience(MEMBER)
    room = amend_room_state(dm, (_event("t3", "m.room.member", "@bob:hs.org", membership="join"),))
    assert audience_for(room, "@alice:hs.org", BOT_ID, MEMBER) == room_audience(
        "matrix", room_key("!room:hs.org")
    )
    foreign = amend_room_state(
        room, (_event("t4", "m.room.member", "@bob:other.org", membership="join"),)
    )
    assert audience_for(foreign, "@alice:hs.org", BOT_ID, MEMBER) == foreign_room_audience(
        "matrix", room_key("!room:hs.org")
    )
    assert not any_participant_is_foreign(dm, BOT_ID)
    assert any_participant_is_foreign(foreign, BOT_ID)


def test_foreign_follows_the_creator_server_not_the_room_id() -> None:
    joins = (
        _event("m1", "m.room.member", BOT_ID, membership="join"),
        _event("m2", "m.room.member", "@alice:hs.org:8448", membership="join"),
    )
    serverless = "!Xq3mR8vTn2LpW5yKd7HcJ4sBfZ6gNe9uA1oEiUwQtVr"
    created = room_state_from_events(
        serverless, (_event("c", "m.room.create", "@alice:hs.org:8448"), *joins)
    )
    assert not any_participant_is_foreign(created, BOT_ID)
    visited = amend_room_state(
        created, (_event("m3", "m.room.member", "@bob:hs.org", membership="invite"),)
    )
    assert any_participant_is_foreign(visited, BOT_ID)
    assert any_participant_is_foreign(room_state_from_events(serverless, joins), BOT_ID)


def test_ambient_digest_keeps_the_tail() -> None:
    lines = tuple(f"line {index}" for index in range(AMBIENT_DIGEST_LIMIT * 2))
    assert ambient_digest(lines) == "\n".join(lines[-AMBIENT_DIGEST_LIMIT:])


def test_inbound_messages_take_only_room_messages() -> None:
    events = (
        _event("$a", "m.room.message", "@alice:hs.org", body="first"),
        _event("$b", "m.room.member", "@bob:hs.org", membership="join"),
        _event("$c", "m.room.message", "@alice:hs.org", body="second", url="mxc://hs.org/f"),
    )
    messages = inbound_messages_from_events("!room:hs.org", events)
    assert [message.event_id for message in messages] == ["$a", "$c"]
    assert messages[0].sender == "@alice:hs.org"
    assert messages[0].content.body == "first"
    assert messages[1].content.url == "mxc://hs.org/f"


def _writeback(terminal: TerminalFrame) -> Writeback:
    return Writeback(
        turn_id=uuid4(),
        conversation_id=uuid4(),
        agent_id=uuid4(),
        queue_key="!room:hs.org",
        terminal=terminal,
        artifacts=(),
        speaker_member_id=MEMBER,
    )


def test_render_terminal_writes_the_words_and_the_question() -> None:
    assert (
        render_terminal(_writeback(TerminalFrame(status="done", text="done")), "https://portal")
        == "done"
    )
    question = TerminalFrame(
        status="done",
        text="pick one",
        question=AskUserInput(
            title="Pick a plan",
            questions=(
                AskQuestion(
                    question="Which plan?",
                    options=(QuestionOption(label="Small"), QuestionOption(label="Large")),
                ),
            ),
        ),
    )
    assert render_terminal(_writeback(question), "https://portal") == (
        "pick one\n\nPick a plan\n1. Which plan?\n   1) Small\n   2) Large\nReply with your choice."
    )


def test_render_terminal_writes_the_private_requests() -> None:
    handoff = TerminalFrame(
        status="done",
        text="waiting",
        credential_request=CredentialRequest(
            reason="postgres password",
            prompts=(CredentialPrompt(slot="PG_PASSWORD", prompt="Password"),),
            sealed="seal",
        ),
        connect_request=ConnectRequest(provider="github", requester_member_id=MEMBER),
    )
    rendered = render_terminal(_writeback(handoff), "https://portal")
    assert "Private input needed: postgres password." in rendered
    assert "Send the values in the portal https://portal." in rendered
    assert "To connect github Open https://portal and approve the request." in rendered
