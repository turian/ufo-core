"""The Matrix surface end to end, against a real Synapse homeserver and the repo's real
durability, admission, and delivery seams.

A Synapse container is launched with `docker run` (the same gating pattern as the redis_hub
integration test): registration shared-secret gate, no federation, sqlite. The test registers a
bot and a member user through Synapse's own admin endpoint. The deploy-owned bot credential is
injected by environment (`MATRIX_HOMESERVER`, `MATRIX_BOT_TOKEN`) exactly as a real deploy would,
and the matrix manifest mounts through `_mount_shared_surfaces`, so the listener, the writeback
poller, and the tool dispatch are the production objects — `SurfaceListenerRunner.run`,
`WritebackPoller.run`, and the registry-dispatched `matrix_room_connect` with a real `ToolContext`.

The turn model is scripted (`TestSupport`'s standin pattern): the agent's model id resolves through
the real `ModelRegistry` to a client whose first reply is a `ToolCallStart` of
`matrix_room_connect`, so the claim, the reserve, and the proof code are produced by the real
tool against a real `SurfaceInstallationAccess`.

Flow: a member creates a room in Synapse, asks the agent in chat to connect it, reads the proof
code the tool returns, invites the bot (the listener joins because the claim stands), proves the
room with the code (the listener confirms the address and links the member), then messages the
room: the real listener admits it, the scripted model answers, and the real `matrix_post`
delivery lands the answer in the room, read back over the wire by the member's own client.

`docker`-gated: missing infrastructure fails the required integration gate and skips an optional
local run."""

import asyncio
import hashlib
import hmac
import json
import socket
import subprocess
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import aclosing
from dataclasses import dataclass, field, replace
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from ufo_ext_context_rollover.manifest import manifest as rollover_manifest
from ufo_ext_matrix.client import DeploySettings, MatrixClient
from ufo_ext_matrix.manifest import manifest as matrix_manifest
from ufo_ext_matrix.wire import SyncRooms, claim_proof_code
from ufo_testsupport.invoker import invoker_factory
from ufo_testsupport.plugin import integration_dependency_available
from ufo_testsupport.surfaces import UNREACHED_AMBIENT_REPLY, no_member_skills

from ufo.blob import FilesystemBlobStore, WorkspaceBlobStore
from ufo.config import Config
from ufo.db import workspace_tx
from ufo.harness.durability import replay_safe_client
from ufo.harness.models.catalog import CORE_MODEL_SPECS, CORE_PRICING
from ufo.harness.models.interface import (
    ModelEvent,
    ModelRequest,
    TextDelta,
    ToolCallDelta,
    ToolCallStart,
    ToolResultBlock,
)
from ufo.harness.models.registry import ModelRegistry
from ufo.harness.sandbox.conversation import SANDBOX_IMAGE_REF, ConversationSandbox
from ufo.harness.sandbox.local import LocalCarrier
from ufo.harness.sandbox.session import ProxyEndpoint, RunTokenCodec
from ufo.host.assemble import HostEnvironment
from ufo.host.ext.loader import skill_registry
from ufo.runtime import queue as loop_queue
from ufo.runtime.access.connectors import ConnectorRegistry
from ufo.runtime.ext.surface import SurfaceListenerRunner
from ufo.runtime.hub import InProcessHub, Terminal
from ufo.runtime.runtime_instance import record_fleet_seat
from ufo.runtime.subagents import SubagentRegistry
from ufo.runtime.surfaces.admission import Admission, MemberAdmission
from ufo.runtime.surfaces.hub_tail import tail_frames
from ufo.runtime.workspace import ws
from ufo.schema import tables
from ufo.schema.records import Usage
from ufo.serve import _mount_shared_surfaces

pytestmark = pytest.mark.docker

SYNAPSE_IMAGE = "matrixdotorg/synapse:v1.161.0"
REGISTRATION_SECRET = "ufo-matrix-registration-secret"
READY_TIMEOUT_S = 120.0
TURN_TIMEOUT_S = 120.0
AGENT_MODEL_ID = "claude-opus-4-8"
PIXEL_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class MatrixUser:
    """A homeserver account whose probes follow one `next_batch` token stream — a fresh tokenless
    `/sync` only sets the account's window once and never shows new timeline events after."""

    user_id: str
    token: str
    homeserver: str
    client_: MatrixClient | None = None
    sync_token: str | None = None

    def client(self) -> MatrixClient:
        if self.client_ is None:
            settings = DeploySettings(homeserver=self.homeserver, bot_token=self.token)
            self.client_ = MatrixClient(settings)
        return self.client_

    async def sync_rooms(self) -> SyncRooms:
        batch = await self.client().sync(self.sync_token)
        self.sync_token = batch.next_batch
        return batch.rooms

    async def aclose(self) -> None:
        if self.client_ is not None:
            await self.client_.aclose()


async def _register_user(url: str, username: str) -> tuple[str, str]:
    password = "ufo-matrix-test-password"
    async with httpx.AsyncClient(base_url=url, timeout=30.0) as admin:
        get = await admin.get(
            "/_synapse/admin/v1/register",
            headers={"X-Matrix-Registration-Secret": REGISTRATION_SECRET},
        )
        get.raise_for_status()
        nonce = get.json()["nonce"]
        mac_builder = hmac.new(REGISTRATION_SECRET.encode("utf8"), digestmod=hashlib.sha1)
        mac_builder.update(nonce.encode("utf8"))
        mac_builder.update(b"\x00")
        mac_builder.update(username.encode("utf8"))
        mac_builder.update(b"\x00")
        mac_builder.update(password.encode("utf8"))
        mac_builder.update(b"\x00notadmin")
        post = await admin.post(
            "/_synapse/admin/v1/register",
            json={
                "nonce": nonce,
                "username": username,
                "password": password,
                "mac": mac_builder.hexdigest(),
            },
        )
        post.raise_for_status()
        payload = post.json()
    return payload["user_id"], payload["access_token"]


@pytest.fixture
def synapse(tmp_path: Path) -> Iterator[tuple[MatrixUser, MatrixUser]]:
    if not integration_dependency_available(
        subprocess.run(["docker", "version"], capture_output=True).returncode == 0,
        "Docker executable is not available",
    ):
        pytest.skip("Docker executable is not available")
    port = _free_port()
    data_dir = tmp_path / "synapse-data"
    data_dir.mkdir()
    (data_dir / "homeserver.yaml").write_text(
        f"""
server_name: ufo-matrix-test.local
public_baseurl: http://127.0.0.1:{port}
report_stats: false
pid_file: /data/pid
enable_registration: false
registration_shared_secret: {REGISTRATION_SECRET}
suppress_key_server_warning: true
database:
  name: sqlite3
  args:
    database: /data/postgres.db
media_store_path: /data/media
listeners:
  - port: 8008
    type: http
    bind_addresses: ['0.0.0.0']
    resources:
      - names: [client]
"""
    )
    # The image runs as uid 100; a single-file bind mount makes /data unwritable for
    # it, so the mount is the whole directory, world-writable for the homeserver uid.
    data_dir.chmod(0o777)
    (data_dir / "homeserver.yaml").chmod(0o666)
    started = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "-p",
            f"{port}:8008",
            "-v",
            f"{data_dir}:/data",
            SYNAPSE_IMAGE,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    reason = f"Docker cannot run {SYNAPSE_IMAGE}: {started.stderr.strip()}"
    if not integration_dependency_available(started.returncode == 0, reason):
        pytest.skip(reason)
    container = started.stdout.strip()
    url = f"http://127.0.0.1:{port}"
    bot_user: MatrixUser | None = None
    member_user: MatrixUser | None = None
    try:
        ready = False
        deadline = time.monotonic() + READY_TIMEOUT_S
        with httpx.Client(timeout=5.0) as probe:
            while time.monotonic() < deadline:
                try:
                    ready = probe.get(f"{url}/_matrix/client/versions").status_code == 200
                except httpx.HTTPError:
                    pass
                if ready:
                    break
                time.sleep(1.0)
        if not ready:
            pytest.skip(f"Synapse at {url} did not become ready")
        bot_user = MatrixUser(*asyncio.run(_register_user(url, "ufo")), url)
        member_user = MatrixUser(*asyncio.run(_register_user(url, "member")), url)
        yield bot_user, member_user
    finally:
        subprocess.run(["docker", "stop", container], capture_output=True, check=False)


@dataclass
class ClaimScriptedModel:
    """Round one calls the claim tool; a round carrying a tool result echoes it (the proof code
    leaves that way); a plain message round answers with text."""

    room_id: str
    _tool_result: str | None = field(default=None)

    async def complete(self, request: ModelRequest) -> AsyncIterator[ModelEvent]:
        for message in request.messages:
            if isinstance(message.content, tuple):
                for block in message.content:
                    if isinstance(block, ToolResultBlock) and isinstance(block.content, str):
                        self._tool_result = block.content
        if self._tool_result is not None:
            echo = self._tool_result
            self._tool_result = None
            yield TextDelta(text=echo)
            yield Usage(input_tokens=11, output_tokens=9)
            return
        if self.room_id is not None:
            yield ToolCallStart(id="claim", name="matrix_room_connect")
            yield ToolCallDelta(id="claim", partial_json=json.dumps({"room": self.room_id}))
            self.room_id = None
            yield Usage(input_tokens=11, output_tokens=9)
            return
        yield TextDelta(text="hi there")
        yield Usage(input_tokens=11, output_tokens=9)


@dataclass(frozen=True)
class Seed:
    workspace_id: UUID
    member_id: UUID
    agent_id: UUID
    conversation_id: UUID


async def _seed() -> Seed:
    workspace_id, member_id, agent_id, conversation_id = (uuid4() for _ in range(4))
    async with workspace_tx() as connection:
        await connection.execute(
            sa.insert(tables.workspace).values(
                id=workspace_id, created_at=sa.func.now(), updated_at=sa.func.now()
            )
        )
        await connection.execute(
            sa.insert(tables.member).values(
                id=member_id,
                workspace_id=workspace_id,
                email=f"{member_id.hex[:8]}@example.com",
                is_admin=True,
                created_at=sa.func.now(),
                updated_at=sa.func.now(),
            )
        )
        await connection.execute(
            sa.insert(tables.agent).values(
                id=agent_id,
                workspace_id=workspace_id,
                name="assistant",
                prompt="You are a terse assistant.",
                model=AGENT_MODEL_ID,
                is_main=True,
                created_at=sa.func.now(),
                updated_at=sa.func.now(),
            )
        )
        await connection.execute(
            sa.insert(tables.conversation).values(
                id=conversation_id,
                workspace_id=workspace_id,
                agent_id=agent_id,
                surface="cli",
                queue_key=conversation_id.hex,
                member_id=member_id,
                created_at=sa.func.now(),
                updated_at=sa.func.now(),
            )
        )
    return Seed(workspace_id, member_id, agent_id, conversation_id)


@dataclass
class Stack:
    bot: MatrixUser
    member: MatrixUser
    seed: Seed
    scripted: ClaimScriptedModel
    hub: InProcessHub
    blob: WorkspaceBlobStore
    runners: tuple[SurfaceListenerRunner, ...]
    listeners: list[asyncio.Task[None]]

    async def restart_listeners(self) -> None:
        for task in self.listeners:
            task.cancel()
        await asyncio.gather(*self.listeners, return_exceptions=True)
        self.listeners[:] = [asyncio.create_task(runner.run()) for runner in self.runners]


@pytest.fixture
async def stack(
    synapse: tuple[MatrixUser, MatrixUser],
    db: None,
    dbos_launched: Config,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> AsyncIterator[Stack]:
    bot, member = synapse
    config = dbos_launched
    scripted = ClaimScriptedModel(room_id="")
    registry = ModelRegistry(
        specs={
            spec.id: replace(spec, client=lambda _spec, _key: scripted, key_slot="", key_env="")
            for spec in CORE_MODEL_SPECS
        },
        pricing=CORE_PRICING,
        auto_model=AGENT_MODEL_ID,
    )
    seed = await _seed()
    hub = InProcessHub()
    blob = WorkspaceBlobStore(backend=FilesystemBlobStore(root=config.blob.root))
    runtime_dbos = replay_safe_client(config.database.system_url)
    loop_queue.reset_runtime()
    loop_queue.init_runtime(
        loop_queue.Runtime(
            config=config,
            blob=blob,
            sandboxes=ConversationSandbox(
                carrier=LocalCarrier(),
                backend="local",
                off_cluster=False,
                image_ref=SANDBOX_IMAGE_REF,
                proxy=ProxyEndpoint(port=0, ca_cert="test-ca"),
                workspace_root=tmp_path / "workspaces",
            ),
            hub=hub,
            cdp_provider=None,
            search_provider=None,
            connectors=ConnectorRegistry(entries={}),
            run_tokens=RunTokenCodec(b"matrix-e2e-test-secret"),
            dbos=runtime_dbos,
            invoker_for=invoker_factory(runtime_dbos),
            subagents=SubagentRegistry(()),
            subagent_grants={},
            manifests=(rollover_manifest(), matrix_manifest()),
            environment=HostEnvironment(
                manifests=(rollover_manifest(), matrix_manifest()), credentials=None
            ),
            registry=registry,
            skills=skill_registry(()),
            credentials=None,
            index=None,
            embed=None,
            artifact_token_secret="",
        )
    )
    monkeypatch.setenv("MATRIX_HOMESERVER", bot.homeserver)
    monkeypatch.setenv("MATRIX_BOT_TOKEN", bot.token)
    app = FastAPI()
    app.state.instance_id = uuid4()
    await record_fleet_seat(app.state.instance_id)
    _mount_shared_surfaces(
        app,
        (rollover_manifest(), matrix_manifest()),
        None,
        blob,
        loop_queue._runtime.sandboxes,
        hub,
        runtime_dbos,
        "",
        None,
        None,
        (AGENT_MODEL_ID,),
        ambient_reply=UNREACHED_AMBIENT_REPLY,
        skills=skill_registry(()),
        member_skill_listing=no_member_skills,
    )
    runners = tuple(app.state.surface_listeners)
    listeners = [asyncio.create_task(runner.run()) for runner in runners]
    tasks: list[asyncio.Task[None]] = []
    if app.state.writeback_poller is not None:
        tasks.append(asyncio.create_task(app.state.writeback_poller.run()))
    if app.state.mid_turn_reply_poller is not None:
        tasks.append(asyncio.create_task(app.state.mid_turn_reply_poller.run()))
    yield Stack(bot, member, seed, scripted, hub, blob, runners, listeners)
    for task in (*tasks, *listeners):
        task.cancel()
    await asyncio.gather(*tasks, *listeners, return_exceptions=True)
    await bot.aclose()
    await member.aclose()
    loop_queue.reset_runtime()


async def _create_room(user: MatrixUser) -> str:
    async with httpx.AsyncClient(base_url=user.homeserver, timeout=30.0) as api:
        response = await api.post(
            "/_matrix/client/v3/createRoom",
            headers={"Authorization": f"Bearer {user.token}"},
            json={"preset": "private_chat"},
        )
        response.raise_for_status()
    return response.json()["room_id"]


async def _invite(user: MatrixUser, room_id: str, other: str) -> None:
    async with httpx.AsyncClient(base_url=user.homeserver, timeout=30.0) as api:
        response = await api.post(
            f"/_matrix/client/v3/rooms/{room_id}/invite",
            headers={"Authorization": f"Bearer {user.token}"},
            json={"user_id": other},
        )
        if response.status_code >= 400:
            raise AssertionError(f"invite {response.status_code}: {response.text}")


async def _room_bodies(user: MatrixUser, room_id: str) -> tuple[str, ...]:
    rooms = await user.sync_rooms()
    room = rooms.join.get(room_id)
    if room is None:
        return ()
    return tuple(
        str(event.content["body"])
        for event in room.timeline.events
        if event.type == "m.room.message"
        and isinstance(event.content, dict)
        and "body" in event.content
    )


async def _wait_for(condition, what: str, deadline_s: float) -> None:
    try:
        for _ in range(int(deadline_s)):
            if await condition():
                return
            await asyncio.sleep(1.0)
        raise AssertionError(f"timed out waiting: {what}")
    except AssertionError:
        await _dump_state()
        raise


async def _dump_state() -> None:
    import sys

    out = sys.stderr
    _name = "=== matrix e2e state ==="
    print(_name, file=out, flush=True)
    async with workspace_tx() as connection:
        for table in (
            tables.conversation,
            tables.turn,
            tables.writeback,
            tables.surface_installation,
            tables.surface_address,
            tables.surface_identity,
        ):
            rows = (await connection.execute(table.select())).all()
            for row in rows:
                print(table.name, tuple(row), file=out, flush=True)


async def _address_proven(seed: Seed, room_id: str) -> bool:
    async with workspace_tx() as connection:
        row = (
            await connection.execute(
                sa.select(tables.surface_address.c.proved_by).where(
                    tables.surface_address.c.address == room_id,
                    tables.surface_address.c.workspace_id == seed.workspace_id,
                )
            )
        ).first()
    return row is not None and row[0] is not None


async def test_a_claimed_room_is_proven_and_replies_end_to_end(stack: Stack) -> None:
    script = stack.seed
    room_id = await _create_room(stack.member)
    scripted = stack.scripted
    scripted.room_id = room_id

    admission = Admission(dbos=loop_queue._runtime.dbos, durable_surfaces=frozenset())
    admitted = await MemberAdmission(admission=admission, workspace_id=script.workspace_id).admit(
        script.conversation_id,
        f"connect the matrix room {room_id} for me",
        speaker_member_id=script.member_id,
    )
    deltas: list[str] = []
    terminal: Terminal | None = None
    with ws(script.workspace_id):
        async with aclosing(tail_frames(stack.hub, admitted.turn_id)) as frames:
            async for _cursor, frame in frames:
                match frame:
                    case TextDelta():
                        deltas.append(frame.text)
                    case Terminal() as last:
                        terminal = last
                        break
    assert terminal is not None
    assert terminal.frame.status == "done", terminal.frame.error_message
    expected_code = claim_proof_code(stack.bot.token, room_id, script.member_id)
    assert expected_code in "".join(deltas)

    await _invite(stack.member, room_id, stack.bot.user_id)

    async def _joined() -> bool:
        rooms = await stack.bot.sync_rooms()
        return rooms.join.get(room_id) is not None

    await _wait_for(_joined, "bot joined the room after the invite", TURN_TIMEOUT_S)

    await stack.member.client().send(
        room_id, "ufo-matrix-proof", {"msgtype": "m.text", "body": expected_code}
    )
    await _wait_for(
        lambda: _address_proven(script, room_id), "proof confirmed the address", TURN_TIMEOUT_S
    )

    await stack.member.client().send(
        room_id, "ufo-matrix-hello", {"msgtype": "m.text", "body": "hello from the room"}
    )

    async def _replied() -> bool:
        return "hi there" in await _room_bodies(stack.member, room_id)

    await _wait_for(_replied, "the agent's reply landed in the room", TURN_TIMEOUT_S)


async def _turn_keys(seed: Seed) -> tuple[str, ...]:
    async with workspace_tx() as connection:
        rows = (
            await connection.execute(
                sa.select(tables.turn.c.idempotency_key).where(
                    tables.turn.c.workspace_id == seed.workspace_id,
                    tables.turn.c.idempotency_key.is_not(None),
                )
            )
        ).all()
    return tuple(row[0] for row in rows)


async def _member_file(seed: Seed, event_id: str) -> tuple[str, str, int] | None:
    async with workspace_tx() as connection:
        row = (
            await connection.execute(
                sa.select(
                    tables.shared_artifact.c.blob_key,
                    tables.shared_artifact.c.filename,
                    tables.shared_artifact.c.size_bytes,
                )
                .join(tables.turn, tables.turn.c.id == tables.shared_artifact.c.turn_id)
                .where(
                    tables.turn.c.workspace_id == seed.workspace_id,
                    tables.turn.c.idempotency_key == event_id,
                    tables.shared_artifact.c.attached_by_member.is_(True),
                )
            )
        ).first()
    return None if row is None else (row[0], row[1], row[2])


async def test_a_member_file_lands_and_a_restart_replays_nothing(stack: Stack) -> None:
    script = stack.seed
    room_id = await _create_room(stack.member)
    stack.scripted.room_id = room_id
    admission = Admission(dbos=loop_queue._runtime.dbos, durable_surfaces=frozenset())
    await MemberAdmission(admission=admission, workspace_id=script.workspace_id).admit(
        script.conversation_id,
        f"connect the matrix room {room_id} for me",
        speaker_member_id=script.member_id,
    )
    code = claim_proof_code(stack.bot.token, room_id, script.member_id)

    async def _claimed() -> bool:
        async with workspace_tx() as connection:
            row = (
                await connection.execute(
                    sa.select(tables.surface_address.c.address).where(
                        tables.surface_address.c.address == room_id
                    )
                )
            ).first()
        return row is not None

    await _wait_for(_claimed, "the tool reserved the room", TURN_TIMEOUT_S)
    await _invite(stack.member, room_id, stack.bot.user_id)

    async def _joined() -> bool:
        return (await stack.bot.sync_rooms()).join.get(room_id) is not None

    await _wait_for(_joined, "bot joined the room after the invite", TURN_TIMEOUT_S)
    member = stack.member.client()
    proof_event = await member.send(room_id, "proof", {"msgtype": "m.text", "body": code})
    await _wait_for(lambda: _address_proven(script, room_id), "proof confirmed", TURN_TIMEOUT_S)

    content_uri = await member.upload_media(PIXEL_PNG, "image/png", "dot.png")
    image_event = await member.send(
        room_id,
        "image",
        {
            "msgtype": "m.image",
            "body": "dot.png",
            "url": content_uri,
            "info": {"mimetype": "image/png", "size": len(PIXEL_PNG)},
        },
    )

    async def _file_landed() -> bool:
        return await _member_file(script, image_event) is not None

    await _wait_for(_file_landed, "the member's image landed on its turn", TURN_TIMEOUT_S)
    landed = await _member_file(script, image_event)
    assert landed is not None
    blob_key, filename, size_bytes = landed
    assert (filename, size_bytes) == ("dot.png", len(PIXEL_PNG))
    with ws(script.workspace_id):
        stored = b"".join([chunk async for chunk in stack.blob.get_stream(blob_key)])
    assert stored == PIXEL_PNG

    before = await _turn_keys(script)
    await stack.restart_listeners()
    after_event = await member.send(
        room_id, "after", {"msgtype": "m.text", "body": "after the restart"}
    )

    async def _answered_after() -> bool:
        return after_event in await _turn_keys(script)

    await _wait_for(_answered_after, "a message after the restart opened a turn", TURN_TIMEOUT_S)
    keys = await _turn_keys(script)
    assert proof_event not in keys
    assert sorted(keys) == sorted((*before, after_event))
