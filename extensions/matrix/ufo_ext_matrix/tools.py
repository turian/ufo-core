from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field

from ufo.sdk.objects import AdminRequired
from ufo.sdk.tools import TextContent, ToolContext, ToolDef, ToolResult
from ufo_ext_matrix.client import MatrixClient, deploy_settings
from ufo_ext_matrix.wire import CLAIM_TTL_SECONDS, SURFACE_NAME, claim_proof_code

CONNECT_GATE = "matrix.room"

RESERVED_REPLY = (
    "Claimed that room for this workspace. Invite the bot to it: {bot}. Then prove the claim by "
    "sending this code in the room: {code}"
)
LINKED_REPLY = "That room already answers this workspace."
TAKEN_REPLY = "That room is held by another workspace or member, so this workspace cannot claim it."


class MatrixRoomConnectInput(BaseModel):
    room: str = Field(min_length=1, max_length=256)


async def matrix_room_connect(ctx: ToolContext, args: MatrixRoomConnectInput) -> ToolResult:
    """Claim one Matrix room for the speaking admin's workspace: the deploy's bot binds here, the
    room address reserves under the speaker until its proof window lapses, and the reply carries
    the code whose possession is the proof — sent in the room, admitted by the listener, never
    by this call."""
    speaker = ctx.require_speaker(CONNECT_GATE)
    if not await ctx.require_speaking_admin(CONNECT_GATE):
        raise AdminRequired(CONNECT_GATE)
    settings = deploy_settings()
    client = MatrixClient(settings)
    try:
        bot_id = (await client.whoami()).user_id
        room_id = await client.resolve_room(args.room)
    finally:
        await client.aclose()
    ext = ctx.ext
    if ext is None:
        raise RuntimeError("the matrix tool ran with no extension context")
    installations = ext.installations
    await installations.bind(SURFACE_NAME, bot_id)
    claimed = await installations.reserve_address(
        SURFACE_NAME, room_id, speaker, datetime.now(UTC) + timedelta(seconds=CLAIM_TTL_SECONDS)
    )
    match claimed:
        case "linked":
            text = LINKED_REPLY
        case "taken":
            text = TAKEN_REPLY
        case _:
            text = RESERVED_REPLY.format(
                bot=bot_id, code=claim_proof_code(settings.bot_token, room_id, speaker)
            )
    return ToolResult(content=(TextContent(text=text),))


MATRIX_ROOM_CONNECT_TOOL = ToolDef(
    name="matrix_room_connect",
    description=(
        "Connect one Matrix room to this workspace so its messages reach the agent and the "
        "agent's replies reach the room. Requires the speaker's admin; names the room by id or "
        "alias. After the claim the member invites the bot and proves it with the code this "
        "returns. Use when a member asks the agent to join or listen to a Matrix room."
    ),
    input_model=MatrixRoomConnectInput,
    handler=matrix_room_connect,
    side_effecting=True,
)
