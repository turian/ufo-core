from ufo.sdk.manifest import Manifest
from ufo.sdk.surfaces import SurfaceSpec
from ufo_ext_matrix.surface import matrix_attach, matrix_listener, matrix_post, matrix_speak
from ufo_ext_matrix.tools import MATRIX_ROOM_CONNECT_TOOL
from ufo_ext_matrix.wire import BOT_TOKEN_ENV, HOMESERVER_ENV, SURFACE_NAME


def manifest() -> Manifest:
    """The matrix surface: one named provider account the deploy owns (two keys, no slots), an
    addressed durable surface the listener owns, and the one member action that claims a room
    for the speaker's workspace."""
    return Manifest(
        name=SURFACE_NAME,
        version="1",
        deploy_keys=(HOMESERVER_ENV, BOT_TOKEN_ENV),
        surfaces=(
            SurfaceSpec(
                name=SURFACE_NAME,
                addressed=True,
                listen=matrix_listener,
                post=matrix_post,
                attach=matrix_attach,
                speak=matrix_speak,
            ),
        ),
        tools=(MATRIX_ROOM_CONNECT_TOOL,),
    )
