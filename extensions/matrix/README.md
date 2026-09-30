# Matrix surface

Members talk to the agent in Matrix rooms. A single bot account, owned by the deploy, is the
surface's one device; a room is the conversation. The surface is wired through the durable-surface
seam exactly as Slack-shaped surfaces are: a `listen` stream for inbound, `post`/`attach`/`speak`
for outbound, address claims for binding a room to a workspace, and the fleet lease for running one
listener across the fleet.

## Why a `listen` surface, not push

Matrix's HTTP push scheme carries no per-request authentication: the pusher's `data` field is
static configuration, echoed verbatim in every push, so a secret in it (or a token that names the
tenant) self-discloses on the first push to any egress. Pushers are also the deprecated half of the
spec. The client-server API's native pull is the long-poll `GET /sync`: one outstanding request
returns on the next event, the bot's access token stays in a `Bearer` header, and nothing is
posted to any third party. The listener is therefore the transport, and the spec declares
`listen` plus `addressed=True` with no ingress route.

## Identity model

The deploy carries two keys, read from the environment and declared as the manifest's
`deploy_keys`:

- `UFO_MATRIX_HOMESERVER` — the homeserver base URL the bot lives on.
- `UFO_MATRIX_BOT_TOKEN` — the bot's client-server access token.

Federated deployment costs nothing: a room on a member's own homeserver invites the bot across and
the same `/sync`, `send`, and media calls reach it. Every workspace binds the bot's user id
(`@bot:server`) as its `matrix` installation; the address table, not the installation, selects the
workspace for a room, which is the addressed-surface contract.

## Binding a room: claim and proof, all in chat

A room binds to exactly one workspace, and only a speaking workspace **admin** may make or take the
claim — the room's messages become that workspace's conversation. The flow runs as conversation:

1. The member asks the agent to connect a room (by `!id:server` or a resolvable `#alias:server`).
   The agent calls the surfaced tool `matrix_room_connect`. The handler gates the speaker as
   admin, resolves the address, binds the fleet installation, and reserves the room for the
   speaker under a 15-minute expiry.
2. The tool answers with the bot's user id and a **proof code** — an eight-character
   `a-z2-7` digest, `HMAC-SHA256(bot token, "ufo.matrix.claim|<room>|<member id>")`. The code is
   derived, never stored: the `surface_address` row holds the claim, the code is whatever the
   secret and the claim compute.
3. The member invites the bot (`/sync` announces the invite). The listener joins while a claim
   stands for the room — a failed rejoin waits on a short cooldown — so the order of inviting and
   claiming is free. The room stays inert until proven: a bot in an unclaimed room admits nothing
   and sends nothing.
4. The claiming member sends the code in the room. The listener computes the code for the row and
   matches it whole-token, case-insensitively; a match links the sender's Matrix user id to the
   claiming member and confirms the address with the proving event id. The proving message is
   never admitted as a turn. A mismatch, or any other message while the claim is open or lapsed,
   changes nothing.

After proof, any room member speaks: linked ones resolve to their workspace member through
`surface_identity`, the others admit without a member id — a room is room-visible by design, and
absence of a link never blocks the conversation, it only narrows the audience.

## Admission and audience

Each non-bot `m.room.message` after the proving event is admitted with the Matrix event id as the
idempotency key, so a redelivered sync batch or a restarted listener never opens a second turn on
one message. A listener's first `/sync` replays each room's recent timeline: it admits only messages
addressed to the bot, and unaddressed ones feed the ambient transcript without another
ambient-reply decision. The message is fenced as a member message: plain text in the member element, inbound
files (downloaded and streamed straight into the store) in the attachments element, and for group
rooms the recent room transcript as the ambient prefix.

Whether the message opens a turn is stated, not guessed: a direct message, or an explicit mention
(the `m.mentions` user list, or a `matrix.to` pill naming the bot, percent-encoded or not),
admits directly; an unaddressed group message goes to the surface's ambient-reply decision, and a
refusal parks it.

Audience follows the audience rules:

- a direct message from a linked member is that member's private conversation;
- a group room, or a message from an unlinked member, is a shared `room:matrix:<key>`
  conversation, the key being the room id with its `:` percent-encoded because audience keys take
  no colon;
- the moment a joined member from a server other than the room creator's appears — or no creator
  is known — the room seals as `foreign:` — an externally shared room reads only itself.

## Delivery

The writeback poller drives `post`: the silence sentinel refuses delivery (`NOTHING_DELIVERED`),
otherwise the terminal text goes out as one `m.room.message`. An open question appends the prompt
and its numbered options; a connect or credential request appends the portal URL when one is
configured. The send carries the stable `txn` id `ufo-post-<turn id>`. The homeserver dedupes a
retransmission of the same transaction on the same device for as long as it keeps the mapping
(Synapse: 24 hours; the spec leaves it to the server), so a writeback re-posted inside that window —
the crash between a successful send and the recorded reply ref — returns the same event instead of
doubling the message. `attach` uploads each shared `file` artifact through the media API and sends one
media message per file under its own `txn` id; one file's rejection costs that file, not its
siblings. `speak` posts a mid-turn reply the same way, keyed on the row's id.

## Errors

A rate limit raises the delivery error with the server's retry delay; a token the homeserver no
longer accepts is permanent and parks the listener; a send the room refuses (the bot left or was
ejected) surfaces as a post failure the poller ages out. Inside the sync loop, a transient failure
(no answer, 429, 5xx) waits the server's delay and re-polls the same batch, and admission is
idempotent on the event id; a message the server refuses for good (a missing file, say) is logged
and skipped. An inbound file whose declared size exceeds the workspace write bound is dropped from
its message.

## Tests

`tests/` holds the pure-logic proofs: sync batch parsing, the claim code's derivation and
matching, mention detection, audience choices, and terminal rendering — no network.
`tests/integration/` runs the whole chain against a real homeserver container the test itself
starts: registration through the shared secret, an invite the listener answers, a proof message
that links, a turn that opens on a room message and answers through a real `PUT /send`, read back
by the member's own `/sync` and by the durable rows (the claim, the link, the conversation, the
delivered writeback). A second run uploads an image through the media API, reads its bytes back
from the store as the turn's member file, then restarts the listener and proves the replayed
timeline opens no turn for the proof or for any message already answered. The model is scripted; everything from the gateway out is real.