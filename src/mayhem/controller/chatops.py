"""ChatOps bots: text in, :func:`mayhem.controller.check_gate.dispatch_chatops`
(docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 3, surface half).

Phase 2 built the ChatOps *seam*: a transport with one method, an injected
validator, and an identity gate that refuses before validation runs. What it did
not build is the half that turns a chat message into a
:class:`~mayhem.controller.check_gate.ChatOpsRequest` — and that half is where
chat's particular dangers live.

**The environment comes from the binding, never from the message.** A channel is
registered against one :class:`~mayhem.domain.identity.EnvironmentScope` by an
administrator, out of band, and :func:`resolve_chatops_request` reads the scope
from that registration. There is deliberately no ``--environment`` in a chat
command and no way to type one: a message that can name its own scope can name
``production`` from a channel registered for ``staging``, and every other
refusal in this codebase becomes decorative the moment that is possible.

**A message is data, never syntax.** Everything after the verb must match
:data:`IDENTIFIER` — letters, digits, and ``._:/@+-``. ``$(rm -rf /)``,
``` `id` ```, ``a; b``, and ``a\nb`` are all refused with
:data:`RULE_CHATOPS_ARGUMENT` naming the character that offended. This is the
same containment rule :mod:`mayhem.controller.ci_surface` applies to a generated
workflow, arrived at from the other end: mayhem does not build a shell command
out of chat text and then quote it carefully, because a careful quote for an
arbitrary future quoting bug is not a control.

**An unbound channel is refused, not defaulted.** :data:`DEFAULT_DENY_SCOPE` is
what an *unregistered* channel resolves to, and it names a scope no role grant
can cover — so an unregistered channel reaches
:func:`~mayhem.controller.check_gate.dispatch_chatops`, finds no role, and is
refused by the same default-deny that refuses a principal with no grants. The
alternative (falling back to the author's own scope) would let a principal who
may run in ``staging`` run in ``production`` by moving to an unregistered
channel, which is a privilege escalation with a chat client as the payload.

The verbs are :data:`~mayhem.controller.check_gate.ChatOpsCommand` — read from
that enum rather than restated, so the bot cannot accept a command the engine
does not have an authorization row for, and
:data:`~mayhem.controller.check_gate.CHATOPS_REQUIRED_ROLE` supplies the role per
command so "who may approve from chat" has exactly one answer (Phase 6's
authorization matrix renders that table; it does not redefine it).

.. warning::

   **No Slack or Teams client exists here.** :func:`receive_message` takes a
   :class:`ChatMessage` value and a registry; it opens no socket, holds no token,
   and has no notion of a workspace. The property worth testing — that the
   requester's identity and the channel's scope both come from outside the
   message — is a property of pure functions, and it is proven with values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from mayhem.controller.check_gate import (
    CHATOPS_REQUIRED_ROLE,
    ChatOpsCommand,
    ChatOpsRefusedError,
    ChatOpsRequest,
    dispatch_chatops,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import EnvironmentScope

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from datetime import datetime

    from mayhem.controller.check_gate import ChatOpsReceipt, ChatOpsTransport
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.identity import Principal, RoleGrant, TeamMembership
    from mayhem.domain.pipeline import PipelineVerdict

__all__ = [
    "AUTHORIZATION_MATRIX",
    "DEFAULT_DENY_SCOPE",
    "IDENTIFIER",
    "RULE_CHATOPS_ARGUMENT",
    "RULE_CHATOPS_CHANNEL_UNBOUND",
    "RULE_CHATOPS_UNKNOWN_COMMAND",
    "ChannelBinding",
    "ChatMessage",
    "ChatOpsBot",
    "ChatOpsRequestParts",
    "ChatOutcome",
    "ParsedChat",
    "parse_command",
    "receive_message",
    "require_identifier",
    "resolve_chatops_request",
]

RULE_CHATOPS_ARGUMENT = "chatops.argument_not_an_identifier"
RULE_CHATOPS_CHANNEL_UNBOUND = "chatops.channel_not_bound"
RULE_CHATOPS_UNKNOWN_COMMAND = "chatops.unknown_command"

#: What an argument may contain. Letters, digits, and the six punctuation marks
#: that appear in the identifiers mayhem really has — run ids, plan refs, ticket
#: keys, digests, file paths. Everything else is refused.
IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")

#: The scope an unregistered channel falls back to. Named, and deliberately
#: un-coverable by an ordinary grant: a grant must say ``environment="*"``
#: explicitly to reach it, so an admin who *wants* a wildcard bot must write one.
DEFAULT_DENY_SCOPE: Final[EnvironmentScope] = EnvironmentScope(
    environment="unbound-channel",
    organization="",
    project="",
)

#: The command → role matrix the bot enforces, read from Phase 2 rather than
#: re-spelled. Rendered by Phase 6's authorization reference; enforced here.
AUTHORIZATION_MATRIX: Final[tuple[tuple[str, str], ...]] = tuple(
    (command.value, role.value) for command, role in CHATOPS_REQUIRED_ROLE.items()
)


# =============================================================================
# What arrives
# =============================================================================


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """One inbound message, as the transport hands it over.

    ``author_id`` is the transport's *authenticated* user id and is never
    derived from the message text or from a ``user:`` prefix inside it. A bot
    that trusts a typed identity is a bot whose identity is whatever somebody
    typed, and a bot that trusts a channel is a bot whose authority is whatever
    channel it was invited to.
    """

    channel_id: str
    author_id: str
    text: str

    def __post_init__(self) -> None:
        if not self.channel_id.strip():
            msg = "a chat message must arrive on a named channel"
            raise InvariantViolationError(RULE_CHATOPS_CHANNEL_UNBOUND, msg)
        if not self.author_id.strip():
            msg = "a chat message must carry the transport's authenticated author id"
            raise InvariantViolationError(RULE_CHATOPS_ARGUMENT, msg)


@dataclass(frozen=True, slots=True)
class ChannelBinding:
    """A channel's registration: which environment its commands act in."""

    channel_id: str
    scope: EnvironmentScope

    def __post_init__(self) -> None:
        if not self.channel_id.strip():
            msg = "a channel binding must name the channel it binds"
            raise InvariantViolationError(RULE_CHATOPS_CHANNEL_UNBOUND, msg)


class ChatOutcome(StrEnum):
    """What the bot did with a message. Three states, and the middle one refuses.

    ``REFUSED`` covers *every* refusal — unparsable text, an unbound channel, an
    unauthorized principal, a validation that did not gate — because a bot that
    distinguishes them to the channel leaks the authorization model to anybody
    who can post. The detail goes to the caller; the channel gets the summary.
    """

    DISPATCHED = "dispatched"
    NOT_A_COMMAND = "not_a_command"
    REFUSED = "refused"


# =============================================================================
# Parsing
# =============================================================================


@dataclass(frozen=True, slots=True)
class ParsedChat:
    """A verb and one argument, or nothing.

    ``NOT_A_COMMAND`` is a *successful* parse: ordinary conversation in a channel
    the bot is in must not be an error, and must not be a dispatch either.
    """

    command: ChatOpsCommand | None
    argument: str
    raw: str

    @property
    def is_command(self) -> bool:
        return self.command is not None


_VERB_PREFIX: Final[str] = "mayhem "


def parse_command(text: str) -> ParsedChat:
    """Parse ``text`` into a verb and one identifier argument.

    Returns ``NOT_A_COMMAND`` (a successful parse with no command) for ordinary
    conversation, and **raises** :class:`~mayhem.domain.errors.
    InvariantViolationError` for text that *tried* to be a command and got the
    grammar wrong: an unknown verb (:data:`RULE_CHATOPS_UNKNOWN_COMMAND`) or a
    missing argument (:data:`RULE_CHATOPS_ARGUMENT`). The grammar is checked but
    the *argument's* character set is not — that is
    :func:`require_identifier`'s job, so that "this was a command" and "this was
    a command with a usable argument" are two separate answers.

    The grammar is deliberately tiny — ``mayhem <verb> <identifier>`` — because a
    chat surface is the least trustworthy input mayhem has, and every feature
    added here is a feature an untrusted typist can reach. Anything longer than
    this is prose, and prose is :data:`ChatOutcome.NOT_A_COMMAND`.
    """
    stripped = text.strip()
    if not stripped.lower().startswith(_VERB_PREFIX):
        return ParsedChat(command=None, argument="", raw=stripped)
    remainder = stripped[len(_VERB_PREFIX) :].strip()
    if not remainder:
        return ParsedChat(command=None, argument="", raw=stripped)
    verb, _, argument = remainder.partition(" ")
    argument = argument.strip()
    try:
        command = ChatOpsCommand(verb.strip().lower())
    except ValueError:
        msg = (
            f"{verb.strip()!r} is not a mayhem chat command; the commands are "
            + ", ".join(sorted(command.value for command in ChatOpsCommand))
        )
        raise InvariantViolationError(RULE_CHATOPS_UNKNOWN_COMMAND, msg) from None
    if not argument:
        msg = (
            f"chat {command.value} needs an argument: a run id, a plan ref, or an "
            "experiment name. There is no default target, because a chat command "
            "that acts on an unnamed thing acts on everything"
        )
        raise InvariantViolationError(RULE_CHATOPS_ARGUMENT, msg)
    return ParsedChat(command=command, argument=argument, raw=stripped)


def require_identifier(value: str, *, subject: str) -> str:
    """``value`` if it is an identifier, else a refusal naming the offending shape."""
    if not IDENTIFIER.fullmatch(value):
        msg = (
            f"{subject} {value!r} is not an identifier mayhem will pass through: "
            "chat text is data, never syntax, so only "
            f"{IDENTIFIER.pattern} is accepted. Nothing from a message is ever "
            "interpolated into a command"
        )
        raise InvariantViolationError(RULE_CHATOPS_ARGUMENT, msg)
    return value


# =============================================================================
# The bot
# =============================================================================


def resolve_chatops_request(
    message: ChatMessage,
    *,
    bindings: Mapping[str, ChannelBinding],
    author: Principal,
    plan: ExecutionPlan | None = None,
) -> tuple[ChatOpsCommand, ChatOpsRequestParts]:
    """Turn a message into the request Phase 2 authorizes.

    Split out from :meth:`ChatOpsBot.dispatch` so the two halves can be tested
    independently: *parsing* (is this a command, and is the argument an
    identifier) and *binding* (which environment, which principal). ``author``
    is a required argument rather than looked up from ``message.author_id``,
    because resolving an author id to a principal is the transport adapter's
    job and guessing it here would make the bot its own identity provider.

    Raises:
        InvariantViolationError: On text that is not a command
            (:data:`RULE_CHATOPS_UNKNOWN_COMMAND`), an unknown verb, or an
            argument that is not an identifier (:data:`RULE_CHATOPS_ARGUMENT`).
    """
    parsed = parse_command(message.text)
    if parsed.command is None:
        msg = "not a mayhem chat command"
        raise InvariantViolationError(RULE_CHATOPS_UNKNOWN_COMMAND, msg)
    require_identifier(parsed.argument, subject="chat argument")
    binding = bindings.get(message.channel_id)
    scope = binding.scope if binding is not None else DEFAULT_DENY_SCOPE
    return parsed.command, ChatOpsRequestParts(
        environment=scope,
        author=author,
        text=parsed.raw,
        target=parsed.argument,
        plan=plan,
        bound=binding is not None,
    )


@dataclass(frozen=True, slots=True)
class ChatOpsRequestParts:
    """Everything the bot resolved, before Phase 2 sees it.

    ``bound`` is carried so the bot can *say* whether the channel was registered
    without re-deriving it, and so a test can assert the scope came from the
    binding rather than from the message: the two differ for every unregistered
    channel, and that difference is the property.
    """

    environment: EnvironmentScope
    author: Principal
    text: str
    target: str
    plan: ExecutionPlan | None = None
    bound: bool = False


@dataclass
class ChatOpsBot:
    """The bot: bindings in, dispatch out, refusals caught and reported.

    Deliberately a plain dataclass rather than a service with a store behind it.
    It holds no credential, opens no connection, and mutates nothing except its
    own :attr:`receipts` log — which is what makes "a refused message changes
    nothing" directly assertable.

    ``validate`` is required and has no default, exactly as in Phase 2: the bot
    must dispatch through the *same* validation entry point the CLI uses, and a
    default validator would be the second one.
    """

    bindings: dict[str, ChannelBinding] = field(default_factory=dict)
    principals: Mapping[str, Principal] = field(default_factory=dict)
    grants: Sequence[RoleGrant] = ()
    memberships: Sequence[TeamMembership] = ()
    receipts: list[ChatOpsReceipt] = field(default_factory=list)

    def bind(self, binding: ChannelBinding) -> None:
        self.bindings[binding.channel_id] = binding

    def dispatch(
        self,
        message: ChatMessage,
        *,
        transport: ChatOpsTransport,
        validate: Callable[[ChatOpsRequest], PipelineVerdict],
        now: datetime,
        plan: ExecutionPlan | None = None,
    ) -> tuple[ChatOutcome, str]:
        """Handle one message. Returns ``(outcome, detail)``; never raises.

        The refusal detail is returned rather than raised so a bot loop can keep
        reading messages: an unparsable message must not be able to stop the bot
        from answering the next one. :func:`receive_message` is the thin wrapper
        that a transport loop calls.
        """
        author = self.principals.get(message.author_id)
        if author is None:
            return (
                ChatOutcome.REFUSED,
                f"the authenticated user {message.author_id!r} is not a known principal, "
                "so mayhem holds no identity to resolve roles against",
            )
        try:
            command, parts = resolve_chatops_request(
                message, bindings=self.bindings, author=author, plan=plan
            )
        except InvariantViolationError as exc:
            if exc.rule == RULE_CHATOPS_UNKNOWN_COMMAND and not _looks_like_command(
                message.text
            ):
                return ChatOutcome.NOT_A_COMMAND, ""
            return ChatOutcome.REFUSED, str(exc)
        request = _to_request(command, parts, run_id=parts.target)
        try:
            receipt = dispatch_chatops(
                request,
                transport=transport,
                validate=validate,
                grants=self.grants,
                memberships=self.memberships,
                now=now,
            )
        except ChatOpsRefusedError as exc:
            return ChatOutcome.REFUSED, str(exc)
        self.receipts.append(receipt)
        return ChatOutcome.DISPATCHED, receipt.detail


def _looks_like_command(text: str) -> bool:
    """Whether the message *tried* to be a command, for refusal-vs-silence."""
    return text.strip().lower().startswith(_VERB_PREFIX)


def _to_request(
    command: ChatOpsCommand,
    parts: ChatOpsRequestParts,
    *,
    run_id: str,
) -> ChatOpsRequest:
    """Build Phase 2's request from resolved parts."""
    return ChatOpsRequest(
        command=command,
        requester=parts.author,
        environment=parts.environment,
        text=parts.text,
        run_id=run_id,
        plan=parts.plan,
    )


def receive_message(
    bot: ChatOpsBot,
    message: ChatMessage,
    *,
    transport: ChatOpsTransport,
    validate: Callable[[ChatOpsRequest], PipelineVerdict],
    now: datetime,
    plan: ExecutionPlan | None = None,
) -> tuple[ChatOutcome, str]:
    """The seam a transport loop calls. One message in, one outcome out."""
    return bot.dispatch(message, transport=transport, validate=validate, now=now, plan=plan)
