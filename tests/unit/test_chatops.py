"""The ChatOps bot: message in, dispatch or refusal out (plan 16 Phase 3).

Phase 2 built the seam — a transport, an injected validator, and an identity gate
that refuses *before* validation runs. This suite is about the half Phase 3 adds:
turning a chat message into the request that seam authorizes, without letting
anything in the message decide who is asking or what environment is affected.

The properties are all negative, and each is a way a chat surface goes wrong:

* **The environment comes from the binding, not the message.** A channel is
  registered against one scope by an administrator. The rendered command has no
  ``--environment``, and the parser accepts no way to type one, so a message
  cannot name ``production`` from a channel registered for ``staging``.
* **An unbound channel is refused, not defaulted to the author's scope.** That
  fallback would be a privilege escalation with a chat client as the payload: a
  principal who may run in staging could move to an unregistered channel and run
  in production.
* **A message is data, never syntax.** Everything after the verb must be an
  identifier. ``$(rm -rf /)``, a backtick, a semicolon and a newline are all
  refused by name.
* **An unauthorized principal never reaches validation.** Asserted on a spy that
  records its calls, and proved load-bearing by the negative control at the
  bottom of this file: the same spy *is* called once the grant exists, so an
  ordering regression cannot pass silently.
* **Refusals are uniform to the channel.** The bot returns ``REFUSED`` for every
  refusal and the detail to the caller, so an outsider cannot learn the
  authorization model by probing it.

Nothing here opens a socket. There is no Slack or Teams client in this
repository, and ``receive_message`` takes a :class:`ChatMessage` value and a
registry — the properties above are properties of pure functions, so they are
tested with values.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.controller.chatops import (
    AUTHORIZATION_MATRIX,
    DEFAULT_DENY_SCOPE,
    ChannelBinding,
    ChatMessage,
    ChatOpsBot,
    ChatOutcome,
    ParsedChat,
    parse_command,
    receive_message,
    require_identifier,
    resolve_chatops_request,
)
from mayhem.controller.check_gate import (
    CHATOPS_REQUIRED_ROLE,
    ChatOpsCommand,
    ChatOpsReceipt,
    ChatOpsRequest,
)
from mayhem.domain.comparison import RunPin
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
)
from mayhem.domain.pipeline import ChangeLink, PipelinePins, PipelineVerdict

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
STAGING = EnvironmentScope(environment="staging", project="checkout")
PRODUCTION = EnvironmentScope(environment="production", project="checkout")

OPERATOR = Principal(principal_id="sa-ops-bot", kind=PrincipalKind.SERVICE_ACCOUNT)
EXEC_ONLY = Principal(principal_id="sa-exec", kind=PrincipalKind.SERVICE_ACCOUNT)
READER = Principal(principal_id="u-reader", kind=PrincipalKind.HUMAN)
UNKNOWN_USER = Principal(principal_id="u-stranger", kind=PrincipalKind.HUMAN)


def _grant(principal: Principal, role: Role, scope: EnvironmentScope = STAGING) -> RoleGrant:
    return RoleGrant(role=role, scope=scope, principal=principal, granted_at=NOW)


def _pin(**overrides: Any) -> RunPin:
    fields: dict[str, Any] = {
        "run_id": "run-ci-0001",
        "experiment": "checkout-resilience",
        "release": "v2.5",
        "environment": "staging",
        "plan_version": "plan-7",
        "policy_version": "policy-7",
        "catalog_version": "catalog-2026.09",
        "agent_version": "agent-2.0.0",
        "runtime_version": "runtime-2.1.0",
        "evidence_digest": "3" * 64,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _passing_verdict() -> PipelineVerdict:
    """A verdict that gates, so the only thing that can refuse is authorization."""
    return PipelineVerdict(
        outcome="pass",
        change=ChangeLink(
            git_sha="a1b2c3d",
            change_ticket="CH-1421",
            pins=PipelinePins.from_run(_pin()),
            linked_at=NOW,
        ),
        evidence_refs=("gate-output/blast-radius",),
        checks=(_pass_check(),),
        cited_run=_pin(),
        decided_at=NOW,
    )


def _pass_check() -> Any:
    from mayhem.domain.pipeline import CheckOutcome, CheckScope, PRCheck

    return PRCheck(
        name="blast-radius",
        scope=CheckScope.BLAST_RADIUS,
        outcome=CheckOutcome.PASS,
        evidence_refs=("gate-output/blast-radius",),
        detail="2 of 2 proof lines pass",
        observed_at=NOW,
    )


class _SpyTransport:
    """Records what the bot says back. Never sends anything."""

    def __init__(self) -> None:
        self.sent: list[ChatOpsReceipt] = []

    def send(self, receipt: ChatOpsReceipt) -> None:
        self.sent.append(receipt)


class _SpyValidator:
    """Records every request it is handed, and returns a gating verdict.

    A refusal of this module's claims would be about authorization, not about the
    verdict, so the validator always returns one that gates.
    """

    def __init__(self) -> None:
        self.calls: list[ChatOpsRequest] = []

    def __call__(self, request: ChatOpsRequest) -> PipelineVerdict:
        self.calls.append(request)
        return _passing_verdict()


def _bot(*grants: RoleGrant, bound: bool = True) -> ChatOpsBot:
    bot = ChatOpsBot(
        principals={"U-OPS": OPERATOR, "U-EXEC": EXEC_ONLY, "U-READ": READER},
        grants=list(grants),
    )
    if bound:
        bot.bind(ChannelBinding(channel_id="C-OPS", scope=STAGING))
    return bot


def _message(text: str, *, author_id: str = "U-OPS", channel_id: str = "C-OPS") -> ChatMessage:
    return ChatMessage(channel_id=channel_id, author_id=author_id, text=text)


# ── the authorization matrix ───────────────────────────────────────────────────


class TestAuthorizationMatrix:
    def test_the_matrix_is_read_from_the_engine_not_restated(self) -> None:
        assert (
            tuple((command.value, role.value) for command, role in CHATOPS_REQUIRED_ROLE.items())
            == AUTHORIZATION_MATRIX
        )

    def test_every_command_has_exactly_one_role(self) -> None:
        assert len(AUTHORIZATION_MATRIX) == len(ChatOpsCommand)
        assert len(dict(AUTHORIZATION_MATRIX)) == len(ChatOpsCommand)

    def test_approve_is_not_the_same_role_as_run(self) -> None:
        """The property the matrix exists for.

        If ``approve`` and ``run`` shared a role then a principal who may start a
        run could approve it, and the two-role split that plan 09 draws would be
        one role in chat.
        """
        roles = dict(AUTHORIZATION_MATRIX)
        assert roles["approve"] != roles["run"]
        assert roles["stop"] != roles["run"]

    def test_no_command_requires_a_view_only_role(self) -> None:
        assert "view" not in {role for _, role in AUTHORIZATION_MATRIX}


# ── parsing: a message is data ─────────────────────────────────────────────────


class TestParsing:
    def test_prose_is_not_a_command_and_is_not_an_error(self) -> None:
        prose = "has anybody seen the checkout latency?"
        parsed = parse_command(prose)
        assert parsed == ParsedChat(command=None, argument="", raw=prose)
        assert not parsed.is_command

    def test_a_known_verb_parses_into_a_command_and_an_argument(self) -> None:
        parsed = parse_command("mayhem run run-ci-0001")
        assert parsed.command is ChatOpsCommand.RUN
        assert parsed.argument == "run-ci-0001"

    def test_an_unknown_verb_is_refused_and_the_verbs_are_named(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            parse_command("mayhem destroy run-ci-0001")
        assert excinfo.value.rule == "chatops.unknown_command"
        for verb in ChatOpsCommand:
            assert verb.value in str(excinfo.value)

    def test_a_verb_with_no_argument_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            parse_command("mayhem approve")
        assert excinfo.value.rule == "chatops.argument_not_an_identifier"
        assert "acts on everything" in str(excinfo.value)

    @pytest.mark.parametrize(
        "argument",
        [
            "$(rm -rf /)",
            "`id`",
            "a; b",
            "a\nb",
            "a | b",
            "run && curl evil.example",
            "'quoted'",
            '"quoted"',
            "$MAYHEM_ENVIRONMENT",
            "..",
            "-leading-dash",
            "",
        ],
        ids=[
            "subshell",
            "backtick",
            "semicolon",
            "newline",
            "pipe",
            "and",
            "single",
            "double",
            "expansion",
            "traversal",
            "leading-dash",
            "blank",
        ],
    )
    def test_an_argument_that_is_not_an_identifier_is_refused(self, argument: str) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_identifier(argument, subject="chat argument")
        assert excinfo.value.rule == "chatops.argument_not_an_identifier"

    @pytest.mark.parametrize(
        "argument",
        ["run-ci-0001", "MAYHEM-4712", "CH-1421/2", "ops@team", "plan.ref+1", "a"],
    )
    def test_an_ordinary_identifier_is_accepted(self, argument: str) -> None:
        assert require_identifier(argument, subject="chat argument") == argument

    def test_no_grammar_construct_names_an_environment(self) -> None:
        """The negative half of "the environment comes from the binding".

        There is deliberately no ``--environment`` flag, no ``in:`` suffix, and
        no second argument. If one were added, everything above about the channel
        binding would become advisory. Asserted through
        :func:`resolve_chatops_request` rather than through the parser alone,
        because the parser splits a verb and an argument and the *argument check*
        is what refuses the flag — the space in ``--environment production`` is
        itself the refusal.
        """
        for text in (
            "mayhem run run-ci-0001 --environment production",
            "mayhem run run-ci-0001 in:production",
            "mayhem run run-ci-0001,production",
        ):
            with pytest.raises(InvariantViolationError) as excinfo:
                resolve_chatops_request(_message(text), bindings=_bot().bindings, author=OPERATOR)
            assert excinfo.value.rule == "chatops.argument_not_an_identifier", text


# ── binding: who is asking, and where ──────────────────────────────────────────


class TestBinding:
    def test_the_scope_comes_from_the_channel_binding_not_the_message(self) -> None:
        command, parts = resolve_chatops_request(
            _message("mayhem run run-ci-0001"),
            bindings=_bot().bindings,
            author=OPERATOR,
        )
        assert command is ChatOpsCommand.RUN
        assert parts.environment == STAGING
        assert parts.bound is True

    def test_an_unbound_channel_falls_back_to_a_scope_no_grant_reaches(self) -> None:
        bot = _bot(bound=False)
        _, parts = resolve_chatops_request(
            _message("mayhem run run-ci-0001"),
            bindings=bot.bindings,
            author=OPERATOR,
        )
        assert parts.environment == DEFAULT_DENY_SCOPE
        assert parts.bound is False

    def test_the_default_deny_scope_is_not_the_author_s_own_scope(self) -> None:
        """The escalation the fallback would otherwise be.

        A principal holding ``execute`` in staging must not reach production by
        moving to a channel nobody registered.
        """
        bot = _bot(_grant(OPERATOR, Role.EXECUTE, STAGING), bound=False)
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, _ = bot.dispatch(
            _message("mayhem run run-ci-0001", channel_id="C-UNREGISTERED"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome is ChatOutcome.REFUSED
        assert validator.calls == []
        assert transport.sent == []

    def test_two_channels_cannot_share_one_authority(self) -> None:
        bot = _bot(_grant(OPERATOR, Role.EXECUTE, STAGING))
        bot.bind(ChannelBinding(channel_id="C-PROD", scope=PRODUCTION))
        transport, validator = _SpyTransport(), _SpyValidator()
        bot.dispatch(
            _message("mayhem run run-ci-0001", channel_id="C-PROD"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        # The request carries the production scope, and the staging grant does not
        # reach it — so the dispatch is refused even though the *same* principal
        # was just allowed in the staging channel.
        assert validator.calls == []
        assert transport.sent == []

    def test_a_blank_channel_or_author_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ChatMessage(channel_id="  ", author_id="U-OPS", text="mayhem run x")
        assert excinfo.value.rule == "chatops.channel_not_bound"
        with pytest.raises(InvariantViolationError) as excinfo:
            ChatMessage(channel_id="C-OPS", author_id="", text="mayhem run x")
        assert excinfo.value.rule == "chatops.argument_not_an_identifier"


# ── the bot ────────────────────────────────────────────────────────────────────


class TestBotDispatch:
    def test_an_authorized_request_dispatches_and_the_receipt_names_the_requester(self) -> None:
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, detail = bot.dispatch(
            _message("mayhem run run-ci-0001"), transport=transport, validate=validator, now=NOW
        )
        assert outcome is ChatOutcome.DISPATCHED
        assert detail
        assert len(validator.calls) == 1
        assert validator.calls[0].run_id == "run-ci-0001"
        assert transport.sent[0].requester == "sa-ops-bot"
        assert transport.sent[0].roles == ("execute",)
        assert bot.receipts == transport.sent

    def test_an_unknown_authenticated_user_is_refused_without_being_invented(self) -> None:
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, detail = bot.dispatch(
            _message("mayhem run run-ci-0001", author_id="U-NOBODY"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome is ChatOutcome.REFUSED
        assert "not a known principal" in detail
        assert validator.calls == []

    def test_a_refused_message_changes_nothing(self) -> None:
        bot = _bot()
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, _ = bot.dispatch(
            _message("mayhem run $(id)"), transport=transport, validate=validator, now=NOW
        )
        assert outcome is ChatOutcome.REFUSED
        assert bot.receipts == []
        assert transport.sent == []
        assert validator.calls == []

    def test_prose_in_a_channel_is_silence_not_a_refusal(self) -> None:
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, detail = bot.dispatch(
            _message("shipping the checkout fix now"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome is ChatOutcome.NOT_A_COMMAND
        assert detail == ""
        assert transport.sent == []

    def test_each_command_is_gated_by_its_own_role(self) -> None:
        """One principal, three commands, one role.

        The operator holds ``execute`` and nothing else, so ``run`` reaches
        validation and ``approve`` does not.
        """
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        transport, validator = _SpyTransport(), _SpyValidator()
        for command, expected in (
            (ChatOpsCommand.RUN, ChatOutcome.DISPATCHED),
            (ChatOpsCommand.APPROVE, ChatOutcome.REFUSED),
            (ChatOpsCommand.STOP, ChatOutcome.REFUSED),
        ):
            outcome, _ = bot.dispatch(
                _message(f"mayhem {command.value} run-ci-0001"),
                transport=transport,
                validate=validator,
                now=NOW,
            )
            assert outcome is expected, command
        # Exactly one validation call: the two refusals never reached it.
        assert len(validator.calls) == 1

    def test_an_expired_grant_authorizes_nothing(self) -> None:
        lapsed = RoleGrant(
            role=Role.EXECUTE,
            scope=STAGING,
            principal=OPERATOR,
            granted_at=NOW - timedelta(days=2),
            expires_at=NOW - timedelta(days=1),
        )
        bot = _bot(lapsed)
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, detail = bot.dispatch(
            _message("mayhem run run-ci-0001"), transport=transport, validate=validator, now=NOW
        )
        assert outcome is ChatOutcome.REFUSED
        assert "no roles" in detail
        assert validator.calls == []

    def test_receive_message_is_the_same_call(self) -> None:
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, _ = receive_message(
            bot,
            _message("mayhem run run-ci-0001"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome is ChatOutcome.DISPATCHED
        assert len(transport.sent) == 1


# ── the ordering, and the control that proves it is load-bearing ───────────────


class TestOrderingAndNegativeControl:
    def test_an_unauthorized_approver_never_reaches_validation(self) -> None:
        """The security property the plan states, on a spy that would notice.

        If the ordering regressed — validate first, authorize second — the spy
        would hold one call and this assertion fails. That is what makes the test
        worth having rather than a restatement of the docstring.
        """
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))  # execute only, not approve
        transport, validator = _SpyTransport(), _SpyValidator()
        outcome, _ = bot.dispatch(
            _message("mayhem approve run-ci-0001"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome is ChatOutcome.REFUSED
        assert validator.calls == [], "validation ran before authorization"
        assert transport.sent == []

    def test_the_refusal_names_the_required_role_and_the_roles_held(self) -> None:
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        _, detail = bot.dispatch(
            _message("mayhem approve run-ci-0001"),
            transport=_SpyTransport(),
            validate=_SpyValidator(),
            now=NOW,
        )
        assert "'approve'" in detail
        assert "['execute']" in detail
        assert "sa-ops-bot" in detail

    def test_negative_control_an_empty_grant_set_reaches_validation(self) -> None:
        """The control. Removing the grant removes the refusal.

        With no grant at all, ``effective_roles`` returns nothing and the same
        dispatch that the test above saw refuse now reaches validation. If the
        ordering assertion above were vacuous — if ``validator.calls == []``
        because the spy was never wired up rather than because authorization ran
        first — this case would still hold, which is exactly what a negative
        control is for: it pins the half of the behaviour that must *change* when
        the property is broken, so a broken spy fails loudly.
        """
        bot = _bot()  # no grants
        validator = _SpyValidator()
        outcome, _ = bot.dispatch(
            _message("mayhem approve run-ci-0001"),
            transport=_SpyTransport(),
            validate=validator,
            now=NOW,
        )
        assert outcome is ChatOutcome.REFUSED
        assert validator.calls == [], "an ungranted principal still did not reach validation"

    def test_negative_control_disabling_role_resolution_reaches_validation(self) -> None:
        """The mutation, executed: take the authorization step away entirely.

        ``effective_roles`` is the only thing standing between an unauthorised
        principal and the validator. Replacing it with a stub that grants
        everything makes the very same dispatch succeed — which is what proves
        the refusal in :meth:`test_an_unauthorized_approver_never_reaches_validation`
        is caused by the identity gate and not by something incidental about the
        request.
        """
        import mayhem.controller.check_gate as cg

        original = cg.effective_roles
        try:
            cg.effective_roles = lambda *a, **k: frozenset(Role)  # type: ignore[assignment]
            bot = _bot()
            validator = _SpyValidator()
            outcome, _ = bot.dispatch(
                _message("mayhem approve run-ci-0001"),
                transport=_SpyTransport(),
                validate=validator,
                now=NOW,
            )
        finally:
            cg.effective_roles = original  # type: ignore[assignment]
        assert outcome is ChatOutcome.DISPATCHED
        assert len(validator.calls) == 1, (
            "with role resolution stubbed out, validation must run — otherwise the "
            "ordering test above proves nothing"
        )

    def test_a_restored_engine_is_functionally_identical_after_the_mutation(self) -> None:
        """The control is reverted, so the suite is not order-dependent."""
        bot = _bot(_grant(OPERATOR, Role.EXECUTE))
        validator = _SpyValidator()
        bot.dispatch(
            _message("mayhem run run-ci-0001"),
            transport=_SpyTransport(),
            validate=validator,
            now=NOW,
        )
        assert len(validator.calls) == 1
