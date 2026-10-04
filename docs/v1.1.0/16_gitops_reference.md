# Plan 16 — GitOps reference architecture and ChatOps reference

Two reference architectures, both of which are *descriptions of decision logic
that exists*, not deployments that have been built. Read the honesty section
first; it is short and it is the part that matters.

## GitOps: declaring an experiment next to the infrastructure it drills

The point of the Terraform surface is that an experiment should be declared where
the infrastructure it drills is, not in a wiki that goes stale.

```hcl
terraform {
  required_providers {
    mayhem = {
      source  = "mayhemlabs/mayhem"
      version = "~> 2.4"
    }
  }
}

resource "mayhem_experiment" "checkout_postgres_failure" {
  name        = "checkout-postgres-failure"
  spec_digest = "…64 hex…"
  spec        = "…JSON-encoded drill spec…"
}
```

`mayhem ci terraform-config` renders that from a `ExperimentConfig` with the spec
JSON-encoded and sorted, so the same config always produces the same bytes.

### The credential is refused in config

`ExperimentConfig` **raises** `terraform.credential_in_config` if you set
`api_token`. Terraform state is plaintext on disk and in the backend, so a token
in a provider block is a token in a bucket. Read it from the environment
(`MAYHEM_API_TOKEN`) instead. The generated file says so in its header.

### Plan/apply over a port, and what fails closed

`terraform_plan` and `terraform_apply` are pure decision logic over
`ExperimentApiPort` — a structural protocol the caller implements over plan 08's
API. Three reach states, and the middle one is the reason they are separate:

| The API answered | Reach | What happens |
| --- | --- | --- |
| an `ExperimentResource` | `REACHABLE` | planned |
| `None` | `ABSENT` | planned as a create — this is a real answer |
| raised, unbound, or wrong shape | `UNAVAILABLE` | **refused** (`terraform.state_unreadable`) |

A `None` and an unreachable API are different facts. "I could not ask whether
this experiment exists" and "this experiment does not exist" are different facts,
and conflating them makes a re-created experiment look like a fresh one —
silently orphaning whatever the old one was attached to. So an unreadable state
is refused rather than treated as empty.

### Apply re-reads and refuses on drift

This is the Terraform analogue of the plan's negative control, and it is
implemented rather than documented:

1. `terraform_plan` records `observed_digest` — the fingerprint of the state it
   derived the plan from.
2. `terraform_apply` **re-reads** and compares.
3. If they differ, it refuses (`terraform.plan_stale`) and writes nothing.

The message says both digests. A Terraform run is exactly where a human reads
"apply" as "do what you said"; refusing to overwrite a change somebody made since
the plan is the whole job.

A write that comes back with a *different* digest, or with something that is not a
resource at all, is `terraform.write_unconfirmed`. Mayhem reports what it can
prove rather than what it hoped.

### What has not been done

- **No `terraform` binary has been driven against a real state file.** Terraform's
  plugin handshake, state locking, and `terraform plan` output format are *not*
  modelled. A passing conformance test is a passing test of *our* decisions —
  create, no-op, update, refuse-on-stale, refuse-on-unconfirmed — given a fake
  API whose answers can be arranged exactly. A real API would make those cases
  depend on a network.
- **No experiment declared through Terraform has been executed.** The round trip
  that is proven is read → write → read over a fake port.

## ChatOps: three commands, one authorization table

```
mayhem <verb> <identifier>
```

That is the entire grammar. `run`, `approve`, `stop` — read from
`ChatOpsCommand`, so the bot cannot accept a command the engine has no
authorization row for.

| Command | Required role | What it dispatches |
| --- | --- | --- |
| `mayhem run <run-id>` | `execute` | a run |
| `mayhem approve <run-id>` | `approve` | an approval |
| `mayhem stop <run-id>` | `emergency_stop` | a stop |

The table is `check_gate.CHATOPS_REQUIRED_ROLE`; `chatops.AUTHORIZATION_MATRIX`
renders it and does not redefine it. One answer to "who may approve", whether the
approval is typed in a channel or granted to a CI job.

### Three properties, each a refusal

**The environment comes from the channel binding, never from the message.** A
channel is registered against one `EnvironmentScope` by an administrator, out of
band. There is deliberately no `--environment` in a chat command and no way to
type one: a message that can name its own scope can name `production` from a
channel registered for `staging`, and every other refusal in this codebase
becomes decorative the moment that is possible.

**An unbound channel is refused, not defaulted.** `DEFAULT_DENY_SCOPE` names a
scope no ordinary grant covers, so an unregistered channel reaches
`dispatch_chatops`, finds no role, and is refused by the same default-deny that
refuses a principal with no grants. The alternative — falling back to the author's
own scope — would let a principal who may run in `staging` run in `production` by
moving to an unregistered channel. That is a privilege escalation with a chat
client as the payload.

**A message is data, never syntax.** Everything after the verb must match
`IDENTIFIER`: letters, digits, and `` ._:/@+- ``. `$(rm -rf /)`, `` `id` ``,
`a; b`, and a newline are all refused with `chatops.argument_not_an_identifier`.
Same containment rule the workflow generator applies, arrived at from the other
end.

Two more refusals come from the same grammar:

| Rule | What it refuses |
| --- | --- |
| `chatops.unknown_command` | a verb that is not one of the three, or text that is not a command at all |
| `chatops.channel_not_bound` | a message or a binding with no channel id |

The refusal names the offending character class and lists the commands that *are*
accepted, so the person who typed it learns the grammar rather than just learning
that they were wrong.

### Ordering: an unauthorized approver never reaches validation

`dispatch_chatops` resolves the requester's roles *first*, and raises
`ChatOpsRefusedError` without ever calling the injected validator. This is a
security property, not a style choice: an approval typed into a channel by
somebody without the `approve` role must not reach the same validation a CLI
invocation reaches *and then* be refused downstream. The refusal belongs at the
door.

The tests prove it on a validator that records its calls — the refusal case
asserts zero calls — and then **prove the assertion is load-bearing** by stubbing
role resolution out and watching the same message dispatch. Without the second
half, "the spy was never wired up" and "authorization ran first" would look the
same.

### Validation is injected, never re-implemented

The bot takes a required `validate` callable and passes the request to it. There
is no default validator, because a default validator would be the second one. The
CLI and the chat path run the same code, which is what "dispatch through
identical validation" means concretely.

### What a refusal looks like

The bot returns `REFUSED` for **every** refusal — unparsable text, an unbound
channel, an unauthorized principal, a validation that did not gate — and returns
the detail to the caller. The channel gets the summary. A bot that distinguishes
its refusals to the channel leaks the authorization model to anybody who can post.

`NOT_A_COMMAND` is a *successful* parse: ordinary conversation in a channel the
bot is in must not be an error, and must not be a dispatch either.

### What does not exist

- **No Slack client. No Teams client.** `receive_message` takes a `ChatMessage`
  value and a registry; it opens no socket, holds no token, and has no notion of
  a workspace. The properties above are properties of pure functions and are
  tested with values.
- **No webhook signature verification.** There is no transport to verify one on.
  When an adapter lands, it must verify the forge's signature before
  `author_id` is trusted — `ChatMessage.author_id` is documented as the
  transport's *authenticated* user id, and an adapter that populates it from an
  unverified request body has turned the bot's identity into whatever somebody
  typed.

## Honesty gates

Restating the constraints, because a reference architecture is exactly where an
overclaim would hide:

1. **Generated is not working.** Every YAML in this plan is generated and
   unit-tested; none has run on a forge.
2. **No forge client, no chat client, no Terraform binary.** All three are
   unbound seams with fakes in the tests.
3. **No signature verification anywhere.** `SIGNATURE_VERIFICATION_IMPLEMENTED`
   is `False`. Packs are integrity-checked, not authenticated. Nothing in these
   architectures upgrades that.
4. **Zero `verified-live` faults, and it stays zero.** A fault appearing in a
   catalog is not a demonstration.
5. **Never gate production on uncertified faults.** A check on an uncertified
   fault warns; the reason is that a check red on every PR until the whole catalog
   is certified is a check people learn to ignore. What is unrepresentable is the
   opposite — an uncertified fault reported as certified — which `FaultClaim`
   refuses at construction. Gate on the certification state the check reported.
6. **Untrusted input reaches a shell only through the environment.** In a workflow
   that is `"$MAYHEM_…"`. In a chat command it is a regex. Neither is a quoting
   strategy.