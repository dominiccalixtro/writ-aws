# terraform/bootstrap

Defines the sandbox-account broker identity: docs/IMPLEMENTATION_PLAN.md sec. 4.

Not yet implemented. When it is, this module is the *only* place the broker
role, its permissions boundary, and its explicit deny statements (sec. 4.2.3)
are defined — console-created identities are prohibited (sec. 4.2.1).

Required resources before Phase 0 is complete (sec. 10, A0.1-A0.3):

- broker IAM role, sandbox account only (sec. 4.1.3 — never in the management
  account; SCPs do not restrict the management account)
- permissions boundary policy (sec. 4.2.2)
- explicit `Deny` statements: escalation, evidence-integrity, boundary-escape
  actions (sec. 4.2.3)
- SCP on the sandbox account's OU capable of denying the broker role
  everything — the quash path (sec. 4.3)
- budget alert + hard budget alarm (sec. 4.4.1), created before anything
  billable

This directory intentionally has no `.tf` files yet and is not run by any
test. `terraform plan` here requires a live AWS Organization (sec. 4.1) that
does not exist until a human provisions it.
