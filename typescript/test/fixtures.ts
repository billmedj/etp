import {
  hashAuthorizationDecision,
  hashEffectProposal,
  hashEffectReceipt,
  hashExecutionGrant,
  hashReconciliationRecord,
  hashTaskCommitment,
} from "../src/verify.ts";
import type {
  AuthorizationDecision,
  EffectProposal,
  EffectReceipt,
  EffectTransactionBundle,
  ExecutionGrant,
  ReconciliationRecord,
  TaskCommitment,
} from "../src/model.ts";

const digest = (pair: string) => `sha256:${pair.repeat(32)}` as const;

export function validTransaction(): EffectTransactionBundle {
  const commitment: TaskCommitment = {
    version: 1,
    commitment_id: "commitment-01",
    principal: "user:alice@example.test",
    objective_digest: digest("11"),
    constraints_digest: digest("22"),
    authority_scope_digest: digest("33"),
    policy_epoch: 7,
    configuration_epoch: 12,
    created_at_ms: 1760000000000,
    expires_at_ms: 1760000900000,
  };
  const proposal: EffectProposal = {
    version: 1,
    proposal_id: "proposal-01",
    commitment_hash: hashTaskCommitment(commitment),
    effect_profile: "io.effect-transaction.http.v1",
    operation: "post",
    target: "https://api.example.test/deployments",
    arguments_digest: digest("44"),
    expected_effect_digest: digest("55"),
    pre_state_digest: digest("66"),
    resource_claim_digest: digest("77"),
    created_at_ms: 1760000001000,
    expires_at_ms: 1760000600000,
  };
  const decision: AuthorizationDecision = {
    version: 1,
    decision_id: "decision-01",
    proposal_hash: hashEffectProposal(proposal),
    evidence_hashes: [digest("88"), digest("99")],
    outcome: "allow",
    reason_codes: ["policy.allow"],
    decided_at_ms: 1760000002000,
    expires_at_ms: 1760000300000,
  };
  const grant: ExecutionGrant = {
    version: 1,
    grant_id: "grant-01",
    proposal_hash: hashEffectProposal(proposal),
    decision_hash: hashAuthorizationDecision(decision),
    audience: "executor:edge-01",
    not_before_ms: 1760000003000,
    expires_at_ms: 1760000060000,
    uses: 1,
    nonce: "7f9a99c1AQIDBAUGBwgJCg",
  };
  const receipt: EffectReceipt = {
    version: 1,
    receipt_id: "receipt-01",
    proposal_hash: hashEffectProposal(proposal),
    grant_hash: hashExecutionGrant(grant),
    attempt_id: "attempt-01",
    claimed_at_ms: 1760000004000,
    dispatched_at_ms: 1760000004100,
    completed_at_ms: 1760000009000,
    outcome: "unknown",
    observation_digest: digest("aa"),
  };
  const first: ReconciliationRecord = {
    version: 1,
    reconciliation_id: "reconciliation-01",
    receipt_hash: hashEffectReceipt(receipt),
    sequence: 1,
    parent_reconciliation_hash: null,
    observed_at_ms: 1760000010000,
    outcome: "still_unknown",
    evidence_digest: digest("bb"),
  };
  const second: ReconciliationRecord = {
    version: 1,
    reconciliation_id: "reconciliation-02",
    receipt_hash: hashEffectReceipt(receipt),
    sequence: 2,
    parent_reconciliation_hash: hashReconciliationRecord(first),
    observed_at_ms: 1760000020000,
    outcome: "effect_confirmed",
    evidence_digest: digest("cc"),
  };
  return {
    commitment,
    proposal,
    decision,
    grant,
    receipt,
    reconciliations: [first, second],
  };
}
