export const VERSION = 1 as const;

export const DOMAINS = {
  task_commitment: "effect-transaction/0.1/task-commitment",
  effect_proposal: "effect-transaction/0.1/effect-proposal",
  authorization_decision: "effect-transaction/0.1/authorization-decision",
  execution_grant: "effect-transaction/0.1/execution-grant",
  effect_receipt: "effect-transaction/0.1/effect-receipt",
  reconciliation_record: "effect-transaction/0.1/reconciliation-record",
} as const;

export type Digest = `sha256:${string}`;

export interface TaskCommitment {
  version: 1;
  commitment_id: string;
  principal: string;
  objective_digest: Digest;
  constraints_digest: Digest;
  authority_scope_digest: Digest;
  policy_epoch: number;
  configuration_epoch: number;
  created_at_ms: number;
  expires_at_ms: number;
}

export interface EffectProposal {
  version: 1;
  proposal_id: string;
  commitment_hash: Digest;
  effect_profile: string;
  operation: string;
  target: string;
  arguments_digest: Digest;
  expected_effect_digest: Digest;
  pre_state_digest: Digest;
  resource_claim_digest: Digest;
  created_at_ms: number;
  expires_at_ms: number;
}

export type DecisionOutcome = "allow" | "deny" | "review";

export interface AuthorizationDecision {
  version: 1;
  decision_id: string;
  proposal_hash: Digest;
  evidence_hashes: Digest[];
  outcome: DecisionOutcome;
  reason_codes: string[];
  decided_at_ms: number;
  expires_at_ms: number;
}

export interface ExecutionGrant {
  version: 1;
  grant_id: string;
  proposal_hash: Digest;
  decision_hash: Digest;
  audience: string;
  not_before_ms: number;
  expires_at_ms: number;
  uses: 1;
  nonce: string;
}

export type ReceiptOutcome = "succeeded" | "failed" | "not_dispatched" | "unknown";

export interface EffectReceipt {
  version: 1;
  receipt_id: string;
  proposal_hash: Digest;
  grant_hash: Digest;
  attempt_id: string;
  claimed_at_ms: number;
  dispatched_at_ms: number | null;
  completed_at_ms: number;
  outcome: ReceiptOutcome;
  observation_digest: Digest;
}

export type ReconciliationOutcome =
  | "effect_confirmed"
  | "no_effect_confirmed"
  | "partial_effect"
  | "still_unknown"
  | "compensated";

export interface ReconciliationRecord {
  version: 1;
  reconciliation_id: string;
  receipt_hash: Digest;
  sequence: number;
  parent_reconciliation_hash: Digest | null;
  observed_at_ms: number;
  outcome: ReconciliationOutcome;
  evidence_digest: Digest;
}

export interface EffectTransactionBundle {
  commitment: TaskCommitment;
  proposal: EffectProposal;
  decision: AuthorizationDecision;
  grant?: ExecutionGrant | null;
  receipt?: EffectReceipt | null;
  reconciliations?: ReconciliationRecord[];
}

export interface VerifiedTransaction {
  commitment_hash: Digest;
  proposal_hash: Digest;
  decision_hash: Digest;
  grant_hash: Digest | null;
  receipt_hash: Digest | null;
  reconciliation_hashes: Digest[];
  state:
    | "decided"
    | "granted"
    | "succeeded"
    | "failed"
    | "not_dispatched"
    | "unknown"
    | ReconciliationOutcome;
}
