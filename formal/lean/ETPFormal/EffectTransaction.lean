/-!
A vendor-neutral abstract model of one effect transaction.

The model defines authorization and state transitions for one effect proposal.
A `TransactionState` contains the durable state for one `proposalId`.

These definitions and theorems do not claim refinement by any wire protocol,
store, executor, operating system, or concrete implementation.
-/

namespace EffectTransaction

abbrev ProposalId := Nat
abbrev GrantId := Nat
abbrev ReceiptId := Nat
abbrev Epoch := Nat

inductive AuthorizationOutcome where
  | allow
  | deny
  | review
deriving DecidableEq, Repr

inductive GrantPhase where
  | prepared
  | issued
  | claimed
  | dispatched
deriving DecidableEq, Repr

inductive EffectKnowledge where
  | notDispatched
  | applied
  | notApplied
  | unknown
  | compensated
deriving DecidableEq, Repr

inductive ExecutionOutcome where
  | notDispatched
  | succeeded
  | failed
  | unknown
deriving DecidableEq, Repr

/-- Reconciliation is append-once: a terminal record cannot have a child. -/
inductive ReconciliationStatus where
  | absent
  | terminal
deriving DecidableEq, Repr

/-- Trusted current context sampled atomically when a grant is claimed. -/
structure ClaimContext where
  policyEpoch : Epoch
  configurationEpoch : Epoch
  revoked : Bool
deriving DecidableEq, Repr

/-- Durable state for exactly one effect proposal. -/
structure TransactionState where
  proposalId : ProposalId
  authorization : AuthorizationOutcome
  policyEpoch : Epoch
  configurationEpoch : Epoch
  grantId : Option GrantId
  phase : GrantPhase
  receiptId : Option ReceiptId
  outcome : ExecutionOutcome
  knowledge : EffectKnowledge
  reconciliation : ReconciliationStatus
deriving DecidableEq, Repr

def prepare (proposalId : ProposalId) (authorization : AuthorizationOutcome)
    (policyEpoch configurationEpoch : Epoch) : TransactionState :=
  { proposalId
    authorization
    policyEpoch
    configurationEpoch
    grantId := none
    phase := .prepared
    receiptId := none
    outcome := .notDispatched
    knowledge := .notDispatched
    reconciliation := .absent }

def issueGrant (state : TransactionState) (grantId : GrantId) :
    Option TransactionState :=
  match state.authorization, state.grantId, state.phase with
  | .allow, none, .prepared =>
      some { state with grantId := some grantId, phase := .issued }
  | _, _, _ => none

/-- A claim requires equal epochs and no revocation. -/
def CurrentForClaim (state : TransactionState) (context : ClaimContext) : Prop :=
  context.policyEpoch = state.policyEpoch ∧
  context.configurationEpoch = state.configurationEpoch ∧
  context.revoked = false

instance currentForClaimDecidable (state : TransactionState)
    (context : ClaimContext) : Decidable (CurrentForClaim state context) := by
  unfold CurrentForClaim
  infer_instance

/-- Claim the current, non-revoked grant in one state transition. -/
def claimGrant (state : TransactionState) (grantId : GrantId)
    (context : ClaimContext) : Option TransactionState :=
  match state.grantId, state.phase with
  | some issuedGrantId, .issued =>
      if CurrentForClaim state context ∧ issuedGrantId = grantId then
        some { state with phase := .claimed }
      else
        none
  | _, _ => none

def dispatchGrant (state : TransactionState) (grantId : GrantId) :
    Option TransactionState :=
  match state.grantId, state.phase with
  | some claimedGrantId, .claimed =>
      if claimedGrantId = grantId then
        some { state with
          phase := .dispatched
          outcome := .unknown
          knowledge := .unknown }
      else
        none
  | _, _ => none

/-- Record one receipt. Reject `notDispatched` after dispatch. -/
def recordReceipt (state : TransactionState) (receiptId : ReceiptId)
    (outcome : ExecutionOutcome) : Option TransactionState :=
  match state.phase, state.receiptId, outcome with
  | .dispatched, none, .succeeded =>
      some { state with receiptId := some receiptId, outcome := .succeeded }
  | .dispatched, none, .failed =>
      some { state with receiptId := some receiptId, outcome := .failed }
  | .dispatched, none, .unknown =>
      some { state with receiptId := some receiptId, outcome := .unknown }
  | _, _, _ => none

def MayStartNewTransaction : EffectKnowledge → Prop
  | .notApplied => True
  | _ => False

def RequiresReconciliation : EffectKnowledge → Prop
  | .unknown => True
  | _ => False

inductive ReconciliationObservation where
  | applied
  | notApplied
deriving DecidableEq, Repr

/-- Reconciliation is accepted once, and only from unknown effect knowledge. -/
def reconcileTransaction (state : TransactionState)
    (observation : ReconciliationObservation) : Option TransactionState :=
  match state.knowledge, state.reconciliation, observation with
  | .unknown, .absent, .applied =>
      some { state with knowledge := .applied, reconciliation := .terminal }
  | .unknown, .absent, .notApplied =>
      some { state with knowledge := .notApplied, reconciliation := .terminal }
  | _, _, _ => none

def GrantConsumed (state : TransactionState) : Prop :=
  state.phase = .claimed ∨ state.phase = .dispatched

def OutcomeConsistent (state : TransactionState) : Prop :=
  match state.outcome with
  | .notDispatched => state.phase ≠ .dispatched
  | .succeeded => state.phase = .dispatched
  | .failed => state.phase = .dispatched
  | .unknown => state.phase = .dispatched

theorem only_allow_authorizes_grant {state next : TransactionState}
    {grantId : GrantId}
    (h : issueGrant state grantId = some next) :
    state.authorization = .allow := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases authorization <;> cases existingGrant <;> cases phase <;>
        simp [issueGrant] at h ⊢

theorem one_proposal_cannot_issue_two_grants {state afterFirst : TransactionState}
    {firstGrantId : GrantId}
    (h : issueGrant state firstGrantId = some afterFirst)
    (secondGrantId : GrantId) :
    issueGrant afterFirst secondGrantId = none := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases authorization <;> cases existingGrant <;> cases phase <;>
        simp [issueGrant] at h
      subst afterFirst
      rfl

theorem successful_claim_requires_current_policy_configuration_and_nonrevocation
    {state afterClaim : TransactionState} {grantId : GrantId}
    {context : ClaimContext}
    (h : claimGrant state grantId context = some afterClaim) :
    context.policyEpoch = state.policyEpoch ∧
    context.configurationEpoch = state.configurationEpoch ∧
    context.revoked = false := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases existingGrant <;> cases phase <;>
        simp [claimGrant, CurrentForClaim] at h ⊢
      exact h.1.1

theorem revoked_grant_cannot_be_claimed (state : TransactionState)
    (grantId : GrantId) (context : ClaimContext)
    (hRevoked : context.revoked = true) :
    claimGrant state grantId context = none := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases existingGrant <;> cases phase <;>
        simp [claimGrant, CurrentForClaim, hRevoked]

theorem claimed_grant_cannot_be_claimed_again
    {state afterClaim : TransactionState} {grantId : GrantId}
    {context : ClaimContext}
    (h : claimGrant state grantId context = some afterClaim) :
    claimGrant afterClaim grantId context = none := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases existingGrant with
      | none => simp [claimGrant] at h
      | some issuedGrantId =>
          cases phase <;> simp [claimGrant] at h
          rcases h with ⟨_, rfl, rfl⟩
          rfl

theorem dispatch_requires_claim {state next : TransactionState}
    {grantId : GrantId}
    (h : dispatchGrant state grantId = some next) :
    state.phase = .claimed := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases existingGrant <;> cases phase <;> simp [dispatchGrant] at h ⊢

theorem no_dispatch_before_claim (state : TransactionState) (grantId : GrantId)
    (h : state.phase ≠ .claimed) :
    dispatchGrant state grantId = none := by
  cases hResult : dispatchGrant state grantId with
  | none => rfl
  | some next => exact False.elim (h (dispatch_requires_claim hResult))

theorem consumed_grant_cannot_be_reissued (state : TransactionState)
    (h : GrantConsumed state) (grantId : GrantId) :
    issueGrant state grantId = none := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      simp [GrantConsumed] at h
      rcases h with rfl | rfl <;> simp [issueGrant]

theorem consumed_grant_never_reactivated (state : TransactionState)
    (h : GrantConsumed state) :
    ∀ grantId, issueGrant state grantId = none := by
  intro grantId
  exact consumed_grant_cannot_be_reissued state h grantId

theorem one_dispatch_has_at_most_one_receipt
    {state afterFirst : TransactionState} {firstReceiptId : ReceiptId}
    {firstOutcome : ExecutionOutcome}
    (h : recordReceipt state firstReceiptId firstOutcome = some afterFirst)
    (secondReceiptId : ReceiptId) (secondOutcome : ExecutionOutcome) :
    recordReceipt afterFirst secondReceiptId secondOutcome = none := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch grantId phase
      existingReceipt outcome knowledge reconciliation =>
      cases phase <;> cases existingReceipt <;> cases firstOutcome <;>
        simp [recordReceipt] at h
      all_goals subst afterFirst <;> cases secondOutcome <;> rfl

theorem not_dispatched_outcome_implies_no_dispatch {state : TransactionState}
    (hConsistent : OutcomeConsistent state)
    (hOutcome : state.outcome = .notDispatched) :
    state.phase ≠ .dispatched := by
  simp [OutcomeConsistent, hOutcome] at hConsistent
  exact hConsistent

theorem succeeded_outcome_implies_dispatch {state : TransactionState}
    (hConsistent : OutcomeConsistent state)
    (hOutcome : state.outcome = .succeeded) :
    state.phase = .dispatched := by
  simp [OutcomeConsistent, hOutcome] at hConsistent
  exact hConsistent

theorem failed_outcome_implies_dispatch {state : TransactionState}
    (hConsistent : OutcomeConsistent state)
    (hOutcome : state.outcome = .failed) :
    state.phase = .dispatched := by
  simp [OutcomeConsistent, hOutcome] at hConsistent
  exact hConsistent

theorem successful_dispatch_is_outcome_consistent
    {state afterDispatch : TransactionState} {grantId : GrantId}
    (h : dispatchGrant state grantId = some afterDispatch) :
    OutcomeConsistent afterDispatch := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch existingGrant
      phase receiptId outcome knowledge reconciliation =>
      cases existingGrant with
      | none => simp [dispatchGrant] at h
      | some claimedGrantId =>
          cases phase <;> simp [dispatchGrant] at h
          rcases h with ⟨rfl, rfl⟩
          simp [OutcomeConsistent]

theorem receipt_recording_preserves_outcome_consistency
    {state afterReceipt : TransactionState} {receiptId : ReceiptId}
    {outcome : ExecutionOutcome}
    (h : recordReceipt state receiptId outcome = some afterReceipt) :
    OutcomeConsistent afterReceipt := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch grantId phase
      existingReceipt priorOutcome knowledge reconciliation =>
      cases phase <;> cases existingReceipt <;> cases outcome <;>
        simp [recordReceipt] at h
      all_goals subst afterReceipt <;> simp [OutcomeConsistent]

theorem reconciliation_only_from_unknown
    {state afterReconciliation : TransactionState}
    {observation : ReconciliationObservation}
    (h : reconcileTransaction state observation = some afterReconciliation) :
    state.knowledge = .unknown := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch grantId phase
      receiptId outcome knowledge reconciliation =>
      cases knowledge <;> cases reconciliation <;> cases observation <;>
        simp [reconcileTransaction] at h ⊢

theorem terminal_reconciliation_has_no_child (state : TransactionState)
    (observation : ReconciliationObservation)
    (hTerminal : state.reconciliation = .terminal) :
    reconcileTransaction state observation = none := by
  cases state with
  | mk proposalId authorization policyEpoch configurationEpoch grantId phase
      receiptId outcome knowledge reconciliation =>
      cases knowledge <;> cases reconciliation <;> cases observation <;>
        simp [reconcileTransaction] at hTerminal ⊢

theorem not_dispatched_is_distinct_from_unknown :
    EffectKnowledge.notDispatched ≠ .unknown := by
  decide

theorem unknown_cannot_start_new_transaction :
    ¬ MayStartNewTransaction .unknown := by
  simp [MayStartNewTransaction]

theorem unknown_requires_reconciliation :
    RequiresReconciliation .unknown := by
  simp [RequiresReconciliation]

theorem reconciliation_is_required_before_new_transaction :
    RequiresReconciliation .unknown ∧ ¬ MayStartNewTransaction .unknown := by
  exact ⟨unknown_requires_reconciliation, unknown_cannot_start_new_transaction⟩

theorem applied_observation_resolves_unknown
    (state : TransactionState)
    (hKnowledge : state.knowledge = .unknown)
    (hNoReconciliation : state.reconciliation = .absent) :
    ∃ next, reconcileTransaction state .applied = some next ∧
      next.knowledge = .applied ∧ next.reconciliation = .terminal := by
  refine ⟨{ state with knowledge := .applied, reconciliation := .terminal }, ?_⟩
  simp [reconcileTransaction, hKnowledge, hNoReconciliation]

theorem confirmed_non_application_allows_new_transaction
    (state : TransactionState)
    (hKnowledge : state.knowledge = .unknown)
    (hNoReconciliation : state.reconciliation = .absent) :
    ∃ next, reconcileTransaction state .notApplied = some next ∧
      MayStartNewTransaction next.knowledge := by
  refine ⟨{ state with knowledge := .notApplied, reconciliation := .terminal }, ?_⟩
  simp [reconcileTransaction, MayStartNewTransaction, hKnowledge,
    hNoReconciliation]

end EffectTransaction
