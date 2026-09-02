------------------------- MODULE EffectTransaction -------------------------
EXTENDS Naturals

(***************************************************************************
Vendor-neutral bounded safety model for one Effect Transaction Protocol
grant. Hashes, signatures, JSON encodings, and database rows are abstracted as
facts established before the transitions below. The model focuses on the
concurrent issuance, currentness, claim, dispatch, receipt, and reconciliation
state machine. This model does not prove implementation refinement.
***************************************************************************)

CONSTANTS MaxTime, MaxEpoch, MaxReconciliations

Workers == {"executor-a", "executor-b"}
DecisionOutcomes == {"PENDING", "ALLOW", "DENY", "REVIEW"}
GrantStates == {"NONE", "ISSUED", "CLAIMED", "DISPATCH_STARTED", "TERMINAL"}
ReceiptOutcomes == {"NONE", "NOT_DISPATCHED", "SUCCEEDED", "FAILED", "UNKNOWN"}
ReconciliationOutcomes == {
    "NONE",
    "EFFECT_CONFIRMED",
    "NO_EFFECT_CONFIRMED",
    "PARTIAL_EFFECT",
    "STILL_UNKNOWN",
    "COMPENSATED"
}
TerminalReconciliationOutcomes == {
    "EFFECT_CONFIRMED",
    "NO_EFFECT_CONFIRMED",
    "COMPENSATED"
}

VARIABLES
    now,
    policyEpoch,
    configurationEpoch,
    revocationEpoch,
    decision,
    grantState,
    grantPolicyEpoch,
    grantConfigurationEpoch,
    grantRevocationEpoch,
    grantCount,
    claimOwner,
    claimCount,
    policyEpochAtClaim,
    configurationEpochAtClaim,
    revocationEpochAtClaim,
    dispatchCount,
    receiptOutcome,
    receiptCount,
    reconciliationCount,
    reconciliationHead,
    terminalAt

vars == <<
    now,
    policyEpoch,
    configurationEpoch,
    revocationEpoch,
    decision,
    grantState,
    grantPolicyEpoch,
    grantConfigurationEpoch,
    grantRevocationEpoch,
    grantCount,
    claimOwner,
    claimCount,
    policyEpochAtClaim,
    configurationEpochAtClaim,
    revocationEpochAtClaim,
    dispatchCount,
    receiptOutcome,
    receiptCount,
    reconciliationCount,
    reconciliationHead,
    terminalAt
>>

Init ==
    /\ now = 0
    /\ policyEpoch = 0
    /\ configurationEpoch = 0
    /\ revocationEpoch = 0
    /\ decision = "PENDING"
    /\ grantState = "NONE"
    /\ grantPolicyEpoch = MaxEpoch + 1
    /\ grantConfigurationEpoch = MaxEpoch + 1
    /\ grantRevocationEpoch = MaxEpoch + 1
    /\ grantCount = 0
    /\ claimOwner = "NONE"
    /\ claimCount = 0
    /\ policyEpochAtClaim = MaxEpoch + 1
    /\ configurationEpochAtClaim = MaxEpoch + 1
    /\ revocationEpochAtClaim = MaxEpoch + 1
    /\ dispatchCount = 0
    /\ receiptOutcome = "NONE"
    /\ receiptCount = 0
    /\ reconciliationCount = 0
    /\ reconciliationHead = "NONE"
    /\ terminalAt = 0

Decide(outcome) ==
    /\ outcome \in {"ALLOW", "DENY", "REVIEW"}
    /\ decision = "PENDING"
    /\ decision' = outcome
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        grantState,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

Issue ==
    /\ decision = "ALLOW"
    /\ grantState = "NONE"
    /\ now < MaxTime
    /\ grantState' = "ISSUED"
    /\ grantPolicyEpoch' = policyEpoch
    /\ grantConfigurationEpoch' = configurationEpoch
    /\ grantRevocationEpoch' = revocationEpoch
    /\ grantCount' = grantCount + 1
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

Claim(worker) ==
    /\ worker \in Workers
    /\ grantState = "ISSUED"
    /\ now < MaxTime
    /\ policyEpoch = grantPolicyEpoch
    /\ configurationEpoch = grantConfigurationEpoch
    /\ revocationEpoch = grantRevocationEpoch
    /\ grantState' = "CLAIMED"
    /\ claimOwner' = worker
    /\ claimCount' = claimCount + 1
    /\ policyEpochAtClaim' = policyEpoch
    /\ configurationEpochAtClaim' = configurationEpoch
    /\ revocationEpochAtClaim' = revocationEpoch
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

StartDispatch(worker) ==
    /\ worker \in Workers
    /\ grantState = "CLAIMED"
    /\ claimOwner = worker
    /\ grantState' = "DISPATCH_STARTED"
    /\ dispatchCount' = dispatchCount + 1
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

RecordBeforeDispatch(outcome) ==
    /\ outcome \in {"NOT_DISPATCHED", "UNKNOWN"}
    /\ grantState = "CLAIMED"
    /\ receiptOutcome = "NONE"
    /\ grantState' = "TERMINAL"
    /\ receiptOutcome' = outcome
    /\ receiptCount' = receiptCount + 1
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

RecordAfterDispatch(outcome) ==
    /\ outcome \in {"SUCCEEDED", "FAILED", "UNKNOWN"}
    /\ grantState = "DISPATCH_STARTED"
    /\ receiptOutcome = "NONE"
    /\ grantState' = "TERMINAL"
    /\ receiptOutcome' = outcome
    /\ receiptCount' = receiptCount + 1
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

AppendReconciliation(outcome) ==
    /\ outcome \in ReconciliationOutcomes \ {"NONE"}
    /\ receiptOutcome = "UNKNOWN"
    /\ reconciliationCount < MaxReconciliations
    /\ terminalAt = 0
    /\ reconciliationCount' = reconciliationCount + 1
    /\ reconciliationHead' = outcome
    /\ terminalAt' =
        IF outcome \in TerminalReconciliationOutcomes
        THEN reconciliationCount + 1
        ELSE 0
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantState,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount
        >>

AdvanceClock ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<
        policyEpoch,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantState,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

RotatePolicy ==
    /\ policyEpoch < MaxEpoch
    /\ policyEpoch' = policyEpoch + 1
    /\ UNCHANGED <<
        now,
        configurationEpoch,
        revocationEpoch,
        decision,
        grantState,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

RotateConfiguration ==
    /\ configurationEpoch < MaxEpoch
    /\ configurationEpoch' = configurationEpoch + 1
    /\ UNCHANGED <<
        now,
        policyEpoch,
        revocationEpoch,
        decision,
        grantState,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

Revoke ==
    /\ revocationEpoch < MaxEpoch
    /\ revocationEpoch' = revocationEpoch + 1
    /\ UNCHANGED <<
        now,
        policyEpoch,
        configurationEpoch,
        decision,
        grantState,
        grantPolicyEpoch,
        grantConfigurationEpoch,
        grantRevocationEpoch,
        grantCount,
        claimOwner,
        claimCount,
        policyEpochAtClaim,
        configurationEpochAtClaim,
        revocationEpochAtClaim,
        dispatchCount,
        receiptOutcome,
        receiptCount,
        reconciliationCount,
        reconciliationHead,
        terminalAt
        >>

Stutter == UNCHANGED vars

Next ==
    \/ \E outcome \in {"ALLOW", "DENY", "REVIEW"} : Decide(outcome)
    \/ Issue
    \/ \E worker \in Workers : Claim(worker)
    \/ \E worker \in Workers : StartDispatch(worker)
    \/ \E outcome \in {"NOT_DISPATCHED", "UNKNOWN"} : RecordBeforeDispatch(outcome)
    \/ \E outcome \in {"SUCCEEDED", "FAILED", "UNKNOWN"} : RecordAfterDispatch(outcome)
    \/ \E outcome \in ReconciliationOutcomes \ {"NONE"} : AppendReconciliation(outcome)
    \/ AdvanceClock
    \/ RotatePolicy
    \/ RotateConfiguration
    \/ Revoke
    \/ Stutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 0..MaxTime
    /\ policyEpoch \in 0..MaxEpoch
    /\ configurationEpoch \in 0..MaxEpoch
    /\ revocationEpoch \in 0..MaxEpoch
    /\ decision \in DecisionOutcomes
    /\ grantState \in GrantStates
    /\ grantPolicyEpoch \in 0..(MaxEpoch + 1)
    /\ grantConfigurationEpoch \in 0..(MaxEpoch + 1)
    /\ grantRevocationEpoch \in 0..(MaxEpoch + 1)
    /\ grantCount \in 0..1
    /\ claimOwner \in Workers \cup {"NONE"}
    /\ claimCount \in 0..1
    /\ policyEpochAtClaim \in 0..(MaxEpoch + 1)
    /\ configurationEpochAtClaim \in 0..(MaxEpoch + 1)
    /\ revocationEpochAtClaim \in 0..(MaxEpoch + 1)
    /\ dispatchCount \in 0..1
    /\ receiptOutcome \in ReceiptOutcomes
    /\ receiptCount \in 0..1
    /\ reconciliationCount \in 0..MaxReconciliations
    /\ reconciliationHead \in ReconciliationOutcomes
    /\ terminalAt \in 0..MaxReconciliations

OnlyAllowIssues == grantCount = 1 => decision = "ALLOW"

AtMostOneGrant == grantCount <= 1

AtMostOneClaim == claimCount <= 1

AtMostOneDispatch == dispatchCount <= 1

AtMostOneReceipt == receiptCount <= 1

ClaimRequiresIssuedGrant == claimCount = 1 => grantCount = 1

ClaimUsedCurrentEpochs ==
    claimCount = 1 =>
        /\ policyEpochAtClaim = grantPolicyEpoch
        /\ configurationEpochAtClaim = grantConfigurationEpoch
        /\ revocationEpochAtClaim = grantRevocationEpoch

DispatchRequiresClaim == dispatchCount = 1 => claimCount = 1

ReceiptRequiresClaim == receiptCount = 1 => claimCount = 1

NotDispatchedRequiresNoDispatch ==
    receiptOutcome = "NOT_DISPATCHED" => dispatchCount = 0

SuccessfulOrFailedRequiresDispatch ==
    receiptOutcome \in {"SUCCEEDED", "FAILED"} => dispatchCount = 1

ReconciliationRequiresUnknown ==
    reconciliationCount > 0 => receiptOutcome = "UNKNOWN"

TerminalReconciliationIsAbsorbing ==
    terminalAt > 0 => reconciliationCount = terminalAt

ConsumedGrantNeverReturnsToIssued ==
    claimCount = 1 => grantState \in {"CLAIMED", "DISPATCH_STARTED", "TERMINAL"}

=============================================================================
