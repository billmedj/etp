# ETP terminology and writing rules

This document defines the public language for ETP specifications, code, and
documentation. The rules use principles from controlled technical English.
They do not claim compliance with ASD-STE100.

## Writing rules

1. Use one term for one concept.
2. Use the active voice when the actor is known.
3. Put one requirement in each sentence.
4. Use short sentences. Prefer 25 words or fewer.
5. Use a direct verb. Avoid noun phrases that hide the action.
6. Name the actor when a pronoun could be unclear.
7. State the condition before the required action.
8. Use lists for procedures, inputs, outputs, and failure conditions.
9. Use `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` only as defined
   by BCP 14.
10. Use ASCII punctuation in public Markdown files.

Do not use slogans, rhetorical questions, metaphors, or promotional claims in
technical documents. Do not use words such as "revolutionary", "bulletproof",
or "world-class" as technical evidence.

## Protocol terms

| Term | Meaning |
| --- | --- |
| task commitment | The record that binds the principal, task documents, authority scope, epochs, and validity interval. |
| effect proposal | The record that identifies one requested operation, target, arguments, expected result, pre-state, and resource claim. |
| authorization decision | The `allow`, `deny`, or `review` result for one effect proposal. |
| execution grant | Short-lived authority for one executor audience to claim one effect proposal. |
| claim | The durable, atomic transition that consumes an execution grant and creates one attempt. |
| attempt | One claimed opportunity to cross the dispatch boundary. |
| dispatch boundary | The point after which an external effect can occur. |
| dispatch marker | A durable record that the executor reached the dispatch boundary. A marker does not prove target acceptance. |
| effect receipt | The canonical ledger record for the observed outcome of one attempt. A receipt does not prove external truth. |
| unknown outcome | The state used when the executor cannot establish whether the effect occurred. |
| reconciliation | An append-only process that adds evidence about an unknown outcome. |
| currentness | Agreement between the grant bindings and the active policy, configuration, revocation state, target state, and trusted time. |
| effect profile | A versioned contract for target identity, committed documents, dispatch, observation, and reconciliation. |
| authority assertion | An authenticated statement that binds one protocol record to a role, signer, audience, epoch, and validity interval. |
| executor audience | The trust-domain identifier of the executor that may claim the grant. |

## Restricted wording

Use these rules in specifications and implementation text:

- Use "exact" only for equality of bytes, fields, identifiers, or committed
  values.
- Use "canonical ledger receipt" instead of "authoritative receipt". The
  latter can imply that the receipt proves external truth.
- Describe the evidence rule instead of using "honest receipt" or "honest
  outcome".
- Use "separately implemented" for implementations maintained in this
  repository. Reserve "independent implementation" for an implementation with
  independent ownership and maintenance.
- Use "native ETP mediation" only when the ETP claim is the sole authority to
  cross the dispatch boundary.
- State the rejected input or transition when you use "fail closed".
- Use "validated evidence" only when a named verifier, trust policy, and effect
  profile define the validation.
- Use "production ready" only after the deployment profile, operational tests,
  key management, complete mediation, and external review are complete.

## Claim rules

Every security claim must identify these items:

- the component that enforces the property;
- the trust assumptions;
- the protected boundary;
- the failure behavior;
- the evidence or test that supports the claim; and
- the known limits.

Formal-model results must state the model, configuration, and bound. They must
not imply refinement to an implementation unless a refinement argument exists.

Conformance results must identify the tested profile and test corpus. A passing
reference implementation does not establish ecosystem interoperability.
