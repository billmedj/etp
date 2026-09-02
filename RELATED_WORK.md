# Related systems

ETP does not replace identity, authorization, attestation, sandboxing, or
workflow systems. It connects these systems at the boundary of one external
effect proposed by an untrusted agent.

This document compares ETP with adjacent work. Links point to primary
specifications or papers when available.

## Comparison

| System or research area | Established function | Use with ETP | Claim boundary |
| --- | --- | --- | --- |
| [Model Context Protocol](https://modelcontextprotocol.io/specification/latest) | Standardizes how agent hosts connect to resources, prompts, and tools | An ETP gateway can turn an MCP tool call into a typed effect proposal and mediate its execution | MCP discovery and transport do not provide ETP's state binding, durable single-use claim, receipt, or reconciliation |
| [Open Policy Agent](https://www.openpolicyagent.org/docs) and [Cedar](https://docs.cedarpolicy.com/) | Evaluate structured authorization requests against policy | An ETP evaluator can use either engine to decide a proposal and record the policy evidence | A policy decision is not a durable execution grant and does not establish dispatch or outcome evidence |
| [OAuth Rich Authorization Requests, RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) | Carries detailed authorization data, such as actions and locations | An effect profile can map a typed effect to RAR details. An evaluator can also accept an RAR decision as authenticated evidence. ETP also binds pre-state, expected effect, a single-use claim, receipt, and reconciliation | ETP does not replace OAuth delegation |
| [OAuth DPoP, RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | Sender-constrains OAuth tokens with proof of possession and request-bound nonces | DPoP can authenticate grant presentation at an HTTP boundary. ETP binds a grant to a complete effect chain, an executor audience, and durable consumption | A nonce and audience do not prove possession. ETP requires an authenticated envelope or transport profile |
| [Macaroons](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/) and [Biscuit](https://doc.biscuitsec.org/reference/specifications) | Support contextual caveats or offline attenuation of delegated authority | They can express delegated authority that is narrowed into an ETP task commitment or grant | ETP Core does not define a general delegation or attenuation language |
| [SPIFFE](https://spiffe.io/docs/latest/spiffe-specs/) | Defines workload identity and trust-domain federation | A deployment can use a SPIFFE ID as an authenticated executor audience. It can use an SVID to secure transport or key delivery | An audience string is not a workload identity. ETP does not replace SPIFFE or SPIRE |
| [Zanzibar](https://www.usenix.org/conference/atc19/presentation/pang) | Provides externally consistent authorization over distributed relationship data | A Zanzibar-style system can provide policy currentness and causal tokens at the ETP claim boundary | ETP reference stores do not provide Zanzibar scale, availability, or global consistency |
| [in-toto Attestation Framework](https://github.com/in-toto/attestation), [SLSA](https://slsa.dev/spec/v1.2/), and [DSSE](https://github.com/secure-systems-lab/dsse) | Define authenticated statements and software supply-chain provenance | Standard attestation envelopes can carry ETP records. An evaluator can accept supply-chain attestations as evidence | A signed statement does not prove that its content is true or current |
| [SCITT architecture, RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) | Defines transparent registration of signed statements and receipts | A deployment can anchor terminal ETP records or checkpoints in a SCITT service. This can expose history rollback or equivocation | ETP 0.1 does not provide a transparency log or consensus |
| [RATS architecture, RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) and [Entity Attestation Token, RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) | Define evidence and appraisal for remote attestation | A deployment profile can admit attested executor identity or platform state as evidence | ETP does not prove hardware, firmware, process, or workload integrity |
| [The Update Framework](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md) | Resists rollback, freeze, mix-and-match, and key-compromise attacks | ETP uses strict versions, validity intervals, role separation, and fail-closed downgrade handling | ETP 0.1 does not provide TUF repositories, delegation, or threshold-key lifecycle |
| [Reliable State Machines](https://arxiv.org/abs/1902.09502) and durable-execution systems | Use durable logs and replay to make local state-machine processing resistant to process failure | ETP defines state and evidence around an external effect that cannot share the local transaction | ETP cannot provide exactly-once delivery to an arbitrary remote target. An ambiguous dispatch has outcome `unknown` |
| [AgentDojo](https://proceedings.neurips.cc/paper_files/paper/2024/file/97091a5177d8dc64b1da8bf3e1f6fb54-Paper-Datasets_and_Benchmarks_Track.pdf) | Provides tasks and attacks for prompt-injected tool-agent evaluation | It can measure the security and utility of an ETP-integrated agent | Protocol conformance vectors are not a prompt-injection benchmark |
| [CaMeL](https://arxiv.org/abs/2503.18813) | Separates control flow from data flow and attaches capabilities to values | CaMeL-style provenance can inform an ETP evaluator. ETP adds durable, state-bound execution and outcome records | ETP does not provide information-flow control or prove prompt-injection resistance |

## Protocol boundary

Adjacent systems provide different functions:

- **Identity:** authenticate the requester.
- **Authorization:** define the action categories available to a principal.
- **Attestation:** identify the source of a statement about an artifact or
  environment.
- **Information flow:** control which data can affect control flow or cross a
  boundary.
- **Durable execution:** continue program state after a failure.
- **Audit transparency:** expose hidden or changed signed history.

ETP determines whether one executor can attempt one exact effect against one
observed state. It also records what the available evidence establishes about
the outcome.

Effect profiles define domain-specific behavior. ETP Core defines the common
transaction and uncertainty rules.

## Design requirements

The comparison gives these requirements:

1. Use standard authenticated envelopes and workload identities.
2. Do not treat a hash as authentication.
3. Keep authorization evidence separate from execution authority.
4. Serialize policy, configuration, and revocation currentness with the claim.
   Alternatively, use a fail-closed causal fence.
5. Preserve `unknown` when evidence cannot resolve external delivery.
6. Use a profile-specific conditional write or fencing token for each mutable
   target.
7. Add transparency, threshold approval, hardware attestation, and delegated
   authorization through profiles. Do not add them to the Core format.
8. Test semantic and prompt-injection controls with adversarial agent
   benchmarks. Protocol tests do not prove these controls.

## Contribution boundary

The individual mechanisms in this document are established. ETP combines them
in a portable record chain and executor state machine for agent-proposed
effects. The combination binds:

- task authority;
- a typed effect and observed pre-state;
- independent authorization evidence;
- single-use execution authority;
- durable dispatch ordering;
- profile-defined outcome evidence;
- fork-free reconciliation after an uncertain outcome.

A research novelty claim requires a systematic literature review and external
peer review. This repository claims an implemented protocol design. It does
not claim priority over all prior systems.
