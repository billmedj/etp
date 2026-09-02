# Kubernetes JSON Patch effect profile 0.1

**Status:** Implementer draft
**Identifier:** `effect-transaction/kubernetes-json-patch/0.1`

This profile defines one RFC 6902 JSON Patch mutation on one existing
Kubernetes object. It binds the mutation to these values:

- cluster trust domain;
- Kubernetes API path;
- object UID;
- `resourceVersion`; and
- exact patch bytes.

## Target identity

The target format is:

```text
k8s://<cluster-trust-domain>/<api-path>?uid=<uid>
```

An administrator MUST configure the cluster trust domain. The executor MUST
NOT use a model-supplied server address.

`api-path` is the canonical API path for one named object. It includes the API
group, version, namespace when applicable, resource, name, and optional
subresource. The target MUST contain the object UID.

This profile does not permit collections, generated-name creates, redirects,
proxy endpoints, `exec`, `attach`, or paths outside the committed resource.

## Profile documents

The arguments document uses media type `application/json-patch+json`. It
contains the ordered RFC 6902 operation array. The first two operations MUST
be:

```json
[
  {"op": "test", "path": "/metadata/uid", "value": "<committed uid>"},
  {"op": "test", "path": "/metadata/resourceVersion", "value": "<committed resourceVersion>"}
]
```

Later operations MAY modify only the paths allowed by the task and policy.
They MUST NOT overwrite `/metadata/uid`, `/metadata/resourceVersion`, or an
ancestor of either field.

This profile does not permit server-side apply, force-conflict options, or
dry-run substitution. It also prohibits a retry that uses a new
`resourceVersion` under the same grant.

The pre-state document binds the cluster trust domain, API path, UID,
`resourceVersion`, and canonical object digest. The resource claim repeats the
object identity and defines the permitted JSON Pointer write set. The expected
effect defines postconditions for the returned or observed object.

## Dispatch and observation

Before dispatch, the executor MUST read the object through the pinned cluster
identity. It MUST verify the UID, `resourceVersion`, object digest, active
epochs, and resource claim. It MUST then claim the ETP grant.

The executor MUST record the `dispatch_started` state before the first PATCH byte
can leave the process. This durable journal update is the dispatch boundary.

A failed UID or `resourceVersion` test produces a `failed` receipt. The
executor MUST NOT rebuild the patch against new state under the same grant.

A response produces a `succeeded` receipt only after the executor verifies the
object identity and all committed postconditions. A timeout, lost response,
failover ambiguity, or unattributed state produces an `unknown` receipt.

Reconciliation MUST use the same pinned cluster identity and object UID. It
MAY use an audit event or a mutation marker. The profile MUST define and
validate any marker. Matching field values alone do not establish attribution.

## Security considerations and limitations

This profile does not replace Kubernetes authentication, authorization,
admission control, audit policy, workload identity, or control-plane security.
It does not make a multi-object operation atomic.

Controllers can change unrelated fields. The write set and postconditions
MUST distinguish relevant changes from unrelated changes.

Kubernetes describes JSON Patch tests and `resourceVersion` in
[API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/).
The patch and path formats are defined by
[RFC 6902](https://www.rfc-editor.org/rfc/rfc6902) and
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901). The byte field uses the
base64url alphabet in
[RFC 4648, Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5).

## Machine-readable contract

`kubernetes-json-patch-0.1.profile.json` lists the seven profile schemas. The
arguments document contains:

- the parsed operation array;
- the exact UTF-8 request bytes as unpadded base64url; and
- the SHA-256 digest of those bytes.

All three values MUST agree. See
[REFERENCE_PROFILES.md](REFERENCE_PROFILES.md) for the vectors and test
commands.
