## Change

Describe the problem and the implemented change.

## Protocol and security impact

- Affected requirement or invariant:
- Trust-boundary change:
- Compatibility or migration impact:
- Public claim change:

Write `None` for an item that does not apply.

## Evidence

List each command and result. Label the evidence as a unit test, property test,
conformance result, formal-model result, external-system test, or external
review.

```text
command
result
```

## Checklist

- [ ] The change is limited to one problem.
- [ ] I added or updated the required tests and vectors.
- [ ] I updated both reference verifiers when protocol behavior changed.
- [ ] I assessed the Lean and TLA+ models when an invariant changed.
- [ ] I updated the specification, threat model, status, and changelog when required.
- [ ] I did not add credentials, private data, customer data, or personal paths.
- [ ] I documented every relevant check that I did not run.
