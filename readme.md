Corda DID Method Proof-of-Concept
=================================

![Corda DID Architecture](architecture.svg)

Corda DID Format
----------------

A Corda DID specifies the `corda` method, a target network (currently `testnet`, `tcn-uat`, `tcn`) and a UUID formatted as per [RFC 4122](https://tools.ietf.org/html/rfc4122#section-3).

```regexp
did:corda:(testnet|tcn-uat|tcn):[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}
```

I.e.

 - `did:corda:testnet:3df6b0a1-6b02-4053-8900-8c36b6d35fa1`
 - `did:corda:tcn:3df6b0a1-6b02-4053-8900-8c36b6d35fa1`
 - `did:corda:tcn-uat:3df6b0a1-6b02-4053-8900-8c36b6d35fa1`

Deliverables
------------

 1. A basic method spec document to be registered with the [DID method registry](https://w3c-ccg.github.io/did-method-registry/#the-registry).
 2. A Universal Resolver "[Driver](https://github.com/decentralized-identity/universal-resolver/)" using the `Corda` method.
 3. A CorDapp providing an end-point implementing the method spec _(1)_ in a way that can be accessed by the resolver _(2)_.

Design-Decisions
----------------

To-Do's
-------

Risks/Known Attack Surface
--------------------------

### Denial-of-Service Attack on Edge-Nodes

### Replication Issues During Unavailibility of Witness Nodes

