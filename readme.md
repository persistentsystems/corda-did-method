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

Methods
-------

### Read

`GET {did}`

### Create `PUT {did}`

```json
{
  "action": "create",
  "did": {
    "@context": "https://w3id.org/did/v1",
    "id": "did:corda:tcn:00000000-0000-0000-0000-000000000000",
    "publicKey": [
      {
        "id": "did:corda:tcn:00000000-0000-0000-0000-000000000000#keys-1",
        "type": "Ed25519",
        "controller": "did:corda:tcn:00000000-0000-0000-0000-000000000000",
        "publicKeyBase58": "GfHq2tTVk9z4eXgyP8um5eg46am2W7LiuDyxW1kk5wy3tRWDg8HNn6UeEUnK"
      }
    ]
  }
}
```

#### Payload:

Any payload that creates or modifies a DID document will have to contain _proof of ownership_ with it.
To implement that, any DID document must be be wrapped in an envelope.
This envelope must contain signatures by all private keys associated with the public keys contained in the documents.

![Corda DID API](did_envelope.svg)

Envelopes that do not contain signatures for all public keys will be rejected.
Envelopes using unsupported cryptographic suites or unsupported serialisation mechanisms will be rejected.

Caveats
-------

 - Not all cryptographic suites to be supported as per the [Linked Data Cryptographic Suite Registry Draft Community Group Report](https://w3c-ccg.github.io/ld-cryptosuite-registry) (09 December 2018) are supported.
 - Not all encodings to be supported as per the [Decentralized Identifiers Draft Community Group](https://w3c-ccg.github.io/did-spec/#public-keys) (06 February 2019) are supported.

|                             	| `publicKeyPem` 	| `publicKeyJwk` 	| `publicKeyHex` 	| `publicKeyBase64` 	| `publicKeyBase58` 	| `publicKeyMultibase` 	|
|-----------------------------	|----------------	|----------------	|----------------	|-------------------	|-------------------	|----------------------	|
| `Ed25519Signature2018`      	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✔         	|           ✖          	|
| `RsaSignature2018`          	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✖         	|           ✖          	|
| `EdDsaSASignatureSecp256k1` 	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✖         	|           ✖          	|
