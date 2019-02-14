Corda DID Method Proof-of-Concept
=================================

This repository contains all components necessary to provide a Corda ‘Decentralized Identifier Method’ within the meaning of the [Data Model and Syntaxes for Decentralized Identifiers Draft Community Group Report 06 February 2019](https://w3c-ccg.github.io/did-spec).
Additionally, it contains a [Universal Resolver Driver](https://github.com/decentralized-identity/universal-resolver) following the [Extensible Driver Architecture](https://medium.com/decentralized-identity/a-universal-resolver-for-self-sovereign-identifiers-48e6b4a5cc3c) paradigm.

![Corda DID System Architecture](architecture.svg)

The system architecture outlined above illustrates the high level components without going into implementation details.
On a high level, persistence of DID documents will be provided by a _consortium_ of trusted nodes operating within a _network_.
The Corda DID method allows targeting three networks by specification: [The Corda Network](https://corda.network/) (UAT and Live [environments](https://corda.network/policy/environments.html)) as well as [Testnet](https://docs.corda.net/head/corda-testnet-intro.html). 

End users that aim to _create_, _read_, _update_ or _delete_ DID documents can do so by interacting with a trusted node of their choosing.
The API provided for interaction is exposing REST endpoints over HTTPS, using a JSON based envelope format closely aligned with the JSON-LD examples found in the [draft community report](https://w3c-ccg.github.io/did-spec/#dfn-did-document).

When users interact with consortium member nodes, their requests will be handled by a _web server_ that transforms the requests into a [format suitable for Corda](https://docs.corda.net/clientrpc.html).
The web server component is running in a process independent of Corda.
User calls ‘proxied’ through this way will invoke a [Flow](https://docs.corda.net/key-concepts-flows.html) on one of the consortium nodes.
As part of this flow, consortium nodes will validate that the id provided by the user is valid and that the message has cryptographic integrity (i.e. that the DID document is signed properly).
Once this validation was successful, DID documents will be replicated from the _trusted node_ (i.e. the node the user chose to interact with via REST) to all _witness nodes_ (i.e. all other nodes in the consortium).
Witness nodes will perform the a cryptographic integrity check as part of the [contract](https://docs.corda.net/key-concepts-contracts.html) underpinning this transaction.

Once replicated, anyone with access to one of the consortium nodes can request the DID document by querying the REST API of an arbitrary node for the document ID.
Systems that aim to support multiple DID methods including the Corda DID method can utilise a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver) that uses the Corda driver.
The driver will translate the request in the universal format to the Corda specific format. 
It is also aware of the consortium nodes for a given supported environment.
The driver thus exclusively requires the id as input.   

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

### Corda DID-Network Mapping

Initially, consortium membership is envisioned to change rarely so that a fixed set of member nodes can be defined and provided to consortium members.
A more dynamic approach to membership may be developed later. 

| ID        | Network                                                         | Stage | Consortium Member Nodes |
|-----------|-----------------------------------------------------------------|-------|-------------------------|
| `testnet` | [Testnet](https://docs.corda.net/head/corda-testnet-intro.html) | --    | --to be defined--       |
| `tcn-uat` | [The Corda Network](https://corda.network/)                     | UAT   | --to be defined--       |
| `tcn`     | [The Corda Network](https://corda.network/)                     | Live  | --to be defined--       |

Components
----------

This outlines the technical components that support the Corda DID method.
All components are contained in this repository as Gradle _sub-modules_.
All components are Kotlin applications.

### Corda DID API ([`did-api`](did-api))

The DID API is the server component to be deployed by consortium member nodes in conjunction with the CorDapp.
It provides Method specific APIs to _create_, _read_, _update_ or _delete_ DID documents.

The Corda DID method achieves proof-of-ownership of a *document* by requiring proof-of-ownership of the *keys* contained in the document.

To implement that, any DID document must be be wrapped in an envelope.
This envelope must contain signatures by all private keys associated with the public keys contained in the documents.

![Corda DID API](did_envelope.svg)

Envelopes that do not contain signatures for all public keys will be rejected.
Envelopes using unsupported cryptographic suites or unsupported serialisation mechanisms will be rejected.
In the current implementation there are severe restrictions on which suites and serialisation mechanisms can be used (see _Caveats_ below). 

#### API Format

##### Instruction

Instruction data tells the API what to do with the document received.
It also contains proof of ownership of keys.
The instruction data is to be formatted according to the following schema:

```json
{
  "definitions": {},
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": [
    "action",
    "signatures"
  ],
  "properties": {
    "action": {
      "$id": "#/properties/action",
      "type": "string",
      "enum": [
        "create",
        "read",
        "update",
        "delete"
      ]
    },
    "nonce": {
      "$id": "#/properties/nonce",
      "type": "string"
    },
    "signatures": {
      "$id": "#/properties/signatures",
      "type": "array",
      "items": {
        "$id": "#/properties/signatures/items",
        "type": "object",
        "required": [
          "id",
          "type",
          "signatureBase58"
        ],
        "properties": {
          "id": {
            "$id": "#/properties/signatures/items/properties/id",
            "type": "string",
            "description": "The ID of the public key that is part of the key pair signing the document.",
            "examples": [
              "did:corda:testnet:3df6b0a1-6b02-4053-8900-8c36b6d35fa1#keys-1",
              "did:corda:tcn:3df6b0a1-6b02-4053-8900-8c36b6d35fa1#keys-2"
            ],
            "pattern": "^did:corda:(testnet|tcn-uat|tcn):[0-9a-f]{8}\\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\\b[0-9a-f]{12}#.+$"
          },
          "type": {
            "$id": "#/properties/signatures/items/properties/type",
            "type": "string",
            "description": "The cryptographic suite this key has been generated with. More formats (RsaSignature2018, EdDsaSASignatureSecp256k1) to follow.",
            "enum": [
              "Ed25519Signature2018"
            ]
          },
          "signatureBase58": {
            "$id": "#/properties/signatures/items/properties/signatureBase58",
            "type": "string",
            "description": "The binary signature in Base58 representation. More formats to follow.",
            "examples": [
              "54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw"
            ]
          }
        }
      }
    }
  }
}
```

i.e.:
 
```json
{
  "action": "create",
  "signatures": [
    {
      "id": "did:corda:tcn:d51924e1-66bb-4971-ab62-ec4910a1fb98#keys-1",
      "type": "Ed25519Signature2018",
      "signatureBase58": "54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw"
    }
  ]
}
```

_Update_ and _delete_ actions require a _nonce_ to prevent replay attacks.

##### Document

The format of the document follows the [Data Model and Syntaxes for Decentralized Identifiers Draft Community Group Report 06 February 2019](https://w3c-ccg.github.io/did-spec) in JSON-LD.

#### Methods

Envelopes are implemented as `multipart/form-data` HTTP requests with two parts:

| Key           | Value            |
|---------------|------------------|
| `instruction` | Instruction JSON |
| `document`    | DID JSON         |

This format is chosen to circumvent issues with canonical document representation for hashing.

##### Create (`PUT {did}`)

This is used to create a new DID.
Proof of ownership of the document has to be presented in the envelope.

Instruction:

```json
{
  "action": "create",
  "signatures": [
	{
	  "id": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a#keys-1",
	  "type": "Ed25519Signature2018",
	  "signatureBase58": "3prrFYf3miPmZTFH9eAsfBDbiTbhwyMGFCcwrbouPdKjz14zhSHTTfWCBWBeKzGbaL4QVgjZzkb9mrDhmVJ9CATG"
	}
  ]
}
```

Document:

```json
{
  "@context": "https://w3id.org/did/v1",
  "id": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a",
  "publicKey": [
	{
	  "id": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a#keys-1",
	  "type": "Ed25519VerificationKey2018",
	  "controller": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a",
	  "publicKeyBase58": "GfHq2tTVk9z4eXgyW7mGhENuKu7WM8hES9emfJvBB4VXrgaL6kS1xs4nSs96"
	}
  ]
}
```

HTTP Request:

```bash
curl -X PUT \
  http://example.org/did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a \
  -H 'cache-control: no-cache' \
  -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
  -F 'instruction={
  "action": "create",
  "signatures": [
	{
	  "id": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a#keys-1",
	  "type": "Ed25519Signature2018",
	  "signatureBase58": "3prrFYf3miPmZTFH9eAsfBDbiTbhwyMGFCcwrbouPdKjz14zhSHTTfWCBWBeKzGbaL4QVgjZzkb9mrDhmVJ9CATG"
	}
  ]
}' \
  -F 'document={
  "@context": "https://w3id.org/did/v1",
  "id": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a",
  "publicKey": [
	{
	  "id": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a#keys-1",
	  "type": "Ed25519VerificationKey2018",
	  "controller": "did:corda:tcn:07438aee-3116-4a76-bc48-b2446ec01c8a",
	  "publicKeyBase58": "GfHq2tTVk9z4eXgyW7mGhENuKu7WM8hES9emfJvBB4VXrgaL6kS1xs4nSs96"
	}
  ]
}'
```

Response:

The API will respond with status `200` for a request with a well-formed instruction *and* a well-formed document *and* valid signature(s) *and* an unused ID.
The API will respond with status `400` for a request with a deformed instruction *or* a deformed document *or* at least one invalid signature.
The API will respond with status `409` for a request with an ID that is already taken.


##### Read (`GET {did}`)

##### Update (`POST {did}`)

##### Delete (`DELETE {did}`)

#### Caveats

 - Not all cryptographic suites to be supported as per the [Linked Data Cryptographic Suite Registry Draft Community Group Report](https://w3c-ccg.github.io/ld-cryptosuite-registry) (09 December 2018) are supported.
 - Not all encodings to be supported as per the [Decentralized Identifiers Draft Community Group](https://w3c-ccg.github.io/did-spec/#public-keys) (06 February 2019) are supported.

|                             	| `publicKeyPem` 	| `publicKeyJwk` 	| `publicKeyHex` 	| `publicKeyBase64` 	| `publicKeyBase58` 	| `publicKeyMultibase` 	|
|-----------------------------	|----------------	|----------------	|----------------	|-------------------	|-------------------	|----------------------	|
| `Ed25519Signature2018`      	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✔         	|           ✖          	|
| `RsaSignature2018`          	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✖         	|           ✖          	|
| `EdDsaSASignatureSecp256k1` 	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✖         	|           ✖          	|


### 

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

