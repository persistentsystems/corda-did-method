Corda DID Method Proof-of-Concept
=================================
## Table of Contents
1. [Introduction](#introduction)
2. [Specifications](#specifications) 
3. [CorDapp design -CMN views](#cmn)
4. [Setup and Developer documentation](#setup)
5. [Caveats](#caveats)
6. [Risks/Known Attack Surface](#risks)

<a name="introduction"></a>
### Introduction
This repository contains all components necessary to provide a Corda ‘Decentralized Identifier Method’ within the meaning of the [Data Model and Syntaxes for Decentralized Identifiers Draft Community Group Report 06 February 2019](https://w3c-ccg.github.io/did-spec).

![Corda DID System Architecture](architecture.svg)

The system architecture outlined above illustrates the high level components without going into implementation details.
On a high level, persistence of DID documents will be provided by a _consortium_ of trusted nodes operating within a _network_.
The Corda DID method allows targeting three networks by specification: [The Corda Network](https://corda.network/) (UAT and Live [environments](https://corda.network/policy/environments.html)) as well as [Testnet](https://docs.corda.net/head/corda-testnet-intro.html).

End users that aim to _create_, _read_, _update_ or _delete_ DID documents can do so by interacting with a trusted node of their choosing.
The API provided for interaction is exposing REST endpoints over HTTP, using a JSON based envelope format closely aligned with the JSON-LD examples found in the [draft community report](https://w3c-ccg.github.io/did-spec/#dfn-did-document).

When users interact with consortium member nodes, their requests will be handled by a _web server_ that transforms the requests into a [format suitable for Corda](https://docs.corda.net/clientrpc.html).
The web server component is running in a process independent of Corda.
User calls ‘proxied’ through this way will invoke a [Flow](https://docs.corda.net/key-concepts-flows.html) on one of the consortium nodes.
As part of this flow, consortium nodes will validate that the id provided by the user is valid and that the message has cryptographic integrity (i.e. that the DID document is signed properly).
Once this validation was successful, DID documents will be replicated from the _trusted node_ (i.e. the node the user chose to interact with via REST) to all _witness nodes_ (i.e. all other nodes in the consortium).
Witness nodes will perform the a cryptographic integrity check as part of the [contract](https://docs.corda.net/key-concepts-contracts.html) underpinning this transaction.

Once replicated, anyone with access to one of the consortium nodes can request the DID document by querying the REST API of an arbitrary node for the document ID.

<a name="specifications"></a>
## Specifications
### Corda DID Format
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



### Directory Structure
| Directory | Description                                                     |
|-----------|-----------------------------------------------------------------|
| `did-api` | Module for defining REST api                         |
| `did-contracts` |  Module for defining Corda smart contracts.                   |
| `did-flows`     | Module for defining Corda flows for read operations.               |
| `did-envelope` | Module for defining the did envelope, document and instruction|
| `did-witness-flows` | Module for defining Corda flows for create,update and delete operations|

<a name="cmn"></a>
## CorDapp design -CMN views
Detailed design of the CorDapp can be viewed [here](/cmn_diagram.md)
<a name="setup"></a>
## Setup and Developer documentation
The steps for setting up the project are [here](/installation_setup.md)
<a name="caveats"></a>
#### Caveats

 - Not all cryptographic suites to be supported as per the [Linked Data Cryptographic Suite Registry Draft Community Group Report](https://w3c-ccg.github.io/ld-cryptosuite-registry) (09 December 2018) are supported.
 - Not all encodings to be supported as per the [Decentralized Identifiers Draft Community Group](https://w3c-ccg.github.io/did-spec/#public-keys) (06 February 2019) are supported.

|                             	| `publicKeyPem` 	| `publicKeyJwk` 	| `publicKeyHex` 	| `publicKeyBase64` 	| `publicKeyBase58` 	| `publicKeyMultibase` 	|
|-----------------------------	|----------------	|----------------	|----------------	|-------------------	|-------------------	|----------------------	|
| `Ed25519Signature2018`      	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✔         	|           ✖          	|
| `RsaSignature2018`          	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✖         	|           ✖          	|
| `EdDsaSASignatureSecp256k1` 	|        ✖       	|        ✖       	|        ✖       	|         ✖         	|         ✖         	|           ✖          	|

<a name="risks"></a>
#### Risks/Known Attack Surface

##### Denial-of-Service Attack on Edge-Nodes

##### Replication Issues During Unavailability of Witness Nodes


