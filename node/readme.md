Methods
-------

### Read

`GET {did}`

### Create

`POST {did}`

#### Payload:



Caveats
-------

 - Cypher Suites supported as per https://w3c-ccg.github.io/did-spec/#registries
 - Mechanisms supported, i.e. publicKeyPem, publicKeyJwk, publicKeyHex, publicKeyBase64, publicKeyBase58, publicKeyMultibase


Currently, only cryptographic suites as per the [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry) (Draft Community Group Report 09 December 2018) are tested as public keys in DID documents in their default serialisations.

| Cryptographic Suite         | Representation        |
|-----------------------------|-----------------------|
| `Ed25519Signature2018`      | Base 58               |
| `Ed25519Signature2018`      | PEM                   |
| `EdDsaSASignatureSecp256k1` | Lowercase Hexadecimal |

Future implementations should be representation-agnostic.

