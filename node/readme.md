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
 - Only ciphers as per https://w3c-ccg.github.io/ld-cryptosuite-registry/ Draft Community Group Report 09 December 2018 are supported as pub keys
