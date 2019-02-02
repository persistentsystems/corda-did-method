package net.corda.did

// Based on v0.11, augmenting the id to fit the Corda spec
object SpecExamples {

	// https://w3c-ccg.github.io/did-spec/#example-2-minimal-self-managed-did-document
	val `Minimal self-managed DID Document` = """{
	|  "@context": "https://w3id.org/did/v1",
	|  "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc",
	|  "publicKey": [{
	|    "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-1",
	|    "type": "RsaVerificationKey2018",
	|    "controller": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc",
	|    "publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
	|  }],
	|  "authentication": [{
	|    "type": "RsaSignatureAuthentication2018",
	|    "publicKey": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-1"
	|  }],
	|  "service": [{
	|    "type": "ExampleService",
	|    "serviceEndpoint": "https://example.com/endpoint/8377464"
	|  }]
	|}""".trimMargin()

	// https://w3c-ccg.github.io/did-spec/#example-16-advanced-did-document-example
	val `Advanced DID Document example` = """{
	|  "@context": "https://w3id.org/future-method/v1",
	|  "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc"|,
	|
	|  "publicKey": [{
	|    "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-1",
	|    "type": "RsaVerificationKey2018",
	|    "controller": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc",
	|    "publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
	|  }, {
	|    "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-2",
	|    "type": "Ed25519VerificationKey2018",
	|    "controller": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc",
	|    "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
	|  }, {
	|    "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-3",
	|    "type": "RsaPublicKeyExchangeKey2018",
	|    "controller": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc",
	|    "publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
	|  }]|,
	|
	|  "authentication": [{
	|    // this mechanism can be used to authenticate as DID ...fghi
	|    "type": "RsaSignatureAuthentication2018",
	|    "publicKey": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-1"
	|  }, {
	|    // this mechanism can be used to biometrically authenticate as DID ...fghi
	|    "type": "ieee2410Authentication2018",
	|    "publicKey": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc#keys-2"
	|  }]|,
	|
	|  "service": [{
	|    "type": "OpenIdConnectVersion1.0Service",
	|    "serviceEndpoint": "https://openid.example.com/"
	|  }, {
	|    "type": "CredentialRepositoryService",
	|    "serviceEndpoint": "https://repository.example.com/service/8377464"
	|  }, {
	|    "type": "XdiService",
	|    "serviceEndpoint": "https://xdi.example.com/8377464"
	|  }, {
	|    "type": "HubService",
	|    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/"
	|  }, {
	|    "type": "MessagingService",
	|    "serviceEndpoint": "https://example.com/messages/8377464"
	|  }, {
	|    "type": "SocialWebInboxService",
	|    "serviceEndpoint": "https://social.example.com/83hfh37dj",
	|    "description": "My public social inbox",
	|    "spamCost": {
	|      "amount": "0.50",
	|      "currency": "USD"
	|    }
	|  }, {
	|    "type": "DidAuthPushModeVersion1",
	|    "serviceEndpoint": "http://auth.example.com/did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc"
	|  }, {
	|    "id": "did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc;bops",
	|    "type": "BopsService",
	|    "serviceEndpoint": "https://bops.example.com/enterprise/"
	|  }]
	|}""".trimIndent()
}
