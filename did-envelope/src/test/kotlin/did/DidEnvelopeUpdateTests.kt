package net.corda.did

import com.natpryce.Success
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.isA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import io.ipfs.multiformats.multibase.MultiBase
import net.corda.assertFailure
import net.corda.assertSuccess
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.core.utilities.toBase64
import net.corda.core.utilities.toHex
import net.corda.did.CryptoSuite.EcdsaSecp256k1
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.CryptoSuite.RSA
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidTemporalRelationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingTemporalInformationFailure
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.simple.JSONObject
import org.junit.Test
import java.net.URI
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.UUID
import java.security.KeyPairGenerator as JavaKeyPairGenerator

/**
 * Test cases for [DidEnvelope] Update
 */
class DidEnvelopeUpdateTests {

	@Test
	fun `Validation succeeds for a valid envelope`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a request that adds a ed25519 key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val oldKeyUri1 = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey1 = oldKeyPair1.public.encoded.toBase58()

		val oldKeyUri2 = URI("${documentId.toExternalForm()}#2")
		val oldKeyPair2 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey2 = oldKeyPair2.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	},
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromOldKey2 = oldKeyPair2.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey2Encoded = signatureFromOldKey2.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey2Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(oldDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a request that adds a rsa key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val oldKeyUri1 = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val oldPublicKey1 = oldKeyPair1.public.encoded.toBase58()

		val oldKeyUri2 = URI("${documentId.toExternalForm()}#2")
		val oldKeyPair2 = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val oldPublicKey2 = oldKeyPair2.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	},
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromOldKey2 = oldKeyPair2.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey2Encoded = signatureFromOldKey2.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$signatureFromOldKey2Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(oldDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a request that adds a ecdsa key`() {
		Security.addProvider(BouncyCastleProvider())
		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())

		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()
		val oldKeyUri1 = URI("${documentId.toExternalForm()}#1")

		val oldKeyPair1 = g.generateKeyPair()
		val oldPublicKey1 = oldKeyPair1.public.encoded.toBase58()

		val oldKeyUri2 = URI("${documentId.toExternalForm()}#2")
		val oldKeyPair2 = g.generateKeyPair()
		val oldPublicKey2 = oldKeyPair2.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = g.generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	},
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromOldKey2 = oldKeyPair2.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey2Encoded = signatureFromOldKey2.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$signatureFromOldKey2Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(oldDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a request that removes a ed25519 key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = oldKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(oldDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a request that removes a rsa key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val oldPublicKey = oldKeyPair.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = oldKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(oldDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a request that removes a ecdsa key`() {
		Security.addProvider(BouncyCastleProvider())
		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())

		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair = g.generateKeyPair()
		val oldPublicKey = oldKeyPair.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = g.generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = oldKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(oldDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation fails for an update that tampers with the creation date`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:01Z",
		|  "updated": "1970-01-01T00:00:01Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidTemporalRelationFailure>())
	}

	@Test
	fun `Validation fails if a created date is added`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2019-01-01T00:00:00Z",
		|  "updated": "2019-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidTemporalRelationFailure>())
	}

	@Test
	fun `Validation fails for an update that does not supply an update date`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<MissingTemporalInformationFailure>())
	}

	@Test
	fun `Validation fails for an update that occurs before the creation date`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2019-02-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2019-02-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidTemporalRelationFailure>())
	}

	@Test
	fun `Validation fails for a potential replay attack`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2017-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2017-01-01T00:00:00Z",
		|  "updated": "2018-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidTemporalRelationFailure>())
	}

	@Test
	fun `Validation fails for a request that doesn't provide signatures for all keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val keyUri1 = URI("${documentId.toExternalForm()}#uno")
		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val publicKey1 = keyPair1.public.encoded.toBase58()

		val keyUri2 = URI("${documentId.toExternalForm()}#dos")
		val keyPair2 = KeyPairGenerator().generateKeyPair()
		val publicKey2 = keyPair2.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$publicKey1"
		|	},
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$publicKey2"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#tres")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = keyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<MissingSignatureFailure>(has(MissingSignatureFailure::target, equalTo(keyUri2))))
	}

	@Test
	fun `Validation succeeds for a valid envelope with base64 encoding`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toBase64()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase64": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a valid envelope with Hex encoding`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newKeyPairEncoded = newKeyPair.public.encoded.toHex()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyHex": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a valid envelope with PEM encoding`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val encoder = Base64.getEncoder()
		val keyBegin = "-----BEGIN PUBLIC KEY-----"
		val keyEnd = "-----END PUBLIC KEY-----"
		val newKeyPairEncoded = keyBegin + String(encoder.encode(newKeyPair.public.encoded)) + keyEnd

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyPem": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a valid envelope with MultiBase encoding`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()

		val newKeyPairEncoded = MultiBase.encode(MultiBase.Base.BASE32, newKeyPair.public.encoded)

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyMultibase": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a valid envelope with JWK encoding`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()

		val eddsaJWK = OctetSequenceKey.Builder(newKeyPair.public.encoded).build()
		val eddsaStringJWK = JSONObject.escape(eddsaJWK.toString())

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyJwk": "$eddsaStringJWK"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for a valid envelope with mixed encoding`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val eddsaJWK = OctetSequenceKey.Builder(originalKeyPair.public.encoded).build()
		val eddsaStringJWK = JSONObject.escape(eddsaJWK.toString())

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyJwk": "$eddsaStringJWK"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val encoder = Base64.getEncoder()
		val keyBegin = "-----BEGIN PUBLIC KEY-----"
		val keyEnd = "-----END PUBLIC KEY-----"
		val newKeyPairEncoded = keyBegin + String(encoder.encode(newKeyPair.public.encoded)) + keyEnd

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyPem": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation fails for an envelope with JWK encoding on incorrect ED public key`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val secondKeyPair = KeyPairGenerator().generateKeyPair()

		val eddsaJWK = OctetSequenceKey.Builder(secondKeyPair.public.encoded).build()
		val eddsaStringJWK = JSONObject.escape(eddsaJWK.toString())

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyJwk": "$eddsaStringJWK"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidSignatureFailure>())
	}

	@Test
	fun `Validation fails for an envelope with JWK encoding on incorrect EC public key`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		Security.addProvider(BouncyCastleProvider())
		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())
		val ecdsaKeyPair = g.generateKeyPair()
		g.initialize(ecSpec, SecureRandom())
		val newEcdsaKeyPair = g.generateKeyPair()
		val ecdsaJWK = ECKey.Builder(Curve.P_256K, newEcdsaKeyPair.public as ECPublicKey).build()
		val ecdsaPubKeyJWK = JSONObject.escape(ecdsaJWK.toString())

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyJwk": "$ecdsaPubKeyJWK"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = ecdsaKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidSignatureFailure>())
	}

	@Test
	fun `Validation fails for an envelope with JWK encoding on incorrect RSA public key`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
		val originalKeyPair = KeyPairGenerator().generateKeyPair()
		val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		Security.addProvider(BouncyCastleProvider())
		val rsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val newRsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		val rsaJwk = RSAKey.Builder(newRsaKeyPair.public as RSAPublicKey).build()
		val rsaPubKeyJWK = JSONObject.escape(rsaJwk.toString())

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyJwk": "$rsaPubKeyJWK"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val signatureFromNewKey = rsaKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<InvalidSignatureFailure>())
	}
}