package net.corda.did

import com.natpryce.Success
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.isA
import net.corda.assertFailure
import net.corda.assertSuccess
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.UntargetedPublicKeyFailure
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import java.util.UUID
import java.security.KeyPairGenerator as JavaKeyPairGenerator

/**
 * Test cases for [DidEnvelope] Delete
 */
class DidEnvelopeDeleteTests {

	@Test
	fun `Deletion succeeds for a valid envelope`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val keyUri = URI("${documentId.toExternalForm()}#keys-1")
		val keyPair = KeyPairGenerator().generateKeyPair()
		val encodedKey = keyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey"
		|	}
		|  ]
		|}""".trimMargin()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signature = keyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val encodedSignature = signature.bytes.toBase58()

		val instruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Deletion fails for an envelope with wrong signature`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val keyUri = URI("${documentId.toExternalForm()}#keys-1")
		val keyPair = KeyPairGenerator().generateKeyPair()
		val encodedKey = keyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey"
		|	}
		|  ]
		|}""".trimMargin()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey"
		|	}
		|  ]
		|}""".trimMargin()

		val bogusKeys = KeyPairGenerator().generateKeyPair()
		val signature = bogusKeys.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val encodedSignature = signature.bytes.toBase58()

		val instruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<InvalidSignatureFailure>(
				has(InvalidSignatureFailure::target, equalTo(keyUri))
		))
	}

	@Test
	fun `Deletion fails for an envelope with irrelevant signatures`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")
		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val encodedKey1 = keyPair1.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val keyUri2 = URI("${documentId.toExternalForm()}#keys-2")
		val keyPair2 = KeyPairGenerator().generateKeyPair()
		val signature = keyPair2.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val encodedSignature = signature.bytes.toBase58()

		val instruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val actual = envelope.validateModification(DidDocument(originalDocument)).assertFailure()

		assertThat(actual, isA<UntargetedPublicKeyFailure>())
	}
}
