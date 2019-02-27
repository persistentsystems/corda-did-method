package net.corda.did

import com.natpryce.Success
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.isA
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite.Ed25519
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import java.util.UUID
import java.security.KeyPairGenerator as JavaKeyPairGenerator

class DidEnvelopeDeleteTests {

	@Test
	fun `Deletion succeeds for a valid envelope`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

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

		val actual = envelope.validateUpdate(DidDocument(originalDocument))

		assertThat(actual, isA<Success<Unit>>())
	}
}
