package net.corda.did

import com.natpryce.Failure
import com.natpryce.Success
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.isA
import net.corda.assertFailure
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.CryptoSuite.RSA
import net.corda.did.DidEnvelopeFailure.ValidationFailure.CryptoSuiteMismatchFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedInstructionFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoKeysFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureCountFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureTargetFailure
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import java.util.UUID
import kotlin.text.Charsets.UTF_8
import java.security.KeyPairGenerator as JavaKeyPairGenerator

class DidEnvelopeCreateTests {

	@Test
	fun `Validation succeeds for a valid envelope`() {
		/*
		 * 1. Generate a valid ID
		 */
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		/*
		 * 2. Generate a key pair
		 */
		val keyPair = KeyPairGenerator().generateKeyPair()

		/*
		 * 3. encode the key pair using the supported encoding
		 */
		val pubKeyBase58 = keyPair.public.encoded.toBase58()

		/*
		 * 4. Build a valid URI for the key in (3)
		 */
		val keyUri = URI("${documentId.toExternalForm()}#keys-1")

		/*
		 * 5. Build a valid DID document using the parameters generated
		 */
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$pubKeyBase58"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * 6. Sign the DID generated in (5) with the key generated in (1)
		 */
		val signature = keyPair.private.sign(document.toByteArray(UTF_8))
		val base58Signature = signature.bytes.toBase58()

		/*
		 * 7. Build a valid instruction set for the DID generated
		 */
		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$base58Signature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate()

		/*
		 * 8. Test Instruction
		 */
		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for an envelope with multiple keys`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val keyPair2 = KeyPairGenerator().generateKeyPair()

		val encodedPubKey1 = keyPair1.public.encoded.toBase58()
		val encodedPubKey2 = keyPair2.public.encoded.toBase58()

		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")
		val keyUri2 = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey2"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = keyPair1.private.sign(document.toByteArray(UTF_8))
		val signature2 = keyPair2.private.sign(document.toByteArray(UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()
		val encodedSignature2 = signature2.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	},
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate()

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation fails for an envelope with multiple signatures targeting the same key`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uri = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(UTF_8))
		val signature2 = kp.private.sign(document.toByteArray(UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()
		val encodedSignature2 = signature2.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	},
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<SignatureTargetFailure>())
	}

	@Test
	fun `Validation fails for an envelope clashing key IDs`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val keyPair2 = KeyPairGenerator().generateKeyPair()

		val encodedPubKey1 = keyPair1.public.encoded.toBase58()
		val encodedPubKey2 = keyPair2.public.encoded.toBase58()

		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey2"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = keyPair1.private.sign(document.toByteArray(UTF_8))
		val signature2 = keyPair2.private.sign(document.toByteArray(UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()
		val encodedSignature2 = signature2.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<SignatureTargetFailure>())
	}

	@Test
	fun `Validation fails for an envelope without keys`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [ ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [ ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<NoKeysFailure>())
	}

	@Test
	fun `Validation fails for an envelope with fewer signatures than keys`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val keyPair2 = KeyPairGenerator().generateKeyPair()

		val encodedPubKey1 = keyPair1.public.encoded.toBase58()
		val encodedPubKey2 = keyPair2.public.encoded.toBase58()

		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")
		val keyUri2 = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey2"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = keyPair1.private.sign(document.toByteArray(UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<SignatureCountFailure>())
	}

	@Test
	fun `Validation fails for an envelope using a non-Ed25519 key`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val ed25519KeyPair = KeyPairGenerator().generateKeyPair()
		// TODO moritzplatt 2019-02-18 -- this will become valid once the crypto suite limitation is removed
		val rsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()

		val ed25519PubKey = ed25519KeyPair.public.encoded.toBase58()
		val rsaPubKey2 = rsaKeyPair.public.encoded.toBase58()

		val ed25519keyUri = URI("${documentId.toExternalForm()}#keys-1")
		val rasKeyUri = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$rsaPubKey2"
		|	},
		|	{
		|	  "id": "$ed25519keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ed25519PubKey"
		|	}
		|  ]
		|}""".trimMargin()

		val ed25519Signature = ed25519KeyPair.private.sign(document.toByteArray(UTF_8))
		val rsaSignature = rsaKeyPair.private.sign(document.toByteArray(UTF_8))

		val encodedEd25519Signature = ed25519Signature.bytes.toBase58()
		val encodedRsaSignature = rsaSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$ed25519keyUri",
		|	  "type": "${Ed25519.signatureID}",
		|	  "signatureBase58": "$encodedEd25519Signature"
		|	},
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${RSA.signatureID}",
		|	  "signatureBase58": "$encodedRsaSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<CryptoSuiteMismatchFailure>())
	}

	@Test
	fun `Validation fails for an envelope with mismatched crypto suites`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val ed25519KeyPair = KeyPairGenerator().generateKeyPair()
		val rsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()

		val ed25519PubKey = ed25519KeyPair.public.encoded.toBase58()

		val keyUri = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ed25519PubKey"
		|	}
		|  ]
		|}""".trimMargin()

		val rsaSignature = rsaKeyPair.private.sign(document.toByteArray(UTF_8))

		val encodedRsaSignature = rsaSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${RSA.signatureID}",
		|	  "signatureBase58": "$encodedRsaSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<CryptoSuiteMismatchFailure>())
	}

	@Test
	fun `Validation succeeds for an envelope with invalid signature`() {
		val documentId = Did("did:corda:tcn:${UUID.randomUUID()}")

		val keyPair = KeyPairGenerator().generateKeyPair()

		val pubKeyBase58 = keyPair.public.encoded.toBase58()

		val keyUri = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$pubKeyBase58"
		|	}
		|  ]
		|}""".trimMargin()

		val wrongSignature = keyPair.private.sign("nonsense".toByteArray(UTF_8))
		val encodedWrongSignature = wrongSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedWrongSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreate().assertFailure()

		assertThat(actual, isA<InvalidSignatureFailure>())
	}

	@Test
	fun `Validation fails for an envelope with malformed instructions`() {
		val document = """{
		  "@context": "https://w3id.org/did/v1",
		  "id": "did:corda:tcn:f85c1782-4dd4-4433-b375-6218c7e53600",
		  "publicKey": [
			{
			  "id": "did:corda:tcn:f85c1782-4dd4-4433-b375-6218c7e53600#keys-1",
			  "type": "Ed25519VerificationKey2018",
			  "controller": "did:corda:tcn:f85c1782-4dd4-4433-b375-6218c7e53600",
			  "publicKeyBase58": "GfHq2tTVk9z4eXgyL5pXiwbd7iK9Xf6d13z8zQqD3ys5VFuTJk2VA1GQGjz6"
			}
		  ]
		}""".trimMargin()

		val instruction = "Bogus"

		assertThat(DidEnvelope(document, instruction).validateCreate(), isA<Failure<MalformedInstructionFailure>>())
	}
}