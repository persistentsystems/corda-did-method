package net.corda.did

import com.grack.nanojson.JsonParserException
import com.natpryce.Success
import com.natpryce.hamkrest.and
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.isA
import com.natpryce.hamkrest.present
import com.natpryce.hamkrest.throws
import net.corda.assertFailure
import net.corda.assertSuccess
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.CryptoSuite.EcdsaSecp256k1
import net.corda.did.CryptoSuite.RSA
import net.corda.did.DidEnvelopeFailure.ValidationFailure.CryptoSuiteMismatchFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidTemporalRelationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoKeysFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureCountFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureTargetFailure
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test
import java.net.URI
import java.security.SecureRandom
import java.security.Security
import java.util.UUID
import kotlin.text.Charsets.UTF_8
import java.security.KeyPairGenerator as JavaKeyPairGenerator

/**
 * Test cases for [DidEnvelope] Create
 */
class DidEnvelopeCreateTests {

	@Test
	fun `Validation succeeds for a valid envelope`() {
		/*
		 * 1. Generate a valid ID
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		/*
		 * 2. Generate ed25519, rsa and ecdsa key pair
		 */
		val keyPair = KeyPairGenerator().generateKeyPair()
		val rsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()
		Security.addProvider(BouncyCastleProvider())
		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())
		val ecdsaKeyPair = g.generateKeyPair()

		/*
		 * 3. encode the key pair using the supported encoding
		 */
		val pubKeyBase58 = keyPair.public.encoded.toBase58()
		val rsaPubKeyBase58 = rsaKeyPair.public.encoded.toBase58()
		val ecdsaPubKeyBase58 = ecdsaKeyPair.public.encoded.toBase58()


		/*
		 * 4. Build a valid URI for the key in (3)
		 */
		val keyUri = URI("${documentId.toExternalForm()}#keys-1")
		val rasKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val ecdsaKeyUri = URI("${documentId.toExternalForm()}#keys-3")

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
		|	},
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$rsaPubKeyBase58"
		|	},
		|	{
		|	  "id": "$ecdsaKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ecdsaPubKeyBase58"
		|	}
		|  ]
		|}""".trimMargin()

		/*
		 * 6. Sign the DID generated in (5) with the key generated in (1)
		 */
		val signature = keyPair.private.sign(document.toByteArray(UTF_8))
		val base58Signature = signature.bytes.toBase58()

		val rsaSignature = rsaKeyPair.private.sign(document.toByteArray(UTF_8))
		val rsaSignatureBase58 = rsaSignature.bytes.toBase58()

		val ecdsaSignature = ecdsaKeyPair.private.sign(document.toByteArray(UTF_8))
		val ecdsaSignatureBase58 = ecdsaSignature.bytes.toBase58()

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
		|	},
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$rsaSignatureBase58"
		|	},
		|	{
		|	  "id": "$ecdsaKeyUri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$ecdsaSignatureBase58"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation()

		/*
		 * 8. Test Instruction
		 */
		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for an envelope with multiple keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

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

		val actual = DidEnvelope(instruction, document).validateCreation()

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation fails for an envelope with multiple signatures targeting the same key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

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

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		assertThat(actual, isA<SignatureTargetFailure>())
	}

	@Test
	fun `Validation fails for an envelope clashing key IDs`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

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

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		assertThat(actual, isA<SignatureTargetFailure>())
	}

	@Test
	fun `Validation fails for an envelope without keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [ ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [ ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		assertThat(actual, isA<NoKeysFailure>())
	}

	@Test
	fun `Validation fails for an envelope with fewer signatures than keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

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

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		assertThat(actual, isA<SignatureCountFailure>())
	}

	@Test
	fun `Validation fails for an envelope with mismatched crypto suites`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

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

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<CryptoSuiteMismatchFailure>(
				has(CryptoSuiteMismatchFailure::target, equalTo(keyUri)) and
						has(CryptoSuiteMismatchFailure::keySuite, equalTo(Ed25519)) and
						has(CryptoSuiteMismatchFailure::signatureSuite, equalTo(RSA))
		))

	}

	@Test
	fun `Validation fails for an envelope with invalid ed25519 signature`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

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

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<InvalidSignatureFailure>(has(InvalidSignatureFailure::target, equalTo(keyUri))))
	}

	@Test
	fun `Validation fails for an envelope with invalid rsa signature`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val rsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()

		val rsaPubKey2 = rsaKeyPair.public.encoded.toBase58()

		val rasKeyUri = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$rsaPubKey2"
		|	}
		|  ]
		|}""".trimMargin()

		val wrongSignature = rsaKeyPair.private.sign("nonsense".toByteArray(UTF_8))
		val encodedWrongSignature = wrongSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${RSA.signatureID}",
		|	  "signatureBase58": "$encodedWrongSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<InvalidSignatureFailure>(has(InvalidSignatureFailure::target, equalTo(rasKeyUri))))
	}

	@Test
	fun `Validation fails for an envelope with invalid ecdsa signature`() {
		Security.addProvider(BouncyCastleProvider())
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())
		val ecdsaKeyPair = g.generateKeyPair()
		val ecdsaPubKey2 = ecdsaKeyPair.public.encoded.toBase58()

		val ecdsaKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$ecdsaKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ecdsaPubKey2"
		|	}
		|  ]
		|}""".trimMargin()

		val wrongSignature = ecdsaKeyPair.private.sign("nonsense".toByteArray(UTF_8))
		val encodedWrongSignature = wrongSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$ecdsaKeyUri",
		|	  "type": "${EcdsaSecp256k1.signatureID}",
		|	  "signatureBase58": "$encodedWrongSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<InvalidSignatureFailure>(has(InvalidSignatureFailure::target, equalTo(ecdsaKeyUri))))
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

		@Suppress("RemoveExplicitTypeArguments")
		assertThat({
			DidEnvelope(document, instruction)
		}, throws(isA<IllegalArgumentException>(
				has(IllegalArgumentException::cause, present(isA<JsonParserException>(
						has(JsonParserException::message, equalTo("Unexpected token 'Bogus' on line 1, char 1"))
				)))
		)))
	}

	@Test
	fun `Validation succeeds for an envelope with a created date only`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyFWjZCLwoH9C7qZb3KvhZVfj2J2wti62dnrH9Hv4HvxZG"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "3jSNdLMeFmsXKy6155d2xSvSzkRcTYSMpXHefYFmGvUg72N3SveezRNbyTaVqvaZ8nD5MA8zGbznWzXdt54e5k8H"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation()

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `validation succeeds for an envelope with an update date only`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyL5csGiHtwEydbBvQF4VgygSjxWYUM5sE34qe5Sf2ALk5"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "g4MgSetbN2YsR4bZe4qDeoxDXgyBqKWyfh2UjoRm8wQPnEhQjEuV46ttzH7XGFViBkL9tenTg7tfaAs6j61AAFD"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation()

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `validation fails for an envelope stating it was updated before it was created`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|  "created": "2019-01-02T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyTPxte7rrotCf1ueoXyJfRob7vTv9kGDhed6ESWnjLXav"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "2CDG4wegz92QBRAEdZsy4Wc4Tyij6FjnPKrDNcsaM73azWPPLy7vcSi2zyaP9Sqo4PNKWgw4YzY38f5HCpSEvLiL"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		assertThat(actual, isA<InvalidTemporalRelationFailure>())
	}

	@Test
	fun `validation fails if publicKey id does not contain did as prefix`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|  "created": "1970-01-01T00:00:00Z",
		|
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91ea-4795883fa781#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyTPxte7rrotCf1ueoXyJfRob7vTv9kGDhed6ESWnjLXav"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91ea-4795883fa781#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "2CDG4wegz92QBRAEdZsy4Wc4Tyij6FjnPKrDNcsaM73azWPPLy7vcSi2zyaP9Sqo4PNKWgw4YzY38f5HCpSEvLiL"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation().assertFailure()

		assertThat(actual, isA<DidEnvelopeFailure.ValidationFailure.InvalidPublicKeyId>())
	}

	@Test
	fun `Validation succeeds for an envelope using a RSA key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val rsaKeyPair = JavaKeyPairGenerator.getInstance("RSA").generateKeyPair()

		val rsaPubKey2 = rsaKeyPair.public.encoded.toBase58()

		val rasKeyUri = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${RSA.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$rsaPubKey2"
		|	}
		|  ]
		|}""".trimMargin()

		val rsaSignature = rsaKeyPair.private.sign(document.toByteArray(UTF_8))

		val encodedRsaSignature = rsaSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${RSA.signatureID}",
		|	  "signatureBase58": "$encodedRsaSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation()

		assertThat(actual, isA<Success<Unit>>())
	}

	@Test
	fun `Validation succeeds for an envelope using a Ecdsa key`() {
		Security.addProvider(BouncyCastleProvider())
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${UUID.randomUUID()}").assertSuccess()

		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())
		val ecdsaKeyPair = g.generateKeyPair()
		val ecdsaPubKey2 = ecdsaKeyPair.public.encoded.toBase58()

		val ecdsaKeyUri = URI("${documentId.toExternalForm()}#keys-2")
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$ecdsaKeyUri",
		|	  "type": "${EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ecdsaPubKey2"
		|	}
		|  ]
		|}""".trimMargin()

		val ecdsaSignature = ecdsaKeyPair.private.sign(document.toByteArray(UTF_8))

		val encodedEcdsaSignature = ecdsaSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$ecdsaKeyUri",
		|	  "type": "${EcdsaSecp256k1.signatureID}",
		|	  "signatureBase58": "$encodedEcdsaSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val actual = DidEnvelope(instruction, document).validateCreation()

		assertThat(actual, isA<Success<Unit>>())
	}
}