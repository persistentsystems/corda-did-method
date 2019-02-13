package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.isA
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.DidValidationResult.DidValidationFailure.MalformedInstructionFailure
import net.corda.did.DidValidationResult.Success
import net.corda.did.Network.CordaNetwork
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import java.util.UUID
import kotlin.text.Charsets.UTF_8

class DidEnvelopeTests {

	@Test
	fun `Can parse a valid envelope creating a DID`() {
		/*
		 * 1. Generate a valid ID
		 */
		val id = CordaDid(CordaNetwork, UUID.randomUUID())

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
		val keyUri = URI("${id.toExternalForm()}#keys-1")

		/*
		 * 5. Build a valid DID document using the parameters generated
		 */
		val document = """{
		  "@context": "https://w3id.org/did/v1",
		  "id": "${id.toExternalForm()}",
		  "publicKey": [
			{
			  "id": "$keyUri",
			  "type": "${Ed25519.keyID}",
			  "controller": "${id.toExternalForm()}",
			  "publicKeyBase58": "$pubKeyBase58"
			}
		  ]
		}""".trimIndent()

		/*
		 * 6. Sign the DID generated in (5) with the key generated in (1)
		 */
		val signature = keyPair.private.sign(document.toByteArray(UTF_8))
		val base58Signature = signature.bytes.toBase58()

		/*
		 * 7. Build a valid instruction set for the DID generated
		 */
		val instruction = """{
		  "action": "create",
		  "signatures": [
			{
			  "id": "$keyUri",
			  "type": "Ed25519Signature2018",
			  "signatureBase58": "$base58Signature"
			}
		  ]
		}""".trimIndent()

		val actual = DidEnvelope(instruction, document).validate()

		/*
		 * 8. Test Instruction
		 */
		assertThat(actual, isA<Success>())
	}

	@Test
	fun `A document with malformed instruction will fail`() {
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

		assertThat(DidEnvelope(document, instruction).validate(), isA<MalformedInstructionFailure>())
	}
}