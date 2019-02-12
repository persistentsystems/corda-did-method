package net.corda.did

import net.corda.core.utilities.toBase58
import net.i2p.crypto.eddsa.KeyPairGenerator
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import org.junit.Test
import java.net.URI

class DidEnvelopeTests {
	@Test
	fun `Can parse a valid envelope`() {
		/**
		 * 1. Generate a key pair
		 * (Test vectors taken from
		 * https://github.com/str4d/ed25519-java/blob/master/test/net/i2p/crypto/eddsa/EdDSAEngineTest.java)
		 */
		val spec = EdDSANamedCurveTable.getByName("Ed25519")
		val keyPair = KeyPairGenerator().generateKeyPair()
		val pubKeyBase58 = keyPair.public.encoded.toBase58()
		val keyUri = URI("did:corda:tcn:00000000-0000-0000-0000-000000000000#keys-1")

		val envelope = """{
			"action": "create",
			"did": {
			  "@context": "https://w3id.org/did/v1",
			  "id": "did:corda:tcn:00000000-0000-0000-0000-000000000000",
			  "publicKey": [
				{
				  "id": "$keyUri",
				  "type": "Ed25519",
				  "controller": "did:example:00000000-0000-0000-0000-000000000000",
				  "publicKeyBase58": "$pubKeyBase58"
				}
			  ]
			}
		}""".trimIndent()

        println(envelope)
	}
}