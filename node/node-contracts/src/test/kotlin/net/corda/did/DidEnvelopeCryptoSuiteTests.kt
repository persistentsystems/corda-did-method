package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.core.utilities.toBase58
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.KeyPairGenerator
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import org.junit.Test
import java.net.URI
import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8

/**
 * Tests against all supported algorithms as per the "Linked Data Cryptographic Suite Registry"
 * Draft Community Group Report 09 December 2018 (https://w3c-ccg.github.io/ld-cryptosuite-registry)
 */
class DidEnvelopeCryptoSuiteTests {

	@Test
	fun `can parse valid envelope with Ed25519 key`() {
		/**
		 * 1. Generate a key pair
		 * (Test vectors taken from
		 * https://github.com/str4d/ed25519-java/blob/master/test/net/i2p/crypto/eddsa/EdDSAEngineTest.java)
		 */
		val spec = EdDSANamedCurveTable.getByName("Ed25519")
		val keyPair = KeyPairGenerator().generateKeyPair()
		val pubKeyBase58 = keyPair.public.encoded.toBase58()

		/**
		 * 2. Inject the key's Base58 representation into the DID document
		 */
		val keyUri = URI("did:example:00000000-0000-0000-0000-000000000000#keys-1")

		val document = """{
		  "@context": "https://w3id.org/did/v1",
		  "id": "did:corda:tcn:00000000-0000-0000-0000-000000000000",
		  "publicKey": [{
			"id": "$keyUri",
			"type": "Ed25519",
			"controller": "did:example:00000000-0000-0000-0000-000000000000",
			"publicKeyBase58": "$pubKeyBase58"
		  }]
		}""".trimIndent()

		/**
		 * 3. Sign the DID document
		 */
		val engine = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm)).also {
			it.initSign(keyPair.private)
		}

		engine.initSign(keyPair.private)
		engine.update(document.toByteArray(UTF_8))

		val signature = engine.sign()

		/**
		 * 4. Construct DID + Envelope
		 */
		val did = DidDocument(document)

		val envelope = DidEnvelope(did, mapOf(keyUri to signature))

		assertThat(envelope.hasIntegrity(), equalTo(true))
	}

	@Test
	fun `can parse valid envelope with RSA key`() {
		TODO()
	}

	@Test
	fun `can parse valid envelope with EdDsaSASecp256k1 key`() {
		TODO()
	}

	@Test
	fun `can parse valid envelope with multiple keys`() {
		TODO()
	}
}