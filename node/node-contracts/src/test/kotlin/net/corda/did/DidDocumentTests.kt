package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.core.crypto.Base58
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.SpecExamples.`Minimal self-managed DID Document`
import org.junit.Test
import java.net.URI
import kotlin.test.fail

class DidDocumentTests {

	@Test
	fun `ID can be extracted from a DID document`() {
		val example = DidDocument(`Minimal self-managed DID Document`)

		assertThat(
				actual = example.id().toExternalForm(),
				criteria = equalTo(Did("did:example:123456789abcdefghi").toExternalForm())
		)
	}

	@Test
	fun `A supported public key can be extracted from a DID document`() {
		val example = """{
		  "@context": "https://w3id.org/did/v1",
		  "id": "did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5",
		  "publicKey": [
			{
			  "id": "did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5#keys-1",
			  "type": "Ed25519VerificationKey2018",
			  "controller": "did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5",
			  "publicKeyBase58": "GfHq2tTVk9z4eXgyMgnD6wQyn62rJfLAnyCB1aAteTjiZj3ejUbjuV4CU4bc"
			}
		  ]
		}""".trimMargin()

		val actual = DidDocument(example)

		val actualKey = actual.publicKeys().singleOrNull() ?: fail("Public Key cannot be extracted")

		assertThat(actualKey.controller, equalTo(URI("did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5")))
		assertThat(actualKey.id, equalTo(URI("did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5#keys-1")))
		assertThat(actualKey.type, equalTo(Ed25519))
		assert(actualKey.value.contentEquals(Base58.decode("GfHq2tTVk9z4eXgyMgnD6wQyn62rJfLAnyCB1aAteTjiZj3ejUbjuV4CU4bc")))
	}
}