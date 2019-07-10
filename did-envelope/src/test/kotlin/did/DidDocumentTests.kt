

package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.assertSuccess
import net.corda.core.crypto.Base58
import net.corda.did.CryptoSuite.Ed25519
import org.junit.Test
import java.net.URI
import java.time.Instant
import java.time.Instant.EPOCH
import kotlin.test.fail

/**
 * Test cases for [DidDocument]
 */
class DidDocumentTests {

	@Test
	fun `ID can be extracted from a DID document`() {
		val example = DidDocument("""{
			  "@context": "https://w3id.org/did/v1",
			  "id": "did:corda:tcn:0e61ab14-73a3-4a7b-846b-15d6bca78b31",
			  "publicKey": [{
				"id": "did:example:123456789abcdefghi#keys-1",
				"type": "RsaVerificationKey2018",
				"controller": "did:example:123456789abcdefghi",
				"publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
			  }],
			  "authentication": [{
				"type": "RsaSignatureAuthentication2018",
				"publicKey": "did:example:123456789abcdefghi#keys-1"
			  }],
			  "service": [{
				"type": "ExampleService",
				"serviceEndpoint": "https://example.com/endpoint/8377464"
			  }]
			}""".trimIndent())

		assertThat(
				actual = example.id().assertSuccess().toExternalForm(),
				criteria = equalTo(CordaDid.parseExternalForm("did:corda:tcn:0e61ab14-73a3-4a7b-846b-15d6bca78b31").assertSuccess().toExternalForm())
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

		val actualKey = actual.publicKeys().assertSuccess().singleOrNull() ?: fail("Public Key cannot be extracted")

		assertThat(actualKey.controller, equalTo(URI("did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5")))
		assertThat(actualKey.id, equalTo(URI("did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5#keys-1")))
		assertThat(actualKey.type, equalTo(Ed25519))
		assert(actualKey.value.contentEquals(Base58.decode("GfHq2tTVk9z4eXgyMgnD6wQyn62rJfLAnyCB1aAteTjiZj3ejUbjuV4CU4bc")))
	}

	@Test
	fun `timestamps can be extracted from a DID`() {
		val example = """{
		  "@context": "https://w3id.org/did/v1",
		  "id": "did:corda:tcn:4ff0fc2f-bc97-4c0c-8b64-46b2f68131f5",
		  "created": "1970-01-01T00:00:00Z",
		  "updated": "2019-02-14T14:00:00Z",
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

		val created = actual.created().assertSuccess()
		val updated = actual.updated().assertSuccess()

		assertThat(created, equalTo(EPOCH))
		assertThat(updated, equalTo(Instant.parse("2019-02-14T14:00:00Z")))
	}
}
