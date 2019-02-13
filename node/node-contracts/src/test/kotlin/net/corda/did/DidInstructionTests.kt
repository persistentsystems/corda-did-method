package net.corda.did

import com.natpryce.hamkrest.absent
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.isA
import com.natpryce.hamkrest.throws
import net.corda.core.crypto.Base58
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import net.corda.did.CryptoSuite.Ed25519
import org.junit.Test
import java.net.URI
import kotlin.test.fail

class DidInstructionTests {

	@Test
	fun `Can parse a "read" instruction`() {
		val instruction = """{
		  "action": "read"
		}""".trimIndent()

		val actual = DidInstruction(instruction)

		assertThat(actual.action(), equalTo(Read))
		assertThat(actual.nonce(), absent())
	}

	@Test
	fun `Can parse a "update" instruction`() {
		val instruction = """{
		  "action": "update",
		  "nonce": "foobar"
		}""".trimIndent()

		val actual = DidInstruction(instruction)

		assertThat(actual.action(), equalTo(Update))
		assertThat(actual.nonce(), equalTo("foobar"))
	}

	@Test
	fun `Can parse a "create" instruction using a well-known crypto suite`() {
		val instruction = """{
		  "action": "create",
		  "signatures": [
			{
			  "id": "did:corda:tcn:d51924e1-66bb-4971-ab62-ec4910a1fb98#keys-1",
			  "type": "Ed25519Signature2018",
			  "signatureBase58": "54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw"
			}
		  ]
		}""".trimIndent()

		val actual = DidInstruction(instruction).signatures().singleOrNull() ?: fail("No signature found")

		assertThat(actual.suite, equalTo(Ed25519))
		assertThat(actual.target, equalTo(URI("did:corda:tcn:d51924e1-66bb-4971-ab62-ec4910a1fb98#keys-1")))
		assert(actual.value.contentEquals(Base58.decode("54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw")))
	}

	@Test
	fun `Rejects "create" instruction using an unknown well-known crypto suite`() {
		val instruction = """{
		  "action": "create",
		  "signatures": [
			{
			  "id": "did:corda:tcn:d51924e1-66bb-4971-ab62-ec4910a1fb98#keys-1",
			  "type": "Ed25519Signature2525",
			  "signatureBase58": "54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw"
			}
		  ]
		}""".trimIndent()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat({ DidInstruction(instruction).signatures() }, throws(isA<IllegalArgumentException>(
				has(IllegalArgumentException::message, equalTo("Unknown ID")))
		))
	}

	@Test
	fun `Can parse a "delete" instruction`() {
		val instruction = """{
		  "action": "delete",
		  "nonce": "foobar"
		}""".trimIndent()

		val actual = DidInstruction(instruction)

		assertThat(actual.action(), equalTo(Delete))
		assertThat(actual.nonce(), equalTo("foobar"))
	}

	@Test
	fun `Rejects unknown instructions`() {
		val instruction = """{
		  "action": "doTheBartman"
		}""".trimIndent()

		val actual = DidInstruction(instruction)

		@Suppress("RemoveExplicitTypeArguments")
		assertThat({ actual.action() }, throws(isA<IllegalArgumentException>(
				has(IllegalArgumentException::message, equalTo("Unknown action doTheBartman.")))
		))
	}
}