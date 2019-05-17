/**
 * R3 copy
 *
 */

package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.isA
import net.corda.JsonFailure.InvalidCryptoSuiteFailure
import net.corda.assertFailure
import net.corda.assertSuccess
import net.corda.core.crypto.Base58
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.DidInstructionFailure.InvalidInstructionJsonFailure
import net.corda.did.DidInstructionFailure.UnknownActionFailure
import org.junit.Test
import java.net.URI
import kotlin.test.fail

class DidInstructionTests {

	@Test
	fun `Can parse a "read" instruction`() {
		val instruction = """{
		  "action": "read"
		}""".trimIndent()

		val actual = DidInstruction(instruction).action().assertSuccess()

		assertThat(actual, equalTo(Read))
	}

	@Test
	fun `Can parse a "update" instruction`() {
		val instruction = """{
		  "action": "update"
		}""".trimIndent()

		val actual = DidInstruction(instruction).action().assertSuccess()

		assertThat(actual, equalTo(Update))
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

		val actual = DidInstruction(instruction).signatures().assertSuccess().singleOrNull()
				?: fail("No signature found")

		assertThat(actual.suite, equalTo(Ed25519))
		assertThat(actual.target, equalTo(URI("did:corda:tcn:d51924e1-66bb-4971-ab62-ec4910a1fb98#keys-1")))
		assert(actual.value.contentEquals(Base58.decode("54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw")))
	}

	@Test
	fun `Rejects create instruction using an unknown crypto suite`() {
		val instruction = """{
		  "action": "create",
		  "signatures": [
			{
			  "id": "did:corda:tcn:d51924e1-66bb-4971-ab62-ec4910a1fb98#keys-1",
			  "type": "NonSenseCypherSignature1997",
			  "signatureBase58": "54CnhKVqE63rMAeM1b8CyQjL4c8teS1DoyTfZnKXRvEEGWK81YA6BAgQHRah4z1VV4aJpd2iRHCrPoNTxGXBBoFw"
			}
		  ]
		}""".trimIndent()

		val actual = DidInstruction(instruction).signatures().assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<InvalidInstructionJsonFailure>(
				has(InvalidInstructionJsonFailure::underlying, isA<InvalidCryptoSuiteFailure>(
						has(InvalidCryptoSuiteFailure::value, equalTo("NonSenseCypherSignature1997"))
				))
		))
	}

	@Test
	fun `Can parse a "delete" instruction`() {
		val instruction = """{
		  "action": "delete"
		}""".trimIndent()

		val actual = DidInstruction(instruction).action().assertSuccess()

		assertThat(actual, equalTo(Delete))
	}

	@Test
	fun `Rejects unknown instructions`() {
		val instruction = """{
		  "action": "doTheBartman"
		}""".trimIndent()

		val actual = DidInstruction(instruction).action().assertFailure()

		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<UnknownActionFailure>(
				has(UnknownActionFailure::action, equalTo("doTheBartman"))
		))
	}
}