package net.corda.did

import com.natpryce.hamkrest.absent
import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.isA
import com.natpryce.hamkrest.throws
import net.corda.did.Action.Create
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import org.junit.Test

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
	fun `Can parse a "create" instruction`() {
		val instruction = """{
		  "action": "create"
		}""".trimIndent()

		val actual = DidInstruction(instruction)

		assertThat(actual.action(), equalTo(Create))
		assertThat(actual.nonce(), absent())
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