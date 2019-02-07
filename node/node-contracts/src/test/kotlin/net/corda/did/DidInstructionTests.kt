package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.did.Action.Read
import org.junit.Test

class DidInstructionTests {

	@Test
	fun `Can parse a "read" instruction`() {
		val instruction = """{
		  "action": "read"
		}""".trimIndent()

		val actual = DidInstruction(instruction)

		assertThat(actual.action(), equalTo(Read))
	}

	@Test
	fun `Can parse an "update" instruction`() {

	}
}