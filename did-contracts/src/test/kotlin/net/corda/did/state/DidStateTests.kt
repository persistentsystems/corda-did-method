package net.corda.did.state

import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.Party
import net.corda.did.DidEnvelope
import net.corda.did.utils.AbstractContractsStatesTestUtils
import org.junit.Test
import kotlin.test.assertEquals

/**
 * Test cases for [DidState]
 */
class DidStateTests : AbstractContractsStatesTestUtils() {

	/**
	 * Test 1.
	 *
	 */
	@Test
	fun `has envelope Field Of Correct Type`() {
		// Does the envelope field exist?
		DidState::class.java.getDeclaredField("envelope")
		// Is the envelope field of the correct type?
		assertEquals(DidState::class.java.getDeclaredField("envelope").type, DidEnvelope::class.java)
	}

	/**
	 * Test 2.
	 *
	 */
	@Test
	fun `has originator Field Of Correct Type`() {
		// Does the originator field exist?
		DidState::class.java.getDeclaredField("originator")
		// Is the originator field of the correct type?
		assertEquals(DidState::class.java.getDeclaredField("originator").type, Party::class.java)
	}

	/**
	 * Test 3.
	 *
	 */
	@Test
	fun `has witnesses Field Of Correct Type`() {
		// Does the witnesses field exist?
		DidState::class.java.getDeclaredField("witnesses")
		// Is the witnesses field of the correct type?
		assertEquals(DidState::class.java.getDeclaredField("witnesses").type, Set::class.java)
	}

	/**
	 * Test 4.
	 *
	 */
	@Test
	fun `has status Field Of Correct Type`() {
		// Does the status field exist?
		DidState::class.java.getDeclaredField("status")
		// Is the status field of the correct type?
		assertEquals(DidState::class.java.getDeclaredField("status").type, DidStatus::class.java)
	}

	/**
	 * Test 5.
	 *
	 */
	@Test
	fun `has linearId Field Of Correct Type`() {
		// Does the linearId field exist?
		DidState::class.java.getDeclaredField("linearId")
		// Is the linearId field of the correct type?
		assertEquals(DidState::class.java.getDeclaredField("linearId").type, UniqueIdentifier::class.java)
	}

}