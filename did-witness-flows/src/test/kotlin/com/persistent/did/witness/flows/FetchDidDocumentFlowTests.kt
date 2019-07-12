package com.persistent.did.witness.flows

import net.corda.core.flows.FlowException
import net.corda.core.utilities.getOrThrow
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Test cases for [FetchDidDocumentFlow]
 *
 * Nodes can fetch did from their local vault by invoking [FetchDidDocumentFlow] as a sub-flow.
 */
class FetchDidDocumentFlowTests : AbstractFlowTestUtils() {

	@Test
	fun `fetch did document from local vault successfully`() {
		// create a did on ledger
		createDID(getDidStateForCreateOperation().envelope)
		mockNetwork.waitQuiescent()
		// query for did
		val flow = TestInitiator(UUID)
		val future = originator.startFlow(flow)
		assertEquals(future.getOrThrow().document1, originalDocument)
	}

	@Test
	fun `fetch did document fails for invalid did`() {
		// create a did on ledger
		createDID(getDidStateForCreateOperation().envelope)
		mockNetwork.waitQuiescent()
		// query for did
		val flow = TestInitiator(java.util.UUID.randomUUID())
		val future = originator.startFlow(flow)
		assertFailsWith<FlowException> { future.getOrThrow() }
	}
}