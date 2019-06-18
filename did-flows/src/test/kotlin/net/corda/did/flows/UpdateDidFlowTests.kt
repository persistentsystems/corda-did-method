package net.corda.did.flows

import net.corda.core.utilities.getOrThrow
import net.corda.did.state.DidState
import net.corda.did.utils.DIDNotFoundException
import net.corda.testing.core.singleIdentity
import org.junit.Test
import kotlin.test.assertFailsWith


class UpdateDidFlowTests : AbstractFlowTestUtils() {

    @Test
    fun `update did successfully`() {
        // update did
        updateDID()!!.tx
        mockNetwork.waitQuiescent()

        w1.transaction {
            val states = w1.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.envelope.rawDocument.equals(getDidStateForUpdateOperation().envelope.rawDocument))
        }

        w2.transaction {
            val states = w2.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.envelope.rawDocument.equals(getDidStateForUpdateOperation().envelope.rawDocument))
        }

        originator.transaction {
            val states = originator.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.envelope.rawDocument.equals(getDidStateForUpdateOperation().envelope.rawDocument))
        }
    }

    @Test
    fun `SignedTransaction returned by the flow is signed by the did originator`() {
        val signedTx = updateDID()!!
        signedTx.verifySignaturesExcept(listOf(w1.info.singleIdentity().owningKey, w2.info.singleIdentity().owningKey))
    }

    @Test
    fun `flow throws DIDNotFound exception for invalid did`() {
        val flow = UpdateDidFlow(getDidStateForUpdateOperation())
        val future = originator.startFlow(flow)
        mockNetwork.waitQuiescent()
        assertFailsWith<DIDNotFoundException> {  future.getOrThrow() }
    }
}