package net.corda.did.flows

import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import org.junit.Test


class DeleteDidFlowTests : AbstractFlowTestUtils() {

    @Test
    fun `delete did successfully`() {
        // delete did
        deleteDID()!!.tx
        mockNetwork.waitQuiescent()

        // confirm did state with status as 'DELETED' on all 3 nodes
        w1.transaction {
            val states = w1.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.DELETED)
        }

        w2.transaction {
            val states = w2.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.DELETED)
        }

        originator.transaction {
            val states = originator.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.DELETED)
        }
    }
}