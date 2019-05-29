package net.corda.did.flows

import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.did.utils.DIDAlreadyExist
import org.junit.Test
import kotlin.test.assertFailsWith

class CreateDidFlowTests : AbstractFlowTestUtils() {

    @Test
    fun `create new did successfully`() {
        // crete did
        val tx = createDID()!!.tx
        mockNetwork.waitQuiescent()

        // confirm did state with status as 'VALID' on both all 3 nodes
        w1.transaction {
            val states = w1.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.VALID)
        }

        w2.transaction {
            val states = w2.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.VALID)
        }

        originator.transaction {
            val states = originator.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.VALID)
        }
    }

    @Test
    fun `create did should fail if did already exist`() {
        // crete did
        val tx = createDID()!!.tx
        mockNetwork.waitQuiescent()

        // confirm did state with status as 'VALID' on both all 3 nodes
        w1.transaction {
            val states = w1.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.VALID)
        }

        w2.transaction {
            val states = w2.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.VALID)
        }

        originator.transaction {
            val states = originator.services.vaultService.queryBy(DidState::class.java).states
            assert(states.size == 1)
            assert(states[0].state.data.status == DidStatus.VALID)
        }


       // mockNetwork.waitQuiescent()
        assertFailsWith<DIDAlreadyExist> { createDID() }
    }
}