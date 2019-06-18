package net.corda.did.flows

import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.did.utils.DIDAlreadyExistException
import net.corda.testing.core.singleIdentity
import org.junit.Test
import kotlin.test.assertFailsWith

class CreateDidFlowTests : AbstractFlowTestUtils() {

    @Test
    fun `create new did successfully`() {
        // create did
        createDID()!!.tx
        mockNetwork.waitQuiescent()

        // confirm did state with status as 'VALID' on all 3 nodes
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
        // create did
        createDID()!!.tx
        mockNetwork.waitQuiescent()

        // confirm did state with status as 'VALID' on all 3 nodes
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

        assertFailsWith<DIDAlreadyExistException> { createDID() }
    }

    @Test
    fun `SignedTransaction returned by the flow is signed by the did originator`() {
        val signedTx = createDID()!!
        signedTx.verifySignaturesExcept(listOf(w1.info.singleIdentity().owningKey, w2.info.singleIdentity().owningKey))
    }
}