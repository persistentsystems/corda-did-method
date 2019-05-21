package net.corda.contract

import net.corda.AbstractContractsStatesTestUtils
import net.corda.core.contracts.TypeOnlyCommandData
import net.corda.did.contract.DidContract
import net.corda.testing.node.MockServices
import net.corda.testing.node.ledger
import org.junit.Test

class CreateDidTests: AbstractContractsStatesTestUtils() {

    class DummyCommand : TypeOnlyCommandData()

    private var ledgerServices = MockServices(listOf("net.corda.did"))

    @Test
    fun `transaction must include Create command`() {
        ledgerServices.ledger {
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), CreateDidTests.DummyCommand())
                this.fails()
            }
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
                this.verifies()
            }
        }
    }

    @Test
    fun `transaction must have no inputs`() {
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
                this.fails()
            }
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
                this.verifies()
            }
        }
    }


    @Test
    fun `transaction must have one output`() {
        ledgerServices.ledger {
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
                this.fails()
            }
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
                this.verifies()
            }
        }
    }

    @Test
    fun `transaction must be signed by did originator`() {
        ledgerServices.ledger {
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(W1.publicKey), DidContract.Commands.Create(envelope))
                this.fails()
            }
            transaction {
                output(DidContract.DID_CONTRACT_ID, CordaDid)
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
                this.verifies()
            }
        }
    }
}
