/**
* Persistent code
*
*/

package net.corda.did.contract

import net.corda.did.utils.AbstractContractsStatesTestUtils
import net.corda.core.contracts.TypeOnlyCommandData
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract.Commands.Delete
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.testing.node.MockServices
import net.corda.testing.node.ledger
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI

/**
 * Test cases for [DidState] evolution specifically for [Delete] command.
 *
 */
class DeleteDidTests : AbstractContractsStatesTestUtils() {

    class DummyCommand : TypeOnlyCommandData()

    private var ledgerServices = MockServices(listOf("net.corda.did.contract"))

    private fun getUpdatedEnvelope() : DidEnvelope {

        val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

        val signature = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val encodedSignature = signature.bytes.toBase58()

        val instruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

        return DidEnvelope(instruction, newDocument)
    }

    @Test
    fun `transaction must include Update command`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DummyCommand())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `transaction must have one input`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `transaction must have one output`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `status of precursor did must be VALID`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState().copy(status = DidStatus.DELETED))
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `status of deleted did must be INVALID`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.ACTIVE))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `linearId of did state should not change when deleting did`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED, linearId = UniqueIdentifier()))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `did originator should not change when deleting did`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED, originator = W1.party))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `witness node list should not change when deleting did`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED, witnesses = setOf()))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `participants list should not change while deleting did`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED, participants = listOf()))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }

    @Test
    fun `publicKeys should not be altered in the did document`() {
        val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
        val newKeyPair = KeyPairGenerator().generateKeyPair()
        val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()

        val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	},
        |	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

        val signature = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val encodedSignature = signature.bytes.toBase58()

        val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

        val instruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	},
        |   {
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

        val envelope = DidEnvelope(instruction, newDocument)
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = getUpdatedEnvelope(), status = DidStatus.DELETED))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete())
                this.verifies()
            }
        }
    }
}