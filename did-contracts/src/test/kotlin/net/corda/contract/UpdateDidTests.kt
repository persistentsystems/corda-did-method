/**
 * Persistent code
 *
 */

package net.corda.contract

import net.corda.AbstractContractsStatesTestUtils
import net.corda.core.contracts.TypeOnlyCommandData
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract
import net.corda.did.state.DidStatus
import net.corda.testing.node.MockServices
import net.corda.testing.node.ledger
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI

class UpdateDidTests: AbstractContractsStatesTestUtils() {

    class DummyCommand : TypeOnlyCommandData()

    private var ledgerServices = MockServices(listOf("net.corda.did"))

    private fun getUpdatedEnvelope() : DidEnvelope {
        /*
        * Generate a new key pair
        */
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
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

        val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

        val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

        val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
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
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), UpdateDidTests.DummyCommand())
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.verifies()
            }
        }
    }

   @Test
    fun `transaction must have one input`() {
       val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
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
               command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
               this.fails()
           }
           transaction {
               input(DidContract.DID_CONTRACT_ID, getDidState())
               output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
               command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
               this.verifies()
           }
       }
   }

    @Test
    fun `status of precursor did must be VALID`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState().copy(status = DidStatus.INVALID))
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.verifies()
            }
        }
    }

    @Test
    fun `status of updated did must be VALID`() {
        val envelope = getUpdatedEnvelope()
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope, status = DidStatus.INVALID))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.verifies()
            }
        }
    }

   @Test
   fun `transaction must be signed by did originator`() {
       val envelope = getUpdatedEnvelope()
       ledgerServices.ledger {
           transaction {
               input(DidContract.DID_CONTRACT_ID, getDidState())
               output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
               command(listOf(W1.publicKey), DidContract.Commands.Update(envelope))
               this.fails()
           }
           transaction {
               input(DidContract.DID_CONTRACT_ID, getDidState())
               output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
               command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
               this.verifies()
           }
       }
   }

    @Test
    fun `id of the updated did document should not change`() {

        /*
        * Generate a new key pair
        */
        val UUID = java.util.UUID.randomUUID()
        val documentId = net.corda.did.CordaDid("did:corda:tcn:${UUID}")
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
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

        val signatureFromOldKey = originalKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

        val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
        val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

        val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

        val env = DidEnvelope(instruction, newDocument)
        ledgerServices.ledger {
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = env))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(env))
                this.fails()
            }
            transaction {
                input(DidContract.DID_CONTRACT_ID, getDidState())
                output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
                command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Update(envelope))
                this.verifies()
            }
        }
    }

   /*@Test
   fun `transaction validation fails for an envelope with multiple signatures targeting the same key`() {

       val documentId = net.corda.did.CordaDid("did:corda:tcn:${UUID.randomUUID()}")

       val kp = KeyPairGenerator().generateKeyPair()

       val pub = kp.public.encoded.toBase58()

       val uri = URI("${documentId.toExternalForm()}#keys-1")

       val document = """{
       |  "@context": "https://w3id.org/did/v1",
       |  "id": "${documentId.toExternalForm()}",
       |  "publicKey": [
       |	{
       |	  "id": "$uri",
       |	  "type": "${CryptoSuite.Ed25519.keyID}",
       |	  "controller": "${documentId.toExternalForm()}",
       |	  "publicKeyBase58": "$pub"
       |	}
       |  ]
       |}""".trimMargin()

       val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))
       val signature2 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

       val encodedSignature1 = signature1.bytes.toBase58()
       val encodedSignature2 = signature2.bytes.toBase58()

       val instruction = """{
       |  "action": "create",
       |  "signatures": [
       |	{
       |	  "id": "$uri",
       |	  "type": "Ed25519Signature2018",
       |	  "signatureBase58": "$encodedSignature1"
       |	},
       |	{
       |	  "id": "$uri",
       |	  "type": "Ed25519Signature2018",
       |	  "signatureBase58": "$encodedSignature2"
       |	}
       |  ]
       |}""".trimMargin()

       ledgerServices.ledger {
           transaction {
               output(DidContract.DID_CONTRACT_ID, CordaDid.copy(envelope = DidEnvelope(instruction, document)))
               command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Create(envelope))
               this.fails()
           }
       }
   }*/
}