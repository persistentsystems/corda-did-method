package com.persistent.did.contract

import com.persistent.did.contract.DidContract.Commands.Delete
import com.persistent.did.state.DidState
import com.persistent.did.utils.AbstractContractsStatesTestUtils
import net.corda.core.contracts.TypeOnlyCommandData
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.testing.node.MockServices
import net.corda.testing.node.ledger
import org.junit.Test

/**
 * Test cases for [DidState] evolution specifically for [Delete] command.
 *
 */
class DeleteDidTests : AbstractContractsStatesTestUtils() {

	class DummyCommand : TypeOnlyCommandData()

	private var ledgerServices = MockServices(listOf("com.persistent.did.contract"))

	private fun getEnvelopeForDelete(): DidEnvelope {

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
	fun `transaction must include Delete command`() {
		val envelope = getEnvelopeForDelete()
		ledgerServices.ledger {
			transaction {
				input(DidContract.DID_CONTRACT_ID, getDidState())
				command(listOf(ORIGINATOR.publicKey), DummyCommand())
				this.fails()
			}
			transaction {
				input(DidContract.DID_CONTRACT_ID, getDidState())
				command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete(envelope))
				this.verifies()
			}
		}
	}

	@Test
	fun `transaction must have one input`() {
		val envelope = getEnvelopeForDelete()
		ledgerServices.ledger {
			transaction {
				input(DidContract.DID_CONTRACT_ID, getDidState())
				input(DidContract.DID_CONTRACT_ID, getDidState())
				command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete(envelope))
				this.fails()
			}
			transaction {
				input(DidContract.DID_CONTRACT_ID, getDidState())
				command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete(envelope))
				this.verifies()
			}
		}
	}

	@Test
	fun `transaction must have no output`() {
		val envelope = getEnvelopeForDelete()
		ledgerServices.ledger {
			transaction {
				input(DidContract.DID_CONTRACT_ID, getDidState())
				output(DidContract.DID_CONTRACT_ID, getDidState().copy(envelope = envelope))
				command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete(envelope))
				this.fails()
			}
			transaction {
				input(DidContract.DID_CONTRACT_ID, getDidState())
				command(listOf(ORIGINATOR.publicKey), DidContract.Commands.Delete(envelope))
				this.verifies()
			}
		}
	}
}