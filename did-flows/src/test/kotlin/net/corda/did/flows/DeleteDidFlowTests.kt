package net.corda.did.flows

import com.natpryce.valueOrNull
import net.corda.core.contracts.TransactionVerificationException
import net.corda.core.crypto.sign
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.toBase58
import net.corda.did.CordaDid
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.did.utils.DIDNotFoundException
import net.corda.testing.core.singleIdentity
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import kotlin.test.assertFailsWith

// ??? moritzplatt 2019-06-20 -- missing a test for various invalid input envelopes
// re-use some of the earlier test vectors from the did-contracts package

// nitesh solanki 2019-06-27 made changes as suggested.
/**
 * Test cases for [DeleteDidFlow]
 */
class DeleteDidFlowTests : AbstractFlowTestUtils() {

	@Test
	fun `delete did successfully`() {
		// delete did
		deleteDID(getDidStateForDeleteOperation().envelope)!!.tx
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

	@Test
	fun `Deletion fails for an envelope with wrong signature`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val keyUri = URI("${documentId.toExternalForm()}#keys-1")
		val keyPair = KeyPairGenerator().generateKeyPair()
		val encodedKey = keyPair.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey"
		|	}
		|  ]
		|}""".trimMargin()

		val bogusKeys = KeyPairGenerator().generateKeyPair()
		val signature = bogusKeys.private.sign(originalDocument.toByteArray(Charsets.UTF_8))
		val encodedSignature = signature.bytes.toBase58()

		val oldKeySignature = keyPair.private.sign(originalDocument.toByteArray(Charsets.UTF_8))
		val oldEncodedSignature = oldKeySignature.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$oldEncodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, originalDocument))
		mockNetwork.waitQuiescent()

		val deleteInstruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(deleteInstruction, originalDocument)
		val flow = DeleteDidFlow(envelope.rawInstruction, documentId.toExternalForm())
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }
	}

	@Test
	fun `Deletion fails for an envelope with irrelevant signatures`() {
		/*
		 * Generate valid base Document
		 */
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		/*
		 * Generate a key pair for the original document
		 */
		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")
		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val encodedKey1 = keyPair1.public.encoded.toBase58()

		val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature = keyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val encodedSignature = signature.bytes.toBase58()

		val oldSignature = keyPair1.private.sign(originalDocument.toByteArray(Charsets.UTF_8))
		val oldEncodedSignature = oldSignature.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$oldEncodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, originalDocument))
		mockNetwork.waitQuiescent()

		val deleteInstruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(deleteInstruction, originalDocument)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { deleteDID(envelope) }
	}

	@Test
	fun `SignedTransaction returned by the flow is signed by the did originator`() {
		val signedTx = deleteDID(getDidStateForDeleteOperation().envelope)!!
		signedTx.verifySignaturesExcept(listOf(w1.info.singleIdentity().owningKey, w2.info.singleIdentity().owningKey))
	}

	@Test
	fun `flow throws DIDNotFound exception for invalid did`() {
		val flow = DeleteDidFlow(getDidStateForDeleteOperation().envelope.rawInstruction, getDidStateForDeleteOperation().envelope.document.id().valueOrNull()!!.toExternalForm())
		val future = originator.startFlow(flow)
		mockNetwork.waitQuiescent()
		assertFailsWith<DIDNotFoundException> { future.getOrThrow() }
	}
}