package com.persistent.did.witness.flows

import co.paralleluniverse.fibers.Suspendable
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.valueOrNull
import com.persistent.did.state.DidState
import com.persistent.did.state.DidStatus
import junit.framework.AssertionFailedError
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.crypto.sign
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.identity.CordaX500Name
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.corda.did.DidDocument
import net.corda.did.DidEnvelope
import net.corda.testing.core.singleIdentity
import net.corda.testing.node.MockNetwork
import net.corda.testing.node.MockNetworkNotarySpec
import net.corda.testing.node.MockNetworkParameters
import net.corda.testing.node.MockNodeParameters
import net.corda.testing.node.StartedMockNode
import net.corda.testing.node.TestCordapp
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.After
import org.junit.Before
import java.net.URI
import java.util.UUID

/**
 * Helper class for Flow tests
 */
abstract class AbstractFlowTestUtils {
	lateinit var mockNetwork: MockNetwork
	lateinit var originator: StartedMockNode
	lateinit var w1: StartedMockNode
	lateinit var w2: StartedMockNode
	val notarySpec = CordaX500Name(organisation = "Notary", locality = "TestVillage", country = "US")
	val UUID = java.util.UUID.randomUUID()
	val documentId = net.corda.did.CordaDid.parseExternalForm("did:corda:tcn:${UUID}").assertSuccess()
	val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
	val originalKeyPair = KeyPairGenerator().generateKeyPair()
	val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()
	val newKeyUri = URI("${documentId.toExternalForm()}#keys-2")
	val newKeyPair = KeyPairGenerator().generateKeyPair()
	val newKeyPairEncoded = newKeyPair.public.encoded.toBase58()
	val originalDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$originalKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

	@Before
	fun setup() {
		mockNetwork = MockNetwork(MockNetworkParameters(cordappsForAllNodes = listOf(TestCordapp.findCordapp("com.persistent.did.state"), TestCordapp.findCordapp("com.persistent.did.contract"), TestCordapp.findCordapp("com.persistent.did.witness.flows").withConfig(mapOf("nodes" to listOf("O=Charlie,L=TestVillage,C=US",
				"O=Binh,L=TestVillage,C=US"), "notary" to "O=Notary,L=TestVillage,C=US"))), threadPerNode = true, notarySpecs = listOf(MockNetworkNotarySpec(notarySpec, false))))
		originator = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Alice", locality = "TestLand", country = "US")))
		w1 = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Charlie", locality = "TestVillage", country = "US")))
		w2 = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Binh", locality = "TestVillage", country = "US")))
		mockNetwork.startNodes()
	}

	@After
	fun tearDown() {
		mockNetwork.stopNodes()
	}

	protected fun getDidStateForCreateOperation(): DidState {
		val signatureFromOldKey = originalKeyPair.private.sign(originalDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, originalDocument)
		return DidState(envelope, originator.info.singleIdentity(), setOf(w1.info.singleIdentity(), w2.info.singleIdentity()), DidStatus.ACTIVE, UniqueIdentifier.fromString(UUID.toString()))
	}

	protected fun getDidStateForDeleteOperation(): DidState {
		val signatureFromOldKey = originalKeyPair.private.sign(originalDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKeyEncoded = signatureFromOldKey.bytes.toBase58()

		val instruction = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$originalKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, originalDocument)
		return DidState(envelope, originator.info.singleIdentity(), setOf(w1.info.singleIdentity(), w2.info.singleIdentity()), DidStatus.DELETED, UniqueIdentifier.fromString(UUID.toString()))
	}

	protected fun getDidStateForUpdateOperation(): DidState {
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

		val envelope = DidEnvelope(instruction, newDocument)
		return DidState(envelope, originator.info.singleIdentity(), setOf(w1.info.singleIdentity(), w2.info.singleIdentity()), DidStatus.ACTIVE, UniqueIdentifier.fromString(UUID.toString()))
	}

	protected fun createDID(envelope: DidEnvelope): SignedTransaction? {
		val flow = CreateDidFlow(envelope)
		val future = originator.startFlow(flow)
		return future.getOrThrow()
	}

	protected fun deleteDID(envelope: DidEnvelope): SignedTransaction? {
		createDID(getDidStateForCreateOperation().envelope)!!.tx
		mockNetwork.waitQuiescent()
		val flow = DeleteDidFlow(envelope.rawInstruction, envelope.document.id().valueOrNull()!!.toExternalForm())
		val future = originator.startFlow(flow)
		return future.getOrThrow()
	}

	protected fun updateDID(envelope: DidEnvelope): SignedTransaction? {
		createDID(getDidStateForCreateOperation().envelope)!!.tx
		mockNetwork.waitQuiescent()
		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		return future.getOrThrow()
	}

	@InitiatingFlow
	@StartableByRPC
	class TestInitiator(private val uuid: UUID) : FlowLogic<DidDocument>() {

		@Suspendable
		override fun call(): DidDocument {
			return subFlow(FetchDidDocumentFlow(UniqueIdentifier(null, uuid)))
		}
	}
}

fun <T, E> Result<T, E>.assertSuccess(): T = when (this) {
	is Success -> this.value
	is Failure -> throw AssertionFailedError("Expected result to be a success but it failed: ${this.reason}")
}