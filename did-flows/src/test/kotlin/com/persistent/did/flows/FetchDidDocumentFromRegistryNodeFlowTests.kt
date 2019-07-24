package com.persistent.did.flows

import co.paralleluniverse.fibers.Suspendable
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.persistent.did.witness.flows.CreateDidFlow
import junit.framework.AssertionFailedError
import net.corda.core.crypto.sign
import net.corda.core.flows.FlowException
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.corda.did.DidDocument
import net.corda.did.DidEnvelope
import net.corda.testing.node.MockNetwork
import net.corda.testing.node.MockNetworkNotarySpec
import net.corda.testing.node.MockNetworkParameters
import net.corda.testing.node.MockNodeParameters
import net.corda.testing.node.StartedMockNode
import net.corda.testing.node.TestCordapp
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Test cases for [FetchDidDocumentFromRegistryNodeFlow]
 *
 * Nodes can query for did from did-registry member node by invoking [FetchDidDocumentFromRegistryNodeFlow] as a sub-flow.
 */
class FetchDidDocumentFromRegistryNodeFlowTests {
	lateinit var mockNetwork: MockNetwork
	lateinit var originator: StartedMockNode
	lateinit var w1: StartedMockNode
	lateinit var w2: StartedMockNode
	lateinit var NonMemberNode: StartedMockNode
	val notarySpec = CordaX500Name(organisation = "Notary", locality = "TestVillage", country = "US")
	val UUID = java.util.UUID.randomUUID()
	val documentId = net.corda.did.CordaDid.parseExternalForm("did:corda:tcn:${UUID}").assertSuccess()
	val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
	val originalKeyPair = KeyPairGenerator().generateKeyPair()
	val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()
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
				"O=Binh,L=TestVillage,C=US"), "notary" to "O=Notary,L=TestVillage,C=US", "network" to "tcn"))), threadPerNode = true, notarySpecs = listOf(MockNetworkNotarySpec(notarySpec, false))))
		originator = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Alice", locality = "TestLand", country = "US"), additionalCordapps = listOf(TestCordapp.findCordapp("com.persistent.did.state"), TestCordapp.findCordapp("com.persistent.did.contract"), TestCordapp.findCordapp("com.persistent.did.witness.flows").withConfig(mapOf("nodes" to listOf("O=Charlie,L=TestVillage,C=US",
				"O=Binh,L=TestVillage,C=US"), "notary" to "O=Notary,L=TestVillage,C=US", "network" to "tcn")))))
		w1 = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Charlie", locality = "TestVillage", country = "US"), additionalCordapps = listOf(TestCordapp.findCordapp("com.persistent.did.state"), TestCordapp.findCordapp("com.persistent.did.contract"), TestCordapp.findCordapp("com.persistent.did.witness.flows").withConfig(mapOf("nodes" to listOf("O=Charlie,L=TestVillage,C=US",
				"O=Binh,L=TestVillage,C=US"), "notary" to "O=Notary,L=TestVillage,C=US", "network" to "tcn")))))
		w2 = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Binh", locality = "TestVillage", country = "US"), additionalCordapps = listOf(TestCordapp.findCordapp("com.persistent.did.state"), TestCordapp.findCordapp("com.persistent.did.contract"), TestCordapp.findCordapp("com.persistent.did.witness.flows").withConfig(mapOf("nodes" to listOf("O=Charlie,L=TestVillage,C=US",
				"O=Binh,L=TestVillage,C=US"), "notary" to "O=Notary,L=TestVillage,C=US", "network" to "tcn")))))
		NonMemberNode = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Alex", locality = "TestLand", country = "US"), additionalCordapps = listOf(TestCordapp.findCordapp("com.persistent.did.flows"))))
		mockNetwork.startNodes()
	}

	@After
	fun tearDown() {
		mockNetwork.stopNodes()
	}

	fun getDidEnvelopeForCreateOperation(): DidEnvelope {
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

		return DidEnvelope(instruction, originalDocument)
	}

	fun createDID(envelope: DidEnvelope): SignedTransaction? {
		val flow = CreateDidFlow(envelope)
		val future = originator.startFlow(flow)
		return future.getOrThrow()
	}

	@InitiatingFlow
	@StartableByRPC
	class TestInitiator(private val didRegistryNode: Party, private val uuid: UUID) : FlowLogic<DidDocument>() {

		@Suspendable
		override fun call(): DidDocument {
			return subFlow(FetchDidDocumentFromRegistryNodeFlow(didRegistryNode, uuid))
		}
	}

	@Test
	fun `Fetch did document from did registry node`() {

		// create a did on ledger
		createDID(getDidEnvelopeForCreateOperation())
		mockNetwork.waitQuiescent()
		val flow = TestInitiator(originator.info.legalIdentities.first(), UUID)
		val future = originator.startFlow(flow)
		assertEquals(future.getOrThrow().didDocument, originalDocument)
	}

	@Test
	fun `Fetch did document should fail for invalid did uuid`() {
		// create a did on ledger
		createDID(getDidEnvelopeForCreateOperation())
		mockNetwork.waitQuiescent()
		val flow = TestInitiator(originator.info.legalIdentities.first(), java.util.UUID.randomUUID())
		val future = originator.startFlow(flow)
		assertFailsWith<FlowException> { future.getOrThrow() }
	}

	fun <T, E> Result<T, E>.assertSuccess(): T = when (this) {
		is Success -> this.value
		is Failure -> throw AssertionFailedError("Expected result to be a success but it failed: ${this.reason}")
	}
}