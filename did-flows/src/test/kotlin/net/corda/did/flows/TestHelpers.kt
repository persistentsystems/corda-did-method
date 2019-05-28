/**
 * Persistent code
 *
 */
package net.corda.did.flows

import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.crypto.sign
import net.corda.core.identity.CordaX500Name
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.testing.core.singleIdentity
import net.corda.testing.node.*
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.After
import org.junit.Before
import java.net.URI

/**
 * A base class to reduce the boilerplate when writing land title flow tests.
 */
abstract class AbstractFlowTestUtils {
	lateinit var mockNetwork: MockNetwork
	lateinit var originator: StartedMockNode
	lateinit var w1: StartedMockNode
	lateinit var w2: StartedMockNode
	val UUID = java.util.UUID.randomUUID()
	val documentId = net.corda.did.CordaDid("did:corda:tcn:${UUID}")
	val originalKeyUri = URI("${documentId.toExternalForm()}#keys-1")
	val originalKeyPair = KeyPairGenerator().generateKeyPair()
	val originalKeyPairEncoded = originalKeyPair.public.encoded.toBase58()

	@Before
	fun setup() {
		mockNetwork = MockNetwork(MockNetworkParameters(cordappsForAllNodes = listOf(TestCordapp.findCordapp("net.corda.did.state"), TestCordapp.findCordapp("net.corda.did.contract"), TestCordapp.findCordapp("net.corda.did.flows")), threadPerNode = true))
		originator = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Alice", locality = "TestLand", country = "US")))
		w1 = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Charlie", locality = "TestVillage", country = "US")))
		w2 = mockNetwork.createNode(MockNodeParameters(legalName = CordaX500Name(organisation = "Binh", locality = "TestVillage", country = "US")))
		listOf(originator, w1, w2).forEach { it.registerInitiatedFlow(DidFinalityFlowResponder::class.java) }
		mockNetwork.startNodes()
	}

	@After
	fun tearDown() {
		mockNetwork.stopNodes()
	}

	private fun getDidState() : DidState{

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
		return DidState(envelope, originator.info.singleIdentity(), setOf(w1.info.singleIdentity(), w2.info.singleIdentity()), DidStatus.VALID, UniqueIdentifier.fromString(UUID.toString()))
	}

	protected fun createDID(): SignedTransaction? {
		val didState = getDidState()
		val flow = CreateDidFlow(didState)
		val future = originator.startFlow(flow)
		return future.getOrThrow()
	}
}