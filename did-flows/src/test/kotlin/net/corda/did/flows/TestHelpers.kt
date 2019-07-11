package net.corda.did.flows

import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import junit.framework.AssertionFailedError
import net.corda.core.identity.CordaX500Name
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
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
		mockNetwork = MockNetwork(MockNetworkParameters(cordappsForAllNodes = listOf(TestCordapp.findCordapp("net.corda.did.state"), TestCordapp.findCordapp("net.corda.did.contract"), TestCordapp.findCordapp("net.corda.did.flows").withConfig(mapOf("nodes" to listOf("O=Charlie,L=TestVillage,C=US",
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
}

fun <T, E> Result<T, E>.assertSuccess(): T = when (this) {
	is Success -> this.value
	is Failure -> throw AssertionFailedError("Expected result to be a success but it failed: ${this.reason}")
}