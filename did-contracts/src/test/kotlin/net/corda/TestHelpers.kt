
package net.corda

import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import junit.framework.AssertionFailedError
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.CordaX500Name
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.testing.core.TestIdentity

/**
 * Persistent code
 *
 */
abstract class AbstractContractsStatesTestUtils {
	val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "3jSNdLMeFmsXKy6155d2xSvSzkRcTYSMpXHefYFmGvUg72N3SveezRNbyTaVqvaZ8nD5MA8zGbznWzXdt54e5k8H"
		|	}
		|  ]
		|}""".trimMargin()

	val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyFWjZCLwoH9C7qZb3KvhZVfj2J2wti62dnrH9Hv4HvxZG"
		|	}
		|  ]
		|}""".trimMargin()

	val envelope = net.corda.did.DidEnvelope(instruction, document)
	val ORIGINATOR = TestIdentity(CordaX500Name(organisation = "Alice", locality = "TestLand", country = "US"))
	var W1 = TestIdentity(CordaX500Name(organisation = "Charlie", locality = "TestVillage", country = "US"))
	var W2 = TestIdentity(CordaX500Name(organisation = "Binh", locality = "TestVillage", country = "US"))
	val CordaDid = DidState(envelope, ORIGINATOR.party, setOf(W1.party, W2.party), DidStatus.VALID, UniqueIdentifier.fromString("77ccbf5e-4ddd-4092-b813-ac06084a3eb0"))
}

/**
 * R3 code
 *
 */
fun <T, E> Result<T, E>.assertSuccess(): T = when (this) {
	is Success -> this.value
	is Failure -> throw AssertionFailedError("Expected result to be a success but it failed: ${this.reason}")
}

/**
 * R3 code
 *
 */
fun <T, E> Result<T, E>.assertFailure(): E = when (this) {
	is Success -> throw AssertionFailedError("Expected result to be a failure but was a success")
	is Failure -> this.reason
}
