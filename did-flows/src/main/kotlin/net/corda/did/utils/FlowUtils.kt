package net.corda.did.utils

import co.paralleluniverse.fibers.Suspendable
import net.corda.AbstractFetchDidDocumentFromRegistryNodeFlow
import net.corda.core.CordaRuntimeException
import net.corda.core.contracts.ContractState
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.*
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.node.services.Vault
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.core.utilities.ProgressTracker
import net.corda.core.utilities.unwrap
import net.corda.did.DidDocument
import net.corda.did.state.DidState

// ??? moritzplatt 2019-06-20 -- these dont need to be encapsulated in an interface but can be standalone extension
// methods just as well

    /**
     * returns a notary from cordapp-config file or throws an exception if notary not found in the nodes network map cache.
     *
     * @receiver [ServiceHub]
     * @return [Party]
     * @throws NotaryNotFoundException
     */
    fun ServiceHub.getNotaryFromConfig(): Party? {
        val config = this.getAppContext().config
        val notary = config.get("notary")
        return this.networkMapCache.getNotary(CordaX500Name.parse(notary.toString())) ?: throw NotaryNotFoundException("Notary not found")
    }

    /**
     * returns list of [StateAndRef] for given linearId
     *
     * @param T the type of state
     * @param linearId the linearId of the [LinearState] to be queried
     * @receiver [ServiceHub]
     * @return [List<StateAndRef>]
     */
    fun <T : ContractState> ServiceHub.loadState(linearId: UniqueIdentifier, clazz: Class<T>): List<StateAndRef<T>> {
        val queryCriteria = QueryCriteria.LinearStateQueryCriteria(null,
                listOf(linearId), Vault.StateStatus.UNCONSUMED, null)
        return this.vaultService.queryBy(clazz, queryCriteria).states
    }



/**
 * Initiating flow to Fetch the [DidDocument] from ledger.
 *
 * @property linearId the linearId of the [DidState].
 */
@InitiatingFlow
class FetchDidDocument(private val linearId: UniqueIdentifier) : FlowLogic<DidDocument> (){

    /**
     * Loads the [DidState] from the ledger and returns the [DidDocument] or throws an exception if DID not found.
     * @return [DidDocument]
     * @throws FlowException
     */
    @Suspendable
    override fun call(): DidDocument {
       try {
          return  serviceHub.loadState(linearId, DidState::class.java).singleOrNull()!!.state.data.envelope.document
        } catch (e: Exception) {
            throw FlowException(e)
        }
    }
}

/**
 * InitiatedBy flow to Fetch the [DidDocument] from ledger. This is a responder flow implementation for nodes attempting to query for [DidDocument] from the did-registry Business network.
 * This feature is required to support interoperability between different CorDapps that depends on the [DidDocument].
 *
 * Use case: a Business Network running a Trade Finance CorDapp may have a constraint in the smart contract to verify the digital signature of end-user represented as a did on ledger. a TF CorDapp can create a session with the did-registry node that is part of another Business Network to
 * fetch the [DidDocument] and hence obtain the publicKey needed to verify the signature.
 *
 * @property session the flow session between initiator and responder.
 */
@InitiatedBy(AbstractFetchDidDocumentFromRegistryNodeFlow::class)
class FetchDidDocumentFromRegistryNodeResponderFlow(private val session: FlowSession) : FlowLogic<Unit> (){

    companion object {
        object RECEIVING : ProgressTracker.Step("Receiving DID request")
        object FETCHING : ProgressTracker.Step("Fetching DID from vault")
        object SENDING : ProgressTracker.Step("Sending DID Document")
    }

    override val progressTracker = ProgressTracker(RECEIVING, FETCHING, SENDING)

    /**
     * Loads the [DidState] from the ledger and returns the [DidDocument] or throws an exception if DID not found.
     * @throws FlowException
     */
    @Suspendable
    override fun call() {
        progressTracker.currentStep = RECEIVING
        val linearId = session.receive<UniqueIdentifier>().unwrap { it }

        progressTracker.currentStep = FETCHING
       val response = try {
              serviceHub.loadState(linearId, DidState::class.java).singleOrNull()!!.state.data.envelope.document
        } catch (e: Exception) {
            throw FlowException(e)
        }

        progressTracker.currentStep = SENDING
        session.send(response)
    }
}

class NotaryNotFoundException(override val message: String) : CordaRuntimeException(message)
class DIDAlreadyExistException(override val message: String) : CordaRuntimeException(message)
class DIDNotFoundException(override val message: String) : CordaRuntimeException(message)
class InvalidDIDException(override val message: String) : CordaRuntimeException(message)