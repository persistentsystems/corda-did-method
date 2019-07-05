package net.corda.did.utils

import co.paralleluniverse.fibers.Suspendable
import net.corda.AbstractFetchDidDocumentFromRegistryNodeFlow
import net.corda.core.CordaRuntimeException
import net.corda.core.contracts.ContractState
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

    fun ServiceHub.getNotaryFromConfig(): Party? {
        val config = this.getAppContext().config
        val notary = config.get("notary")
        return this.networkMapCache.getNotary(CordaX500Name.parse(notary.toString())) ?: throw NotaryNotFoundException("Notary not found")
    }

    fun <T : ContractState> ServiceHub.loadState(linearId: UniqueIdentifier, clazz: Class<T>): List<StateAndRef<T>> {
        val queryCriteria = QueryCriteria.LinearStateQueryCriteria(null,
                listOf(linearId), Vault.StateStatus.UNCONSUMED, null)
        return this.vaultService.queryBy(clazz, queryCriteria).states
    }


@InitiatingFlow
class FetchDidDocument(private val linearId: UniqueIdentifier) : FlowLogic<DidDocument> (){
    @Suspendable
    override fun call(): DidDocument {
       try {
          return  serviceHub.loadState(linearId, DidState::class.java).singleOrNull()!!.state.data.envelope.document
        } catch (e: Exception) {
            throw FlowException(e)
        }
    }
}

@InitiatedBy(AbstractFetchDidDocumentFromRegistryNodeFlow::class)
class FetchDidDocumentFromRegistryNodeResponderFlow(private val session: FlowSession) : FlowLogic<Unit> (){

    companion object {
        object RECEIVING : ProgressTracker.Step("Receiving DID request")
        object FETCHING : ProgressTracker.Step("Fetching DID from vault")
        object SENDING : ProgressTracker.Step("Sending DID Document")
    }

    override val progressTracker = ProgressTracker(RECEIVING, FETCHING, SENDING)

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