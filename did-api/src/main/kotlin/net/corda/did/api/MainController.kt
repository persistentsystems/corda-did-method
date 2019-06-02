/**
 * Persistent code
 *
 */

package net.corda.did.api
import com.natpryce.map
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.CordaX500Name
import net.corda.core.messaging.vaultQueryBy
import net.corda.core.node.services.Vault
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.core.node.services.vault.builder
import net.corda.core.utilities.getOrThrow
import net.corda.did.state.DidState
import net.corda.did.state.DidStateSchemaV1
import org.springframework.http.MediaType
import org.springframework.http.MediaType.*
import org.springframework.web.bind.annotation.*
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity
import net.corda.core.utilities.loggerFor
import net.corda.did.flows.CreateDidFlow
import net.corda.did.state.DidStatus
import net.corda.did.utils.DIDAlreadyExist

val SERVICE_NAMES = listOf("Notary", "Network Map Service")

/**
 *  A Spring Boot Server API controller for interacting with the node via RPC.
 */
//@JsonAutoDetect(getterVisibility= JsonAutoDetect.Visibility.NONE)
@RestController
@RequestMapping("/")
class MainController(rpc: NodeRPCConnection) {

    companion object {
        private val logger = loggerFor<MainController>()
    }

    private val myLegalName = rpc.proxy.nodeInfo().legalIdentities.first().name
    private val proxy = rpc.proxy
    val queryUtils=QueryUtil(proxy)

    /**
     * Returns the node's name.
     */
    @GetMapping(value = [ "me" ], produces = [ APPLICATION_JSON_VALUE ])
    fun whoami() = mapOf("me" to myLegalName)

    /**
     * Returns all parties registered with the network map service. These names can be used to look up identities using
     * the identity service.
     */
    @GetMapping(value = [ "peers" ], produces = [ APPLICATION_JSON_VALUE ])
    fun getPeers(): Map<String, List<CordaX500Name>> {
        val nodeInfo = proxy.networkMapSnapshot()
        return mapOf("peers" to nodeInfo
                .map { it.legalIdentities.first().name }
                //filter out myself, notary and eventual network map started by driver
                .filter { it.organisation !in (SERVICE_NAMES + myLegalName.organisation) })
    }

    /**
     * Create DID
     */
    //@RequestParam("instruction") instruction: String,@RequestParam("document") document: String
    @PostMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE) ,consumes=arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun createDID(@PathVariable(value = "did") did: String,@RequestParam("instruction") instruction: String,@RequestParam("document") document: String ) : ResponseEntity<Any?> {
        try {

            val envelope = net.corda.did.DidEnvelope(instruction,document)
            val documentId = net.corda.did.CordaDid(did).uuid
            try{
                queryUtils.getDIDDocumentByLinearId(documentId.toString())
                return ResponseEntity(HttpStatus.CONFLICT)
            }
            catch(e:NullPointerException) {
                /**
                 * Validate  creation envelope
                 */
                try {
                    envelope.validateCreation()
                }
                catch(e:Exception){
                    return ResponseEntity.badRequest().body(e.message)
                }

                logger.info("document id=" + documentId)
                val originator = proxy.nodeInfo().legalIdentities.first()
                /* WIP :Need clarification from Moritz on how the witnesses can be fetched*/
                var w1 = proxy.wellKnownPartyFromX500Name(CordaX500Name.parse("O=PartyB,L=New York,C=US"))!!
                var w2 = proxy.wellKnownPartyFromX500Name(CordaX500Name.parse("O=PartyB,L=New York,C=US"))!!
                try {
                    val cordaDid = DidState(envelope, originator, setOf(w1, w2), DidStatus.VALID, UniqueIdentifier.fromString(documentId.toString()))
                    val flowHandler = proxy.startFlowDynamic(CreateDidFlow::class.java, cordaDid)
                    val result = flowHandler.use { it.returnValue.getOrThrow() }
                    return ResponseEntity.ok().body(result.toString())
                } catch (e: IllegalArgumentException) {
                    return ResponseEntity.badRequest().body(e.message)
                }
            }

        }
        catch(e:Exception){
            logger.error(e.message)
            return ResponseEntity.badRequest().body(e.message)

        }

    }
/*
* Fetch DID document
* */
    @GetMapping("{did}", produces = [APPLICATION_JSON_VALUE])
    fun fetchDIDDocument(@PathVariable(value = "did") did: String):ResponseEntity<Any?> {
        logger.info("Checking criteria against the Vault")
        try {
            val documentId = net.corda.did.CordaDid(did).uuid
            builder {
                val responseData = queryUtils.getDIDDocumentByLinearId(documentId.toString())
                return ResponseEntity.ok().body(responseData)
            }
        }
        catch (e:NullPointerException){
            logger.error(e.toString())
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Requested DID not found");

        }
        catch (e:Exception){
            logger.error(e.toString())
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("There was an error while fetching DID document");

        }


    }

}
