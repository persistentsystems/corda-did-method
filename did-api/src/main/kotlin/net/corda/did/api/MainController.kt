/**
 * Persistent code
 *
 */

package net.corda.did.api



import com.natpryce.onFailure
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.CordaX500Name
import net.corda.core.node.services.vault.builder
import net.corda.core.utilities.getOrThrow
import net.corda.did.state.DidState
import org.springframework.http.MediaType
import org.springframework.http.MediaType.*
import org.springframework.web.bind.annotation.*
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity
import net.corda.core.utilities.loggerFor
import net.corda.did.DidDocument
import net.corda.did.flows.CreateDidFlow
import net.corda.did.state.DidStatus
import net.corda.did.flows.UpdateDidFlow


val SERVICE_NAMES = listOf("Notary", "Network Map Service")

/**
 *  A Spring Boot Server API controller for interacting with the node via RPC.
 */
//@JsonAutoDetect(getterVisibility= JsonAutoDetect.Visibility.NONE)
@RestController
@RequestMapping("/")
class MainController(rpc: NodeRPCConnection) {

    companion object {
         val logger = loggerFor<MainController>()
    }

    private val myLegalName = rpc.proxy.nodeInfo().legalIdentities.first().name
    private val proxy = rpc.proxy
    val queryUtils=QueryUtil(proxy)
    val apiUtils=APIUtils()

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

    @PutMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE) ,consumes=arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun createDID(@PathVariable(value = "did") did: String,@RequestParam("instruction") instruction: String,@RequestParam("document") document: String ) : ResponseEntity<Any?> {
        try {
            logger.info("inside create function")
            if ( instruction.isEmpty() ){
                logger.error("instruction is empty")
                return ResponseEntity ( ApiResponse("Instruction is empty").toResponseObj(),HttpStatus.BAD_REQUEST )

            }
            if ( document.isEmpty() ){
                logger.error("document is empty")
                return ResponseEntity ( ApiResponse("Document is empty").toResponseObj(),HttpStatus.BAD_REQUEST )

            }
            if( did.isEmpty() ){
                logger.error("did is empty")
                return ResponseEntity ( ApiResponse("DID is empty").toResponseObj(),HttpStatus.BAD_REQUEST )

            }
            val envelope = net.corda.did.DidEnvelope(instruction,document)
            val documentId = net.corda.did.CordaDid(did).uuid

            val queriedDid=queryUtils.getDIDDocumentByLinearId(documentId.toString())
            if( !queriedDid.isEmpty() ){
                return ResponseEntity ( ApiResponse("DID already exists").toResponseObj(),HttpStatus.CONFLICT )
            }
            /**
            * Validate envelope
            */
            val envelopeVerifed=envelope.validateCreation()
            envelopeVerifed.onFailure {
                return apiUtils.sendErrorResponse( it.reason )
                 }
            logger.info("document id" + documentId)
            val originator = proxy.nodeInfo().legalIdentities.first()
            /* WIP :Need clarification from Moritz on how the witnesses can be fetched*/
            val listOfWitnesses=proxy.networkMapSnapshot().flatMap { it.legalIdentities }.toSet()
            try {
                val cordaDid = DidState(envelope, originator, listOfWitnesses.minus(proxy.nodeInfo().legalIdentities.toSet()), DidStatus.VALID, UniqueIdentifier.fromString(documentId.toString()))
                val flowHandler = proxy.startFlowDynamic(CreateDidFlow::class.java, cordaDid)
                val result = flowHandler.use { it.returnValue.getOrThrow() }
                return ResponseEntity.ok().body(ApiResponse(result.toString()).toResponseObj())
            } catch (e: IllegalArgumentException) {
                return ResponseEntity.badRequest().body(ApiResponse(e.message).toResponseObj())
            }


        }
        catch(e:Exception){
            logger.error(e.message)
            return ResponseEntity.badRequest().body(ApiResponse(e.message).toResponseObj())

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
                val queriedData = queryUtils.getDIDDocumentByLinearId(documentId.toString())
                if( queriedData.isEmpty() ){
                    val response=ApiResponse("Requested DID not found")
                    return ResponseEntity(response.toResponseObj(),HttpStatus.NOT_FOUND)

                }
                return ResponseEntity.ok().body(queriedData)
            }
        }
        catch (e:IllegalArgumentException){
            logger.error(e.toString())
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse("The DID requested is not in the correct format").toResponseObj())

        }
        catch (e:Exception){
            logger.error(e.toString())
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResponse("There was an error while fetching DID document").toResponseObj())

        }


    }

    @PostMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE) ,consumes=arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun updateDID(@PathVariable(value = "did") did: String,@RequestParam("instruction") instruction: String,@RequestParam("document") document: String ) : ResponseEntity<Any?> {
        try {
            logger.info("inside the update DID function")
            if ( instruction.isEmpty() ){
                logger.error("instruction is empty")
                return ResponseEntity ( ApiResponse("Instruction is empty").toResponseObj(),HttpStatus.BAD_REQUEST )

            }
            if ( document.isEmpty() ){
                logger.error("document is empty")
                return ResponseEntity ( ApiResponse("Document is empty").toResponseObj(),HttpStatus.BAD_REQUEST )

            }
            if( did.isEmpty() ){
                logger.error("did is empty")
                return ResponseEntity ( ApiResponse("DID is empty").toResponseObj(),HttpStatus.BAD_REQUEST )

            }
            val envelope = net.corda.did.DidEnvelope(instruction,document)
            val documentId = net.corda.did.CordaDid(did).uuid
            var queriedDid:DidDocument

            try {
                 queriedDid = queryUtils.getCompleteDIDDocumentByLinearId(documentId.toString())
            }
            catch( e:NullPointerException ){
                return ResponseEntity ( ApiResponse(" Provided DID does not exist").toResponseObj(),HttpStatus.NOT_FOUND )
            }

            /**
             * Validate envelope
             */


            val envelopeVerifed = envelope.validateModification(queriedDid)
            envelopeVerifed.onFailure {
                return apiUtils.sendErrorResponse(it.reason)
            }
            logger.info("document id" + documentId)
            val originator = proxy.nodeInfo().legalIdentities.first()
            /* WIP :Need clarification from Moritz on how the witnesses can be fetched*/
            val listOfWitnesses=proxy.networkMapSnapshot().flatMap { it.legalIdentities }.toSet()
            try {
                logger.info("creating the corda state object")
                val cordaDid = DidState(envelope, originator, listOfWitnesses.minus(proxy.nodeInfo().legalIdentities.toSet()), DidStatus.VALID, UniqueIdentifier.fromString(documentId.toString()))
                logger.info("invoking the flow")
                val flowHandler = proxy.startFlowDynamic(UpdateDidFlow::class.java, cordaDid)
                logger.info("get result from the flow")
                val result = flowHandler.use { it.returnValue.getOrThrow() }
                logger.info("flow successful")
                return ResponseEntity.ok().body(ApiResponse(result.toString()).toResponseObj())
            } catch ( e: IllegalArgumentException ) {
                return ResponseEntity.badRequest().body(ApiResponse(e.message).toResponseObj())
            }


        }
        catch( e:Exception ){
            logger.error(e.message)
            return ResponseEntity.badRequest().body(ApiResponse(e.message).toResponseObj())

        }

    }

}
