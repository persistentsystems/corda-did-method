/**
 * Persistent code
 *
 */

package net.corda.did.api



import com.natpryce.onFailure
import net.corda.core.messaging.startFlow
import net.corda.core.node.services.vault.builder
import net.corda.core.utilities.getOrThrow
import org.springframework.http.MediaType
import org.springframework.http.MediaType.*
import org.springframework.web.bind.annotation.*
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity
import net.corda.core.utilities.loggerFor
import net.corda.did.flows.CreateDidFlow
import net.corda.did.flows.DeleteDidFlow
import net.corda.did.flows.UpdateDidFlow
import net.corda.did.utils.DIDAlreadyExistException
import net.corda.did.utils.DIDNotFoundException
import org.springframework.web.context.request.async.DeferredResult
import java.util.concurrent.Executors

/**
 *  A Spring Boot Server API controller for interacting with the node via RPC.
 */

@RestController
@RequestMapping("/")
// ??? moritzplatt 2019-06-20 -- consider passing connection parameters instead so the controller can manage the connection
// itself. i.e. re-establishing connection in case it fails or adding functionality to re-establish a connection in case of errors

// pranav 2019-06-25 added RPC reconnection library to reconnect if node connection is lost,docs@ https://docs.corda.net/clientrpc.html#reconnecting-rpc-clients
class MainController(rpc: NodeRPCConnection) {

    companion object {
         val logger = loggerFor<MainController>()

    }
    private val proxy = rpc.proxy
    private val queryUtils = QueryUtil(proxy)
    private val apiUtils = APIUtils()

    private val executorService = Executors.newSingleThreadExecutor()
    /**
     * Create DID
     */
    @PutMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE), consumes = arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun createDID( @PathVariable(value = "did") did: String, @RequestPart("instruction") instruction: String, @RequestPart("document") document: String ) : DeferredResult<ResponseEntity<Any?>> {
        val apiResult = DeferredResult<ResponseEntity<Any?>>()
        try {

            logger.info( "inside create function" )
            val envelope = apiUtils.generateEnvelope(instruction,document,did)
            net.corda.did.CordaDid.parseExternalForm(did)

            // ??? moritzplatt 2019-06-20 -- suggestion here would be to remove this block and instead of querying, rely on the output of the startFlowDynamic call only
            // the current implementation introduces a race condition between the `getDIDDocumentByLinearId` call and the
            // consumption of the `returnValue`

            /**
            * Validate envelope
            */
            val envelopeVerified = envelope.validateCreation()
            envelopeVerified.onFailure { apiResult.setErrorResult( apiUtils.sendErrorResponse( it.reason ));return apiResult}
            logger.info("document verified")
            // ??? moritzplatt 2019-06-20 -- as described in comments on the flow logic, this should not be passed from the API


            /* WIP :Need clarification from Moritz on how the witnesses can be fetched*/

            // ??? moritzplatt 2019-06-20 -- the API should not be aware of the witnesses. The CorDapp should be aware
            // of the set of witnesses by configuration. Considering all network members witnesses is incorrect.

                // ??? moritzplatt 2019-06-20 -- consider comments on the flow constructor
                  //pranav: 2019-06-27 As per Moritz comments we are now just passing envelope to flow
                val flowHandler = proxy.startFlowDynamic(CreateDidFlow::class.java, envelope)
                logger.info("initializing flow handler")
                // ??? moritzplatt 2019-06-20 -- not familiar with Spring but `getOrThrow` is blocking.
                // Maybe there is a pattern around futures (i.e. https://www.baeldung.com/spring-async)?
                // Just a thought though
               // pranav: 2019-06-27 added logic to for asynchronous execution of blocking code
                executorService.submit {
                    try {

                        val result = flowHandler.use { it.returnValue.getOrThrow() }
                        apiResult.setResult(ResponseEntity.ok().body(ApiResponse(result.toString()).toResponseObj()))
                    }
                    catch(e: IllegalArgumentException ){
                        apiResult.setErrorResult(ResponseEntity.badRequest().body( ApiResponse(e.message).toResponseObj() ))

                    }
                    catch( e : DIDDeletedException ){
                        apiResult.setErrorResult(ResponseEntity ( ApiResponse( APIMessage.DID_DELETED ).toResponseObj(), HttpStatus.CONFLICT))
                    }
                    catch( e: DIDAlreadyExistException ){
                        apiResult.setErrorResult(ResponseEntity ( ApiResponse( APIMessage.CONFLICT ).toResponseObj(), HttpStatus.CONFLICT ))

                    }

                }

                return apiResult


        }
        catch( e : Exception ){
            logger.error( e.message )
            apiResult.setErrorResult(ResponseEntity.badRequest().body( ApiResponse(e.message).toResponseObj() ))
            return apiResult
        }


    }
/*
* Fetch DID document
* */
    @GetMapping("{did}", produces = [APPLICATION_JSON_VALUE])
    fun fetchDIDDocument( @PathVariable(value = "did") did: String ):ResponseEntity<Any?> {

        try {
            val uuid = net.corda.did.CordaDid.parseExternalForm(did).onFailure {   logger.info("inside exception");return ResponseEntity.status( HttpStatus.BAD_REQUEST ).body( ApiResponse( APIMessage.INCORRECT_FORMAT ).toResponseObj() )}

            builder {
                val didJson = queryUtils.getDIDDocumentByLinearId(uuid.uuid.toString())
                if( didJson.isEmpty() ){
                    val response = ApiResponse( APIMessage.NOT_FOUND )
                    return ResponseEntity( response.toResponseObj(), HttpStatus.NOT_FOUND )

                }
                // ??? moritzplatt 2019-06-20 -- do not return the re-serialised version based on JsonObject. Signatures may not match
                // pranav 2019-06-25 updated code to return raw document as a string
                return ResponseEntity.ok().body(didJson)
            }
        }
        catch ( e : IllegalArgumentException ){
            logger.error( e.toString())
            return ResponseEntity.status( HttpStatus.BAD_REQUEST ).body( ApiResponse( APIMessage.INCORRECT_FORMAT ).toResponseObj() )

        }
        catch ( e : IllegalStateException ){
            logger.error( e.toString())
            return ResponseEntity.status( HttpStatus.BAD_REQUEST ).body( ApiResponse( APIMessage.INCORRECT_FORMAT ).toResponseObj() )

        }
        catch( e : DIDDeletedException ){
             return ResponseEntity ( ApiResponse( APIMessage.DID_DELETED ).toResponseObj(), HttpStatus.NOT_FOUND )

        }
        catch ( e : Exception ){
            logger.error( e.toString() )
            return ResponseEntity.status( HttpStatus.INTERNAL_SERVER_ERROR ).body( ApiResponse( e.message ).toResponseObj() )
        }
    }

    @PostMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE), consumes=arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun updateDID( @PathVariable(value = "did") did: String, @RequestParam("instruction") instruction: String, @RequestParam("document") document: String ) : DeferredResult<ResponseEntity<Any?>> {
        val apiResult = DeferredResult<ResponseEntity<Any?>>()
        try {
            val envelope = apiUtils.generateEnvelope(instruction,document,did)
            val uuid = net.corda.did.CordaDid.parseExternalForm(did).onFailure {    apiResult.setErrorResult(ResponseEntity.status( HttpStatus.BAD_REQUEST ).body( ApiResponse( APIMessage.INCORRECT_FORMAT ).toResponseObj() ));return apiResult}

            // ??? moritzplatt 2019-06-20 -- merge with assignment var didJson = try { ... }
            try {
                val didJson = queryUtils.getCompleteDIDDocumentByLinearId(uuid.uuid.toString())
                val envelopeVerified = envelope.validateModification( didJson )
                envelopeVerified.onFailure { apiResult.setErrorResult( apiUtils.sendErrorResponse( it.reason ));return apiResult }
            }
            catch( e : NullPointerException ){

                apiResult.setErrorResult(ResponseEntity ( ApiResponse( APIMessage.NOT_FOUND ).toResponseObj(), HttpStatus.NOT_FOUND ))
                return apiResult
            }
            catch( e : DIDDeletedException ){
                apiResult.setErrorResult( ResponseEntity ( ApiResponse( APIMessage.DID_DELETED ).toResponseObj(), HttpStatus.NOT_FOUND ))
                return apiResult
            }

            /**
             * Validate envelope
             */

            val flowHandler = proxy.startFlowDynamic(UpdateDidFlow::class.java, envelope)
            //start
            executorService.submit {
                try {
                    val result = flowHandler.use { it.returnValue.getOrThrow() }
                    apiResult.setResult(ResponseEntity.ok().body( ApiResponse(result.toString()).toResponseObj() ))
                }
                catch(e: IllegalArgumentException ){

                    apiResult.setErrorResult( ResponseEntity.badRequest().body( ApiResponse(e.message).toResponseObj() ))

                }
                catch( e : DIDDeletedException ){

                    apiResult.setErrorResult(ResponseEntity ( ApiResponse( APIMessage.DID_DELETED ).toResponseObj(), HttpStatus.CONFLICT))
                }

            }
            //end


            return apiResult

        }
        catch( e : Exception ){
            logger.error( e.message )
            apiResult.setErrorResult(ResponseEntity.badRequest().body( ApiResponse( e.message ).toResponseObj() ))
            return apiResult
        }
    }


    // ??? moritzplatt 2019-06-20 -- does a `DELETE` require a document at all? it could be an instruction set only?
    //pranav 2019-06-27 - updated the code to accept only instruction
    @DeleteMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE), consumes=arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun deleteDID( @PathVariable(value = "did") did: String, @RequestPart("instruction") instruction: String ) : DeferredResult<ResponseEntity<Any?>> {
        val apiResult = DeferredResult<ResponseEntity<Any?>>()
        try {

            val flowHandler = proxy.startFlow(::DeleteDidFlow, instruction, did)

            executorService.submit {
                try {
                    val result = flowHandler.use { it.returnValue.getOrThrow() }

                    apiResult.setResult(ResponseEntity.ok().body( ApiResponse(result.toString()).toResponseObj() ))
                }
                catch(e: IllegalArgumentException ){

                    apiResult.setErrorResult( ResponseEntity.badRequest().body( ApiResponse(e.message).toResponseObj() ))

                }
                catch( e : DIDNotFoundException ){

                    apiResult.setErrorResult(ResponseEntity ( ApiResponse( APIMessage.DID_DELETED ).toResponseObj(), HttpStatus.CONFLICT))
                }

            }

            return apiResult

        }
        catch( e : Exception ){
            logger.error( e.message )
            apiResult.setErrorResult( ResponseEntity.badRequest().body( ApiResponse( e.message ).toResponseObj() ))
            return apiResult
        }
    }
}
