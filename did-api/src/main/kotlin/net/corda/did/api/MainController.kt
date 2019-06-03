/**
 * Persistent code
 *
 */

package net.corda.did.api


import com.fasterxml.jackson.databind.util.JSONPObject
import com.fasterxml.jackson.databind.util.JSONWrappedObject
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
import net.corda.did.flows.CreateDidFlow
import net.corda.did.state.DidStatus
import net.corda.did.DidEnvelopeFailure.ValidationFailure.*


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

    @PostMapping(value = "{did}",
            produces = arrayOf(MediaType.APPLICATION_JSON_VALUE) ,consumes=arrayOf(MediaType.MULTIPART_FORM_DATA_VALUE))
    fun createDID(@PathVariable(value = "did") did: String,@RequestParam("instruction") instruction: String,@RequestParam("document") document: String ) : ResponseEntity<Any?> {
        try {
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
                if(it.reason is InvalidSignatureFailure){
                    logger.info("Invalid signature error")
                    return ResponseEntity.badRequest().body(ApiResponse("Signature provided is invalid").toResponseObj())

                }
                else if(it.reason is MalformedInstructionFailure){
                    logger.info("Malformed instruction error")
                    return ResponseEntity.badRequest().body(ApiResponse("Instruction provided is Malformed").toResponseObj())
                }
                else if(it.reason is MalformedDocumentFailure){
                    logger.info("Malformed document error")
                    return ResponseEntity.badRequest().body(ApiResponse("Document provided is Malformed").toResponseObj())
                }
                else if(it.reason is MalformedPrecursorFailure){
                    logger.info("The precursor DID is invalid")
                    return ResponseEntity.badRequest().body(ApiResponse("The precursor DID is invalid").toResponseObj())
                }
                else if(it.reason is NoKeysFailure){
                    logger.info("The DID does not contain any public keys")
                    return ResponseEntity.badRequest().body(ApiResponse("The DID does not contain any public keys").toResponseObj())
                }
                else if(it.reason is SignatureTargetFailure){
                    logger.info("Multiple Signatures target the same key")
                    return ResponseEntity.badRequest().body(ApiResponse("Multiple Signatures target the same key").toResponseObj())
                }
                else if(it.reason is DuplicatePublicKeyIdFailure){
                    logger.info("Multiple public keys have the same ID")
                    return ResponseEntity.badRequest().body(ApiResponse("Multiple public keys have the same ID").toResponseObj())
                }
                else if(it.reason is SignatureCountFailure){
                    logger.info("The number of keys in the DID document does not match the number of signatures")
                    return ResponseEntity.badRequest().body(ApiResponse("The number of keys in the DID document does not match the number of signatures").toResponseObj())
                }
                else if(it.reason is UnsupportedCryptoSuiteFailure){
                    logger.info("unsupported cryptographic suite")
                    return ResponseEntity.badRequest().body(ApiResponse("unsupported cryptographic suite").toResponseObj())
                }
                else if(it.reason is UntargetedPublicKeyFailure){
                    logger.info("No signature was provided for target")
                    return ResponseEntity.badRequest().body(ApiResponse("No signature was provided for target").toResponseObj())
                }
                else if(it.reason is CryptoSuiteMismatchFailure){
                    logger.info("Cryptosuite mismatch")
                    return ResponseEntity.badRequest().body(ApiResponse("Signing key suite and signature are different").toResponseObj())
                }
                else if(it.reason is NoMatchingSignatureFailure){
                    logger.info("No signature is provided for any of the keys.")
                    return ResponseEntity.badRequest().body(ApiResponse("No signature is provided for any of the keys.").toResponseObj())
                }
                else if(it.reason is MissingSignatureFailure){
                    logger.info("Signature is missing")
                    return ResponseEntity.badRequest().body(ApiResponse("Signature is missing for a target").toResponseObj())
                }
                else if(it.reason is MissingTemporalInformationFailure){
                    logger.info("The document is missing information about its creation")
                    return ResponseEntity.badRequest().body(ApiResponse("The document is missing information about its creation").toResponseObj())
                }
                else if(it.reason is InvalidTemporalRelationFailure){
                    logger.info("Documents temporal relation is incorrect")
                    return ResponseEntity.badRequest().body(ApiResponse("Documents temporal relation is incorrect").toResponseObj())
                }
                else if(it.reason is InvalidPublicKeyId){
                    logger.info("PublicKey ID must contain did as prefix for target ")
                    return ResponseEntity.badRequest().body(ApiResponse("PublicKey ID must contain did as prefix for target ").toResponseObj())
                }
                else{
                    return ResponseEntity.badRequest().body(ApiResponse(it.reason.toString()).toResponseObj())
                }

                 }
            logger.info("document id" + documentId)
            val originator = proxy.nodeInfo().legalIdentities.first()
            /* WIP :Need clarification from Moritz on how the witnesses can be fetched*/
            var w1 = proxy.wellKnownPartyFromX500Name(CordaX500Name.parse("O=PartyB,L=New York,C=US"))!!
            var w2 = proxy.wellKnownPartyFromX500Name(CordaX500Name.parse("O=PartyB,L=New York,C=US"))!!
            try {
                val cordaDid = DidState(envelope, originator, setOf(w1, w2), DidStatus.VALID, UniqueIdentifier.fromString(documentId.toString()))
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
                if(queriedData.isEmpty()){
                    val response=ApiResponse("Requested DID not found")
                    return ResponseEntity(response.toResponseObj(),HttpStatus.NOT_FOUND)

                }
                return ResponseEntity.ok().body(queriedData)
            }
        }
        catch (e:Exception){
            logger.error(e.toString())
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiResponse("There was an error while fetching DID document").toResponseObj())

        }


    }

}
