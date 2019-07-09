package net.corda.did.api

import com.natpryce.onFailure
import net.corda.did.DidEnvelope
import net.corda.did.DidEnvelopeFailure
import org.springframework.http.ResponseEntity
/**
 * Persistent code
 *
 */
/**
 * Helper functions for handling API exceptions and responses
 *
 * */
class APIUtils {
    /**
     * @param[reason] Takes exception as input
     * @return The appropriate status code and message
     * */
    fun sendErrorResponse( reason : DidEnvelopeFailure.ValidationFailure ): ResponseEntity<Any?> {
        when( reason ){
            is DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure ->  {
                MainController.logger.info("Signature provided is invalid")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.INVALID_SIGNATURE ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.MalformedInstructionFailure ->  {
                MainController.logger.info("Instruction provided is Malformed")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MALFORMED_INSTRUCTION ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.MalformedDocumentFailure -> {
                MainController.logger.info("Document provided is Malformed")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MALFORMED_DOCUMENT ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.MalformedPrecursorFailure ->{
                MainController.logger.info("The precursor DID is invalid")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.PRECURSOR_DID ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.NoKeysFailure -> {
                MainController.logger.info("The DID does not contain any public keys")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.NO_PUBLIC_KEYS ).toResponseObj() )

            }
            is DidEnvelopeFailure.ValidationFailure.SignatureTargetFailure -> {
                MainController.logger.info("Multiple Signatures target the same key")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MULTIPLE_SIGNATURES ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.DuplicatePublicKeyIdFailure -> {
                MainController.logger.info("Multiple public keys have the same ID")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MULTIPLE_PUBLIC_KEY ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.SignatureCountFailure -> {
                MainController.logger.info("The number of keys in the DID document does not match the number of signatures")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MISMATCH_SIGNATURE_TO_KEY_COUNT ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.UnsupportedCryptoSuiteFailure -> {
                MainController.logger.info("unsupported cryptographic suite")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.UNSUPPORTED_CRYPTO_SUITE ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.UntargetedPublicKeyFailure -> {
                MainController.logger.info("No signature was provided for target")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.NO_SIGNATURE ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.CryptoSuiteMismatchFailure -> {
                MainController.logger.info("Cryptosuite mismatch")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.CRYPTOSUITE_MISMATCH ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.NoMatchingSignatureFailure -> {
                MainController.logger.info("No signature is provided for any of the keys.")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.NO_MATCHING_SIGNATURE ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.MissingSignatureFailure -> {
                MainController.logger.info("Signature is missing")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MISSING_SIGNATURE ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.MissingTemporalInformationFailure -> {
                MainController.logger.info("The document is missing information about its creation")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.MISSING_TEMPORAL_INFORMATION ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.InvalidTemporalRelationFailure -> {
                MainController.logger.info("Documents temporal relation is incorrect")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.INVALID_TEMPORAL_INFORMATION ).toResponseObj() )
            }
            is DidEnvelopeFailure.ValidationFailure.InvalidPublicKeyId -> {
                MainController.logger.info("PublicKey ID must contain did as prefix for target ")
                return ResponseEntity.badRequest().body( ApiResponse( APIMessage.INVALID_PUBLIC_KEY ).toResponseObj() )
            }
            else ->{
                return ResponseEntity.badRequest().body( ApiResponse(reason.toString()).toResponseObj() )
            }
        }
    }
    /**
     * @param[instruction] The instruction payload containing signature,action passed as a string
     * @param[document] The raw document containing encoded public key ,information about type of key,as well as information about the controller of did
     * @param[did] The decentralized identifier passed as a string
     *
     * The function performs validations on instruction,document and did passed
     *
     * @return  The DidEnvelope class object
     * */
    fun generateEnvelope(instruction: String ,document: String ,did: String): DidEnvelope {

        if ( instruction.isEmpty() ){
            MainController.logger.info( "instruction is empty" )
            throw IllegalArgumentException(APIMessage.INSTRUCTION_EMPTY.message)

        }
        if ( document.isEmpty() ){
            MainController.logger.info( "document is empty" )
            throw IllegalArgumentException(APIMessage.DOCUMENT_EMPTY.message)

        }
        if( did.isEmpty() ){
            MainController.logger.info( "did is empty" )
            throw IllegalArgumentException(APIMessage.DID_EMPTY.message)

        }
        val envelope = net.corda.did.DidEnvelope(instruction, document)
        val envelopeDid = envelope.document.id().onFailure { throw IllegalArgumentException(APIMessage.DID_EMPTY.message) }

        if ( envelopeDid.toExternalForm()!=did){
            MainController.logger.info("Mismatch occurred in DID in parameter and DID in document ")
            throw IllegalArgumentException(ApiResponse( APIMessage.MISMATCH_DID ).message)
        }
        return envelope
    }
}