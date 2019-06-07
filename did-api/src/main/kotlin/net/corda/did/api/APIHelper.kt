package net.corda.did.api

import net.corda.did.DidEnvelopeFailure
import org.springframework.http.ResponseEntity
/**
 * Persistent code
 *
 */

class APIUtils {
    fun sendErrorResponse(reason: DidEnvelopeFailure.ValidationFailure): ResponseEntity<Any?> {
        when( reason ){
            is DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure ->  {
                MainController.logger.info("Signature provided is invalid")
                return ResponseEntity.badRequest().body(ApiResponse("Signature provided is invalid").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.MalformedInstructionFailure ->  {
                MainController.logger.info("Instruction provided is Malformed")
                return ResponseEntity.badRequest().body(ApiResponse("Instruction provided is Malformed").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.MalformedDocumentFailure -> {
                MainController.logger.info("Document provided is Malformed")
                return ResponseEntity.badRequest().body(ApiResponse("Document provided is Malformed").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.MalformedPrecursorFailure ->{
                MainController.logger.info("The precursor DID is invalid")
                return ResponseEntity.badRequest().body(ApiResponse("The precursor DID is invalid").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.NoKeysFailure -> {
                MainController.logger.info("The DID does not contain any public keys")
                return ResponseEntity.badRequest().body(ApiResponse("The DID does not contain any public keys").toResponseObj())

            }
            is DidEnvelopeFailure.ValidationFailure.SignatureTargetFailure -> {
                MainController.logger.info("Multiple Signatures target the same key")
                return ResponseEntity.badRequest().body(ApiResponse("Multiple Signatures target the same key").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.DuplicatePublicKeyIdFailure -> {
                MainController.logger.info("Multiple public keys have the same ID")
                return ResponseEntity.badRequest().body(ApiResponse("Multiple public keys have the same ID").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.SignatureCountFailure -> {
                MainController.logger.info("The number of keys in the DID document does not match the number of signatures")
                return ResponseEntity.badRequest().body(ApiResponse("The number of keys in the DID document does not match the number of signatures").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.UnsupportedCryptoSuiteFailure -> {
                MainController.logger.info("unsupported cryptographic suite")
                return ResponseEntity.badRequest().body(ApiResponse("unsupported cryptographic suite").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.UntargetedPublicKeyFailure -> {
                MainController.logger.info("No signature was provided for target")
                return ResponseEntity.badRequest().body(ApiResponse("No signature was provided for target").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.CryptoSuiteMismatchFailure -> {
                MainController.logger.info("Cryptosuite mismatch")
                return ResponseEntity.badRequest().body(ApiResponse("Signing key suite and signature are different").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.NoMatchingSignatureFailure -> {
                MainController.logger.info("No signature is provided for any of the keys.")
                return ResponseEntity.badRequest().body(ApiResponse("No signature is provided for any of the keys.").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.MissingSignatureFailure -> {
                MainController.logger.info("Signature is missing")
                return ResponseEntity.badRequest().body(ApiResponse("Signature is missing for a target").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.MissingTemporalInformationFailure -> {
                MainController.logger.info("The document is missing information about its creation")
                return ResponseEntity.badRequest().body(ApiResponse("The document is missing information about its creation").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.InvalidTemporalRelationFailure -> {
                MainController.logger.info("Documents temporal relation is incorrect")
                return ResponseEntity.badRequest().body(ApiResponse("Documents temporal relation is incorrect").toResponseObj())
            }
            is DidEnvelopeFailure.ValidationFailure.InvalidPublicKeyId -> {
                MainController.logger.info("PublicKey ID must contain did as prefix for target ")
                return ResponseEntity.badRequest().body(ApiResponse("PublicKey ID must contain did as prefix for target ").toResponseObj())
            }
            else ->{
                return ResponseEntity.badRequest().body(ApiResponse(reason.toString()).toResponseObj())
            }


        }

    }


}