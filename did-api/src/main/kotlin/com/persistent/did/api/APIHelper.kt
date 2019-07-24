package com.persistent.did.api

import com.natpryce.onFailure
import com.persistent.did.api.APIMessage.CRYPTO_SUITE_MISMATCH
import com.persistent.did.api.APIMessage.DID_EMPTY
import com.persistent.did.api.APIMessage.DOCUMENT_EMPTY
import com.persistent.did.api.APIMessage.INCORRECT_ACTION
import com.persistent.did.api.APIMessage.INSTRUCTION_EMPTY
import com.persistent.did.api.APIMessage.INVALID_PUBLIC_KEY
import com.persistent.did.api.APIMessage.INVALID_SIGNATURE
import com.persistent.did.api.APIMessage.INVALID_TEMPORAL_INFORMATION
import com.persistent.did.api.APIMessage.MALFORMED_DOCUMENT
import com.persistent.did.api.APIMessage.MALFORMED_INSTRUCTION
import com.persistent.did.api.APIMessage.MISMATCH_DID
import com.persistent.did.api.APIMessage.MISMATCH_SIGNATURE_TO_KEY_COUNT
import com.persistent.did.api.APIMessage.MISSING_SIGNATURE
import com.persistent.did.api.APIMessage.MISSING_TEMPORAL_INFORMATION
import com.persistent.did.api.APIMessage.MULTIPLE_PUBLIC_KEY
import com.persistent.did.api.APIMessage.MULTIPLE_SIGNATURES
import com.persistent.did.api.APIMessage.NO_MATCHING_SIGNATURE
import com.persistent.did.api.APIMessage.NO_PUBLIC_KEYS
import com.persistent.did.api.APIMessage.NO_SIGNATURE
import com.persistent.did.api.APIMessage.PRECURSOR_DID
import com.persistent.did.api.APIMessage.UNSUPPORTED_CRYPTO_SUITE
import com.persistent.did.api.MainController.Companion.logger
import net.corda.did.DidEnvelope
import net.corda.did.DidEnvelopeFailure.ValidationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.CryptoSuiteMismatchFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.DuplicatePublicKeyIdFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidPublicKeyId
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidTemporalRelationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedDocumentFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedInstructionFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedPrecursorFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingTemporalInformationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoKeysFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoMatchingSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureCountFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureTargetFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.UnsupportedCryptoSuiteFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.UntargetedPublicKeyFailure
import org.springframework.http.ResponseEntity

/**
 * Helper functions for handling API errors and responses
 * */
class APIUtils {
	/**
	 * @param[reason] The reason for why the interaction with the DID API failed
	 * @return A response with appropriate status code and human-readable error message
	 */
	fun sendErrorResponse(reason: ValidationFailure): ResponseEntity<Any?> = when (reason) {
		is InvalidSignatureFailure           -> badRequest(INVALID_SIGNATURE)
		is MalformedInstructionFailure       -> badRequest(MALFORMED_INSTRUCTION)
		is MalformedDocumentFailure          -> badRequest(MALFORMED_DOCUMENT)
		is MalformedPrecursorFailure         -> badRequest(PRECURSOR_DID)
		is NoKeysFailure                     -> badRequest(NO_PUBLIC_KEYS)
		is SignatureTargetFailure            -> badRequest(MULTIPLE_SIGNATURES)
		is DuplicatePublicKeyIdFailure       -> badRequest(MULTIPLE_PUBLIC_KEY)
		is SignatureCountFailure             -> badRequest(MISMATCH_SIGNATURE_TO_KEY_COUNT)
		is UnsupportedCryptoSuiteFailure     -> badRequest(UNSUPPORTED_CRYPTO_SUITE)
		is UntargetedPublicKeyFailure        -> badRequest(NO_SIGNATURE)
		is CryptoSuiteMismatchFailure        -> badRequest(CRYPTO_SUITE_MISMATCH)
		is NoMatchingSignatureFailure        -> badRequest(NO_MATCHING_SIGNATURE)
		is MissingSignatureFailure           -> badRequest(MISSING_SIGNATURE)
		is MissingTemporalInformationFailure -> badRequest(MISSING_TEMPORAL_INFORMATION)
		is InvalidTemporalRelationFailure    -> badRequest(INVALID_TEMPORAL_INFORMATION)
		is InvalidPublicKeyId                -> badRequest(INVALID_PUBLIC_KEY)
		else                                 -> badRequest(ApiResponse(reason.toString()).toResponseObj())
	}

	private fun badRequest(message: APIMessage): ResponseEntity<Any?> {
		logger.info(message.toString())
		return badRequest(ApiResponse(message).toResponseObj())
	}

	private fun badRequest(response: ApiResponse): ResponseEntity<Any?> = ResponseEntity.badRequest().body(response)

	/**
	 * @param[instruction] The instruction payload containing signature,action passed as a string
	 * @param[document] The raw document containing encoded public key ,information about type of key,as well as information about the controller of did
	 * @param[did] The decentralized identifier passed as a string
	 *
	 * The function performs validations on instruction,document and did passed
	 *
	 * @return  The DidEnvelope class object
	 * */
	fun generateEnvelope(instruction: String, document: String, did: String, action: String): DidEnvelope {

		if (instruction.isEmpty()) {
			logger.info("instruction is empty")
			throw IllegalArgumentException(INSTRUCTION_EMPTY.message)
		}

		if (document.isEmpty()) {
			logger.info("document is empty")
			throw IllegalArgumentException(DOCUMENT_EMPTY.message)
		}

		if (did.isEmpty()) {
			logger.info("did is empty")
			throw IllegalArgumentException(DID_EMPTY.message)
		}

		val envelope = DidEnvelope(instruction, document)
		if (envelope.instruction.json["action"] != action) {
			throw IllegalArgumentException(ApiResponse(INCORRECT_ACTION).message)

		}
		val envelopeDid = envelope.document.id().onFailure { throw IllegalArgumentException(DID_EMPTY.message) }

		if (envelopeDid.toExternalForm() != did) {
			logger.info("Mismatch occurred in DID in parameter and DID in document ")
			throw IllegalArgumentException(ApiResponse(MISMATCH_DID).message)
		}
		return envelope
	}
}