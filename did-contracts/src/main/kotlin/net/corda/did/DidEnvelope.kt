package net.corda.did

import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.mapFailure
import com.natpryce.onFailure
import net.corda.FailureCode
import net.corda.did.Action.Create
import net.corda.did.Action.Update
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.CryptoSuite.EdDsaSASecp256k1
import net.corda.did.CryptoSuite.RSA
import net.corda.did.DidEnvelopeFailure.ValidationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.CryptoSuiteMismatchFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.DuplicatePublicKeyIdFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.InvalidTemporalRelationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedDocumentFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedInstructionFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingTemporalInformationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoKeysFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureCountFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.SignatureTargetFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.UnsupportedCryptoSuiteFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.UntargetedPublicKeyFailure
import net.corda.isValidEd25519Signature
import net.corda.toEd25519PublicKey
import java.net.URI

/**
 * This document encapsulates a DID, preserving the full JSON document as received by the owner, the action to be
 * executed on this document and signatures over the document using all key pairs covered in the DID.
 * While it would be beneficial to have a strongly typed `DidEnvelope` class in which the aspects of a DID are stored as
 * individual fields, the lack of a canonical JSON representation on which hashes are generated makes this problematic.
 *
 * Instead, this class provides convenience methods, that extract information from the JSON document on request. Note
 * that the document tree these operations work on will not be stored in a field to keep serialisation size small. This
 * means that usage of the convenience methods has a high computational overhead.
 *
 * @param instruction The instruction string, outlining which action should be performed with the DID document provided
 * along with cryptographic proof of ownership of the DID document in form of a signature.
 * @param document The DID Document string to be written/updated
 */
@Suppress("MemberVisibilityCanBePrivate")
class DidEnvelope(
		instruction: String,
		document: String
) {
	val instruction = DidInstruction(instruction)
	val document = DidDocument(document)

	/**
	 * Validates that the envelope presented is formatted in a valid way to _create_ a DID.
	 */
	fun validateCreate(): Result<Unit, ValidationFailure> {
		instruction.action().onFailure {
			return Failure(MalformedInstructionFailure(it.reason))
		}.ensureIs(Create)

		return validate()
	}

	/**
	 * Validates that the envelope presented represents a valid update to the [precursor] provided.
	 */
	fun validateUpdate(precursor: DidDocument): Result<Unit, ValidationFailure> {
		instruction.action().onFailure {
			return Failure(MalformedInstructionFailure(it.reason))
		}.ensureIs(Update)

		// perform base validation, ensuring that the document is valid, not yet taking into account the precursor
		validate().onFailure { return it }

		// perform temporal validation, ensuring the created/updated times are sound
		validateTemporal(precursor).onFailure { return it }

		return Success(Unit)
	}

	private fun validateTemporal(precursor: DidDocument): Result<Unit, ValidationFailure> {
		// temporal validation
		val precursorCreated = precursor.created().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it }

		val precursorUpdated = precursor.updated().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it }

		val created = document.created().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it }

		val updated = document.updated().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it } ?: return Failure(MissingTemporalInformationFailure())

		// fail if the created timestamp has been modified with an update
		if (precursorCreated != created)
			return Failure(InvalidTemporalRelationFailure())

		if (precursorUpdated != null && !updated.isAfter(precursorUpdated))
			return Failure(InvalidTemporalRelationFailure())

		return Success(Unit)
	}

	private fun validate(): Result<Unit, ValidationFailure> {
		// extract temporal information
		val created = document.created().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it }

		val updated = document.updated().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it }

		if (updated != null && created != null && !updated.isAfter(created))
			return Failure(InvalidTemporalRelationFailure())

		// Try to extract the signatures from the `instruction` block.
		// Fail in case this is not possible (i.e. data provided is not JSON or is not well-formed).
		val signatures = instruction.signatures().onFailure {
			return Failure(MalformedInstructionFailure(it.reason))
		}

		val distinctSignatureTargets = signatures.map { it.target }.distinct()

		// Ensure each signature targets one distinct key
		if (signatures.size > distinctSignatureTargets.size)
			return Failure(SignatureTargetFailure())

		// Try to extract the public keys from the `instruction` block. Fail if not possible (i.e. malformed JSON or inappropriate structure).
		val publicKeys = document.publicKeys().onFailure {
			return Failure(MalformedDocumentFailure(it.reason))
		}

		val distinctPublicKeyIds = publicKeys.map { it.id }.distinct()

		// Ensure key IDs are unique
		if (publicKeys.size > distinctPublicKeyIds.size)
			return Failure(DuplicatePublicKeyIdFailure())

		// At least one key is required for proof of ownership. Fail if no keys are provided.
		if (publicKeys.isEmpty())
			return Failure(NoKeysFailure())

		// At least one signature per key is required.
		if (signatures.size < publicKeys.size)
			return Failure(SignatureCountFailure())

		// Temporary: Fail is there is at least one RSA or EdDsaSASecp256k1 key
		// TODO moritzplatt 2019-02-13 -- once all crypto suites are supported, remove this provision
		publicKeys.firstOrNull {
			it.type != Ed25519
		}?.let {
			return Failure(UnsupportedCryptoSuiteFailure(it.type))
		}

		// Fail if there are public keys that do not have a corresponding signature
		val pairings = publicKeys.map { publicKey ->
			val signature = signatures.singleOrNull {
				it.target == publicKey.id
			} ?: return Failure(UntargetedPublicKeyFailure(publicKey.id))
			publicKey to signature
		}

		// Fail if the crypto suite for any given signature doesn't match the corresponding key's crypto suite
		pairings.forEach { (publicKey, signature) ->
			if (publicKey.type != signature.suite)
				return Failure(CryptoSuiteMismatchFailure(
						target = publicKey.id,
						keySuite = publicKey.type,
						signatureSuite = signature.suite
				))
		}

		// Fail is a signature is invalid
		pairings.forEach { (publicKey, signature) ->
			when (signature.suite) {
				Ed25519          -> {
					if (!signature.value.isValidEd25519Signature(document.raw(), publicKey.value.toEd25519PublicKey()))
						return Failure(InvalidSignatureFailure(publicKey.id))
				}

				// TODO moritzplatt 2019-02-13 -- Implement this for other supported crypto suites
				RSA              -> TODO()
				EdDsaSASecp256k1 -> TODO()
			}
		}

		return Success(Unit)
	}

	private fun Action.ensureIs(expected: Action) {
		if (this != expected)
			throw IllegalArgumentException("Can't validate a $this action using a $expected method.")
	}
}

@Suppress("UNUSED_PARAMETER")
sealed class DidEnvelopeFailure : FailureCode() {
	sealed class ValidationFailure(description: String) : DidEnvelopeFailure() {
		class MalformedInstructionFailure(underlying: DidInstructionFailure) : ValidationFailure("The instruction document is invalid: $underlying")
		class MalformedDocumentFailure(underlying: DidDocumentFailure) : ValidationFailure("The DID is invalid: $underlying")
		class NoKeysFailure : ValidationFailure("The DID does not contain any public keys")
		class SignatureTargetFailure : ValidationFailure("Multiple Signatures target the same key")
		class DuplicatePublicKeyIdFailure : ValidationFailure("Multiple public keys have the same ID")
		class SignatureCountFailure : ValidationFailure("The number of keys in the DID document does not match the number of signatures")
		class UnsupportedCryptoSuiteFailure(suite: CryptoSuite) : ValidationFailure("$suite is no a supported cryptographic suite")
		class UntargetedPublicKeyFailure(target: URI) : ValidationFailure("No signature was provided for target $target")
		class CryptoSuiteMismatchFailure(target: URI, keySuite: CryptoSuite, signatureSuite: CryptoSuite) : ValidationFailure("$target is a key using $keySuite but is signed with $signatureSuite.")
		class InvalidSignatureFailure(target: URI) : ValidationFailure("Signature for $target was invalid.")
		class MissingTemporalInformationFailure : ValidationFailure("The document is missing information about its creation")
		class InvalidTemporalRelationFailure : ValidationFailure("Documents temporal relation is incorrect")
	}
}
