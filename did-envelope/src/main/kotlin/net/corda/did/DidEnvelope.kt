/**
 * R3 copy
 *
 */

package net.corda.did

import com.natpryce.*
import net.corda.FailureCode
import net.corda.core.serialization.CordaSerializable
import net.corda.did.Action.Create
import net.corda.did.Action.Delete
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
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MalformedPrecursorFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingSignatureFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.MissingTemporalInformationFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoKeysFailure
import net.corda.did.DidEnvelopeFailure.ValidationFailure.NoMatchingSignatureFailure
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
 * @property rawInstruction The instruction string, outlining which action should be performed with the DID document provided
 * along with cryptographic proof of ownership of the DID document in form of a signature.
 * @property rawDocument The DID Document string to be written/updated
 * @property instruction The [DidInstruction] object
 * @property document The [DidDocument] object
 */
@Suppress("MemberVisibilityCanBePrivate", "CanBeParameter")
@CordaSerializable
class DidEnvelope(
		// ??? moritzplatt 2019-06-20 -- do these need to be vals? `rawInstruction` is unsused `rawDocument` only from test

		// nitesh solanki 2019-06-27 yes, else corda serialization throws an exception
		val rawInstruction: String,
		val rawDocument: String
) {
	 val instruction = DidInstruction(rawInstruction)
	 val document = DidDocument(rawDocument)

	/**
	 * Validates that the envelope presented is formatted in a valid way to _create_ a DID.
	 */
	fun validateCreation(): Result<Unit, ValidationFailure> {
		instruction.action().onFailure {
			return Failure(MalformedInstructionFailure(it.reason))
		}.ensureIs(Create)

		return validate()
	}

	/**
	 * Validates that the envelope presented represents a valid update/deletion of the [precursor] provided.
	 * @param precursor The precursor document.
	 */
	fun validateModification(precursor: DidDocument): Result<Unit, ValidationFailure> {
		instruction.action().onFailure {
			return Failure(MalformedInstructionFailure(it.reason))
		}.ensureIs(Update, Delete)

		// perform base validation, ensuring that the document is valid, not yet taking into account the precursor
		validate().onFailure { return it }

		// perform temporal validation, ensuring the created/updated times are sound
		validateTemporal(precursor).onFailure { return it }

		// perform key ownership for deletion (i.e. prove ownership of ALL keys)
		// ??? moritzplatt 2019-06-20 -- is this what we want, i.e. even for deletion we require all keys?
		validateKeysForModification(precursor).onFailure { return it }

		return Success(Unit)
	}

    /**
     * Validates that the envelope presented represents a valid deletion of the [precursor] provided.
	 * @param precursor The precursor document.
     */

	// nitesh solanki 2019-06-27  for deletion there is no temporal checks since we are not passing new doc to delete api
    fun validateDeletion(precursor: DidDocument): Result<Unit, ValidationFailure> {
        instruction.action().onFailure {
            return Failure(MalformedInstructionFailure(it.reason))
        }.ensureIs(Update, Delete)

        // perform base validation, ensuring that the document is valid, not yet taking into account the precursor
        validate().onFailure { return it }

        // perform key ownership for deletion (i.e. prove ownership of ALL keys)
        // ??? moritzplatt 2019-06-20 -- is this what we want, i.e. even for deletion we require all keys?
        validateKeysForModification(precursor).onFailure { return it }

        return Success(Unit)
    }


    private fun validate(): Result<Unit, ValidationFailure> {
		document.context().mapFailure {
			MalformedDocumentFailure(it)
		}.onFailure { return it }

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


		/**
		 * Persistent code
		 *
		 */
		// Fail if the id of the public key do not contain did as a prefix
		publicKeys.map { publicKey ->
			val publicKeyId = publicKey.id.toString()
			val did = this.document.id().valueOrNull() as CordaDid
			if (!publicKeyId.subSequence(0, publicKeyId.indexOf("#")).equals(did.toExternalForm()))
				return Failure(ValidationFailure.InvalidPublicKeyId(publicKey.id))
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

		return pairings.verifySignatures()
	}

	/**
	 * @param precursor The precursor document
	 */
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

	/**
	 * @param precursor The precursor document
	 */
	// validate that _each_ key in the precursor document has a signature in the current one
	private fun validateKeysForModification(precursor: DidDocument): Result<Unit, ValidationFailure> {
		// standard validation has been performed prior to this so we know the keys in the precursor document have a
		// valid signature
		val precursorKeys = precursor.publicKeys().mapFailure {
			MalformedPrecursorFailure(it)
		}.onFailure { return it }

		val currentSignatures = instruction.signatures().mapFailure {
			MalformedInstructionFailure(it)
		}.onFailure { return it }

		return precursorKeys.map { precursorKey ->
			val qualifiedSignature = currentSignatures.firstOrNull { signature ->
				signature.target == precursorKey.id
			} ?: return Failure(MissingSignatureFailure(precursorKey.id))
			precursorKey to qualifiedSignature
		}.verifySignatures()
	}

	/**
	 * @param precursor The precursor document
	 */
	// validate that _at least one_ key in the precursor document has a signature in the current one
	private fun validateKeysForDelete(precursor: DidDocument): Result<Unit, ValidationFailure> {
		val precursorKeys = precursor.publicKeys().mapFailure {
			MalformedPrecursorFailure(it)
		}.onFailure { return it }

		val currentSignatures = instruction.signatures().mapFailure {
			MalformedInstructionFailure(it)
		}.onFailure { return it }

		return precursorKeys.map { precursorKey ->
			precursorKey to currentSignatures.firstOrNull { signature ->
				signature.target == precursorKey.id
			}
		}.firstOrNull { it.second != null }?.let { (pk, sig) ->
			if (sig!!.value.isValidSignature(document.raw, pk)) {
				Success(Unit)
			} else {
				Failure(InvalidSignatureFailure(pk.id))
			}
		} ?: Failure(NoMatchingSignatureFailure())
	}

	private fun List<Pair<QualifiedPublicKey, QualifiedSignature>>.verifySignatures(): Result<Unit, ValidationFailure> {
		forEach { (publicKey, signature) ->
			if (!signature.value.isValidSignature(document.raw, publicKey)) return Failure(InvalidSignatureFailure(publicKey.id))
		}
		return Success(Unit)
	}

	/**
	 *
	 * @param originalMessage message on which signature is obtained
	 * @param publicKey [QualifiedPublicKey] of the signer
	 * @receiver [ByteArray]
	 * @return [Boolean] returns true if signature is valid else false
	 */
	private fun ByteArray.isValidSignature(originalMessage: ByteArray, publicKey: QualifiedPublicKey): Boolean {
		return when (publicKey.type) {
			Ed25519          -> isValidEd25519Signature(originalMessage, publicKey.value.toEd25519PublicKey())
			// ??? moritzplatt 2019-06-20 -- Are you considering any work on supporting additional crypto suites?
			// TODO moritzplatt 2019-02-13 -- Implement this for other supported crypto suites
			RSA              -> TODO()
			EdDsaSASecp256k1 -> TODO()
		}
	}

	/**
	 * @param expected
	 * @receiver [Action]
	 * @throws IllegalArgumentException
	 */
	private fun Action.ensureIs(vararg expected: Action) {
		if (!expected.contains(this))
			throw IllegalArgumentException("Can't validate a $this action using a $expected method.")
	}

}

@Suppress("UNUSED_PARAMETER", "CanBeParameter", "MemberVisibilityCanBePrivate")
/**
 * Class specifies if there is any error document or instruction supplied.
 * @property[MalformedInstructionFailure] Used to specify if  instruction is malformed.
 * @property[MalformedDocumentFailure] Specifies malformed document.
 * @property[MalformedPrecursorFailure] Specifies if precursor is malformed.
 * @property[NoKeysFailure] Specifies DID document does not contain public keys.
 * @property[SignatureTargetFailure] Multiple Signatures target the same key
 * @property[SignatureCountFailure] The number of keys in the DID document does not match the number of signatures
 * @property[UnsupportedCryptoSuiteFailure] Not a supported cryptographic suite
 * @property[CryptoSuiteMismatchFailure] Signing keys and signature are using different suites
 * @property[InvalidSignatureFailure] Signature is invalid.
 * @property[MissingSignatureFailure] Signature missing.
 * @property[MissingTemporalInformationFailure] Temporal information not  provided.
 * @property[InvalidTemporalRelationFailure] Temporal information is invalid.
 * @property[InvalidPublicKeyId] PublicKey ID must contain did as prefix for target
 * @property[DuplicatePublicKeyIdFailure] Multiple public keys have the same ID
 * @property[UntargetedPublicKeyFailure] No signature was provided for target.
 * @property[NoMatchingSignatureFailure] No matching signature.
 * */
sealed class DidEnvelopeFailure : FailureCode() {
	sealed class ValidationFailure(description: String) : DidEnvelopeFailure() {
		class MalformedInstructionFailure(val underlying: DidInstructionFailure) : ValidationFailure("The instruction document is invalid: $underlying")
		class MalformedDocumentFailure(val underlying: DidDocumentFailure) : ValidationFailure("The DID is invalid: $underlying")
		class MalformedPrecursorFailure(val underlying: DidDocumentFailure) : ValidationFailure("The precursor DID is invalid: $underlying")
		class NoKeysFailure : ValidationFailure("The DID does not contain any public keys")
		class SignatureTargetFailure : ValidationFailure("Multiple Signatures target the same key")
		class DuplicatePublicKeyIdFailure : ValidationFailure("Multiple public keys have the same ID")
		class SignatureCountFailure : ValidationFailure("The number of keys in the DID document does not match the number of signatures")
		class UnsupportedCryptoSuiteFailure(val suite: CryptoSuite) : ValidationFailure("$suite is no a supported cryptographic suite")
		class UntargetedPublicKeyFailure(val target: URI) : ValidationFailure("No signature was provided for target $target")
		class CryptoSuiteMismatchFailure(val target: URI, val keySuite: CryptoSuite, val signatureSuite: CryptoSuite) : ValidationFailure("$target is a key using $keySuite but is signed with $signatureSuite.")
		class InvalidSignatureFailure(val target: URI) : ValidationFailure("Signature for $target is invalid.")
		class NoMatchingSignatureFailure : ValidationFailure("No signature is provided for any of the keys.")
		class MissingSignatureFailure(val target: URI) : ValidationFailure("Signature for $target is missing.")
		class MissingTemporalInformationFailure : ValidationFailure("The document is missing information about its creation")
		class InvalidTemporalRelationFailure : ValidationFailure("Documents temporal relation is incorrect")
		class InvalidPublicKeyId(val target: URI) : ValidationFailure("PublicKey ID must contain did as prefix for target $target")
	}
}
