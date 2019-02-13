package net.corda.did

import net.corda.did.Action.Delete
import net.corda.did.Action.Update
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.CryptoSuite.EdDsaSASecp256k1
import net.corda.did.CryptoSuite.RSA
import net.corda.did.DidValidationResult.DidValidationFailure.CryptoSuiteMismatchFailure
import net.corda.did.DidValidationResult.DidValidationFailure.InvalidSignatureFailure
import net.corda.did.DidValidationResult.DidValidationFailure.MalformedDocumentFailure
import net.corda.did.DidValidationResult.DidValidationFailure.MalformedInstructionFailure
import net.corda.did.DidValidationResult.DidValidationFailure.NoKeysFailure
import net.corda.did.DidValidationResult.DidValidationFailure.NoNonceFailure
import net.corda.did.DidValidationResult.DidValidationFailure.SignatureCountFailure
import net.corda.did.DidValidationResult.DidValidationFailure.UnsupportedCryptoSuiteFailure
import net.corda.did.DidValidationResult.DidValidationFailure.UntargetedSignatureFailure
import net.corda.did.DidValidationResult.Success
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

	// TODO moritzplatt 2019-02-13 -- should be rewritten in a monadic fashion to avoid early returns
	fun validate(): DidValidationResult {
		val signatures = try {
			instruction.signatures()
		} catch (e: IllegalArgumentException) {
			return MalformedInstructionFailure(e)
		}

		val action = try {
			instruction.action()
		} catch (e: IllegalArgumentException) {
			return MalformedInstructionFailure(e)
		}

		val nonce = try {
			instruction.nonce()
		} catch (e: IllegalArgumentException) {
			return MalformedInstructionFailure(e)
		}

		val publicKeys = try {
			document.publicKeys()
		} catch (e: IllegalArgumentException) {
			return MalformedDocumentFailure(e)
		}

		if (publicKeys.isEmpty())
			return NoKeysFailure()

		if (signatures.size != publicKeys.size)
			return SignatureCountFailure()

		if ((action == Update || action == Delete) && nonce == null)
			return NoNonceFailure()

		// TODO moritzplatt 2019-02-13 -- once all crypto suites are supported, remove this provision
		publicKeys.firstOrNull {
			it.type != Ed25519
		}?.let {
			return UnsupportedCryptoSuiteFailure(it.type)
		}

		val pairings = publicKeys.map { publicKey ->
			val signature = signatures.singleOrNull {
				it.target == publicKey.id
			} ?: return UntargetedSignatureFailure(publicKey.id)
			publicKey to signature
		}

		pairings.forEach { (publicKey, signature) ->
			if (publicKey.type != signature.suite)
				return CryptoSuiteMismatchFailure(
						target = publicKey.id,
						keySuite = publicKey.type,
						signatureSuite = signature.suite
				)
		}

		pairings.forEach { (publicKey, signature) ->
			when (signature.suite) {
				Ed25519          -> {
					if (!signature.value.isValidEd25519Signature(document.bytes, publicKey.value.toEd25519PublicKey()))
						return InvalidSignatureFailure(publicKey.id)
				}

				// TODO moritzplatt 2019-02-13 -- Implement this for other supported crypto suites
				RSA              -> TODO()
				EdDsaSASecp256k1 -> TODO()
			}
		}

		return Success
	}
}

sealed class DidValidationResult {
	object Success : DidValidationResult()

	sealed class DidValidationFailure(description: String) : DidValidationResult() {
		class MalformedInstructionFailure(root: Exception) : DidValidationFailure("The instruction document is invalid: ${root.localizedMessage}")
		class NoNonceFailure : DidValidationFailure("No nonce provided with instruction")
		class MalformedDocumentFailure(root: Exception) : DidValidationFailure("The DID is invalid: ${root.localizedMessage}")
		class NoKeysFailure : DidValidationFailure("The DID does not contain any public keys")
		class SignatureCountFailure : DidValidationFailure("The number of keys in the DID document does not match the number of signatures")
		class UnsupportedCryptoSuiteFailure(suite: CryptoSuite) : DidValidationFailure("$suite is no a supported cryptographic suite")
		class UntargetedSignatureFailure(target: URI) : DidValidationFailure("No signature was provided for target $target")
		class CryptoSuiteMismatchFailure(target: URI, keySuite: CryptoSuite, signatureSuite: CryptoSuite) : DidValidationFailure("$target is a key using $keySuite but is signed with $signatureSuite.")
		class InvalidSignatureFailure(target: URI) : DidValidationFailure("Signature for $target was invalid.")
	}

}
