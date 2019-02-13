package net.corda.did

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
class DidEnvelope(
		instruction: String,
		document: String
) {
	val instruction = DidInstruction(instruction)
	val document = DidDocument(document)

	fun signatures(): Set<QualifiedSignature> = instruction.signatures()

	fun publicKeys(): Set<QualifiedPublicKey> = document.publicKeys()

	fun hasIntegrity(): Boolean {
//		document().let { doc ->
//
//			// The keys embedded in the DID document
//			val documentKeys = doc.keys()
//
//			// 1 - check the number of proofs matches the number of keys in the document
//			if (proofs.size != documentKeys.size)
//				return false
//
//			// 2 - check that each proof key ID has a corresponding key in the document
//			if (!proofs.keys.containsAll(documentKeys.keys))
//				return false
//
//			// 3 - check that each of the proofs contains a valid signature over the DID document
//			return documentKeys.all { (reference, publicKey) ->
//				val signature = proofs[reference]!!
//
//				val suite = CryptoSuite.values().single {
//					it.algorithm == publicKey.algorithm
//				}
//
//				signature.isValidSignature(suite, payload.bytes, publicKey)
//			}
//		}
		return false
	}
}
