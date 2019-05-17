/**
 * R3 copy
 *
 */

package net.corda.did

import com.grack.nanojson.JsonObject
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.map
import com.natpryce.mapFailure
import com.natpryce.onFailure
import net.corda.FailureCode
import net.corda.JsonFailure
import net.corda.did.DidDocumentFailure.InvalidDocumentJsonFailure
import net.corda.did.DidDocumentFailure.InvalidTimeStampFormatFailure
import net.corda.getMandatoryArray
import net.corda.getMandatoryBase58Bytes
import net.corda.getMandatoryCryptoSuiteFromKeyID
import net.corda.getMandatoryString
import net.corda.getMandatoryUri
import java.time.Instant
import javax.xml.bind.DatatypeConverter

/**
 * This encapsulates a DID, preserving the full JSON document as received by the owner. While it would be beneficial to
 * have a strongly typed `DidDocument` class in which the aspects of a DID are stored as individual fields, the lack of
 * a canonical JSON representation on which hashes are generated makes this problematic.
 *
 * Instead, this class provides convenience methods, that extract information from the JSON document on request. Note
 * that the document tree these operations work on will not be stored in a field to keep serialisation size small. This
 * means that usage of the convenience methods has a high computational overhead.
 */
class DidDocument(document: String) : JsonBacked(document) {

	fun id(): DidDocumentResult<CordaDid> = json.getMandatoryString("id").map {
		CordaDid(it)
	}.mapFailure {
		InvalidDocumentJsonFailure(it)
	}

	fun publicKeys(): DidDocumentResult<Set<QualifiedPublicKey>> = json.getMandatoryArray("publicKey").map { keys ->
		keys.filterIsInstance(JsonObject::class.java).map { key ->
			val id = key.getMandatoryUri("id").mapFailure {
				InvalidDocumentJsonFailure(it)
			}.onFailure { return it }

			val suite = key.getMandatoryCryptoSuiteFromKeyID("type").mapFailure {
				InvalidDocumentJsonFailure(it)
			}.onFailure { return it }

			val controller = key.getMandatoryUri("controller").mapFailure {
				InvalidDocumentJsonFailure(it)
			}.onFailure { return it }

			// TODO moritzplatt 2019-02-13 -- Support other encodings
			val value = key.getMandatoryBase58Bytes("publicKeyBase58").mapFailure {
				InvalidDocumentJsonFailure(it)
			}.onFailure { return it }

			QualifiedPublicKey(id, suite, controller, value)
		}.toSet()
	}.mapFailure { InvalidDocumentJsonFailure(it) }

	// These (by design) drop time zone information as we are only interested in a before/after relationship of
	// instants.
	fun created(): DidDocumentResult<Instant?> = getTimestamp("created")

	fun updated(): DidDocumentResult<Instant?> = getTimestamp("updated")

	private fun getTimestamp(field: String): DidDocumentResult<Instant?> = json.getString(field)?.let {
		try {
			Success(DatatypeConverter.parseDateTime(it).toInstant())
		} catch (e: IllegalArgumentException) {
			Failure(InvalidTimeStampFormatFailure(it))
		}
	} ?: Success(null)
}

@Suppress("UNUSED_PARAMETER")
sealed class DidDocumentFailure : FailureCode() {
	class InvalidDocumentJsonFailure(underlying: JsonFailure) : DidDocumentFailure()
	class InvalidTimeStampFormatFailure(input: String) : DidDocumentFailure()
}

private typealias DidDocumentResult<T> = Result<T, DidDocumentFailure>

