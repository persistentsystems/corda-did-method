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
import net.corda.core.serialization.CordaSerializable
import net.corda.did.DidDocumentFailure.InvalidDidFailure
import net.corda.did.DidDocumentFailure.InvalidDocumentJsonFailure
import net.corda.did.DidDocumentFailure.InvalidTimeStampFormatFailure
import net.corda.getMandatoryArray
import net.corda.getMandatoryBase58Bytes
import net.corda.getMandatoryCryptoSuiteFromKeyID
import net.corda.getMandatoryString
import net.corda.getMandatoryUri
import java.lang.IllegalArgumentException
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
 *
 * @property document1 String representation of did document.
 */
@CordaSerializable
data class DidDocument(val document1: String) : JsonBacked(document1) {

	/**
	 * Returns the id from json did document
	 *
	 * @return [DidDocumentResult]
	 */
	fun id(): DidDocumentResult<CordaDid> {
		val id = json.getMandatoryString("id").mapFailure {
			InvalidDocumentJsonFailure(it)
		}.onFailure { return it }

		val cordaDID = CordaDid.parseExternalForm(id).onFailure { return Failure(DidDocumentFailure.InvalidDidFailure(it.reason)) }
		// ??? moritzplatt 2019-06-20 -- this call could throw an exception. to keep in line with the monadic approach,
		// consider refactoring the CordaDID class in the following way:
		//
		// class CordaDid(
		//        val did: URI,
		//        val network: Network,
		//        val uuid: UUID
		//) {
		//
		//    companion object {
		//        fun parseExternalForm(externalForm: String): Result<CordaDid, ???> {
		//           ...
		//        }
		//    }
		//
		//    fun toExternalForm() = did.toString()
		//}
		//
		// This will allow you to stick to the monadic approach and chain success/failures further

		return Success(cordaDID)
	}

	// ??? moritzplatt 2019-06-20 -- shouldn't return a nullable UUID but a failure if the UUID can't be retrieved
	// it is mandatory

	// ??? moritzplatt 2019-06-20 -- consider renaming the function:
	// `UUID` is the type returned, not the concept behind it

	// ??? moritzplatt 2019-06-20 -- this method feels unnecessary as the same result can be achieved by `id().uuid`

	// nitesh solanki 2019-06-27 UUID() not needed

	/*fun UUID(): DidDocumentResult<UUID?> = id().map{
			return Success(it.uuid)
		}.mapFailure {
			// ??? moritzplatt 2019-06-20 -- strictly speaking, this wouldn't only apply for a UUID with invalid format
			// but also if the UUID is missing from the document altogether
			return Failure(DidDocumentFailure.InvalidUUIDFormatFailure(it.toString()))
		}*/

	/**
	 * Returns the context from json did document
	 *
	 * @return [DidDocumentResult]
	 */
	fun context() = json.getMandatoryString("@context").map {
		it.isNotEmpty()
	}.mapFailure {
		InvalidDocumentJsonFailure(it)
	}

	/**
	 * Returns the list of public Keys from json did document
	 *
	 * @return [DidDocumentResult]
	 */
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
	/**
	 * Returns the created timestamp from json did document
	 *
	 * @return [DidDocumentResult]
	 */
	fun created(): DidDocumentResult<Instant?> = getTimestamp("created")

	/**
	 * Returns the updated timestamp from json did document
	 *
	 * @return [DidDocumentResult]
	 */
	fun updated(): DidDocumentResult<Instant?> = getTimestamp("updated")

	/**
	 * Returns the Instant type
	 *
	 * @return [DidDocumentResult]
	 */
	private fun getTimestamp(field: String): DidDocumentResult<Instant?> = json.getString(field)?.let {
		try {
			Success(DatatypeConverter.parseDateTime(it).toInstant())
		} catch (e: IllegalArgumentException) {
			Failure(InvalidTimeStampFormatFailure(it))
		}
	} ?: Success(null)
}

@Suppress("UNUSED_PARAMETER")
/**
 * Identify incorrect document json
 *
 * @property InvalidDocumentJsonFailure  if document is invalid
 * @property InvalidDidFailure DID is invalid
 * @property InvalidTimeStampFormatFailure created or updated field is invalid.
 *
 * */
sealed class DidDocumentFailure : FailureCode() {
	class InvalidDocumentJsonFailure(underlying: JsonFailure) : DidDocumentFailure()
	class InvalidDidFailure(underlying: CordaDidFailure) : DidDocumentFailure()
	class InvalidTimeStampFormatFailure(input: String) : DidDocumentFailure()
}

private typealias DidDocumentResult<T> = Result<T, DidDocumentFailure>

