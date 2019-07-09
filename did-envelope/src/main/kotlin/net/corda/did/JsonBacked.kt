/**
 * R3 copy
 *
 */

package net.corda.did

import com.grack.nanojson.JsonObject
import com.grack.nanojson.JsonParser
import com.grack.nanojson.JsonParserException
import net.corda.core.serialization.CordaSerializable
import kotlin.text.Charsets.UTF_8

/**
 * An abstract class that allows for ad-hoc parsing of JSON, serialising the canonical string representation only.
 */
@Suppress("MemberVisibilityCanBePrivate", "CanBeParameter")
@CordaSerializable
/**
 *@property[raw] The raw document data.
 * @property [json] document parsed as JsonObject
 * @param [source] document passed as a string.
 * */
abstract class JsonBacked(val source: String) {
	// Corda serialisation dictates these won't be serialised. Only the fields in the constructor that have getters are.
	// This means there is no volume overhead in storing these as fields.
	val raw: ByteArray = source.toByteArray(UTF_8)
	val json: JsonObject

	init {
		json = try {
			JsonParser.`object`().from(source)
		} catch (e: JsonParserException) {
			throw IllegalArgumentException(e)
		}
	}
}