package net.corda.did

import com.grack.nanojson.JsonObject
import com.grack.nanojson.JsonParser
import com.grack.nanojson.JsonParserException
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import net.corda.JsonFailure
import kotlin.text.Charsets.UTF_8

/**
 * An abstract class that allows for ad-hoc parsing of JSON, storing the canonical string representation.
 */
abstract class JsonBacked(private val source: String) {
	fun raw(): ByteArray = source.toByteArray(UTF_8)

	fun source(): String = source

	fun json(): Result<JsonObject, JsonFailure> = try {
		Success(JsonParser.`object`().from(source))
	} catch (e: JsonParserException) {
		Failure(JsonFailure)
	}
}