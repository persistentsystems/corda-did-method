package net.corda.did

import com.grack.nanojson.JsonObject
import com.grack.nanojson.JsonParser
import com.grack.nanojson.JsonParserException
import com.natpryce.Failure
import com.natpryce.Success
import net.corda.JsonFailure.ParserFailure
import net.corda.JsonResult
import kotlin.text.Charsets.UTF_8

/**
 * An abstract class that allows for ad-hoc parsing of JSON, storing the canonical string representation.
 */
abstract class JsonBacked(private val source: String) {
	fun raw(): ByteArray = source.toByteArray(UTF_8)

	fun source(): String = source

	fun json(): JsonResult<JsonObject> = try {
		Success(JsonParser.`object`().from(source))
	} catch (e: JsonParserException) {
		Failure(ParserFailure(
				message = e.message,
				linePosition = e.linePosition,
				characterPosition = e.charPosition,
				characterOffset = e.charOffset
		))
	}
}