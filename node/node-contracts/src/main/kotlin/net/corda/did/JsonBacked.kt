package net.corda.did

import com.grack.nanojson.JsonObject
import com.grack.nanojson.JsonParser

/**
 * An abstract class that allows for ad-hoc parsing of JSON, storing the canonical string representation.
 */
abstract class JsonBacked(private val jsonString: String) {
	fun raw(): String = jsonString
	fun json(): JsonObject = JsonParser.`object`().from(jsonString)
}