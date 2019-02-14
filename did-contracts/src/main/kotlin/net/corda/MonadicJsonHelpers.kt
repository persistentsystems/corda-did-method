package net.corda

import com.grack.nanojson.JsonArray
import com.grack.nanojson.JsonObject
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success

fun JsonObject.getArray(key: String): Result<JsonArray, JsonFailure> = getArray(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

fun JsonObject.getNumber(key: String): Result<Number, JsonFailure> = getNumber(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

fun JsonObject.getObject(key: String): Result<JsonObject, JsonFailure> = getObject(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

fun JsonObject.getString(key: String): Result<String, JsonFailure> = getString(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

object JsonFailure
