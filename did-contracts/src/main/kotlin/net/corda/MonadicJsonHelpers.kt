package net.corda

import com.grack.nanojson.JsonArray
import com.grack.nanojson.JsonObject
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success

fun JsonObject.getMandatoryArray(key: String): Result<JsonArray, JsonFailure> = getArray(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

fun JsonObject.getMandatoryNumber(key: String): Result<Number, JsonFailure> = getNumber(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

fun JsonObject.getMandatoryObject(key: String): Result<JsonObject, JsonFailure> = getObject(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

fun JsonObject.getMandatoryString(key: String): Result<String, JsonFailure> = getString(key)?.let {
	Success(it)
} ?: Failure(JsonFailure)

object JsonFailure
