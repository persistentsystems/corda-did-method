/**
 * R3 copy
 *
 */

package net.corda

import com.grack.nanojson.JsonArray
import com.grack.nanojson.JsonObject
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.flatMap
import com.natpryce.mapFailure
import net.corda.JsonFailure.InvalidBase58Representation
import net.corda.JsonFailure.InvalidCryptoSuiteFailure
import net.corda.JsonFailure.InvalidUriFailure
import net.corda.JsonFailure.MissingPropertyFailure
import net.corda.core.crypto.AddressFormatException
import net.corda.core.crypto.Base58
import net.corda.did.CryptoSuite
import java.net.URI

fun JsonObject.getMandatoryArray(key: String): JsonResult<JsonArray> = getArray(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

fun JsonObject.getMandatoryNumber(key: String): JsonResult<Number> = getNumber(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

fun JsonObject.getMandatoryObject(key: String): JsonResult<JsonObject> = getObject(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

fun JsonObject.getMandatoryString(key: String): JsonResult<String> = getString(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

fun JsonObject.getMandatoryUri(key: String): JsonResult<URI> = getMandatoryString(key).flatMap { value ->
	try {
		Success(URI.create(value))
	} catch (e: IllegalArgumentException) {
		Failure(InvalidUriFailure(value))
	}
}

fun JsonObject.getMandatoryCryptoSuiteFromKeyID(keyID: String): JsonResult<CryptoSuite> = getMandatoryString(keyID).flatMap { value ->
	CryptoSuite.fromKeyID(value).mapFailure {
		InvalidCryptoSuiteFailure(value)
	}
}

fun JsonObject.getMandatoryCryptoSuiteFromSignatureID(signatureID: String): JsonResult<CryptoSuite> = getMandatoryString(signatureID).flatMap { value ->
	CryptoSuite.fromSignatureID(value).mapFailure {
		InvalidCryptoSuiteFailure(value)
	}
}

fun JsonObject.getMandatoryBase58Bytes(key: String): JsonResult<ByteArray> = getMandatoryString(key).flatMap { value ->
	try {
		Success(Base58.decode(value))
	} catch (e: AddressFormatException) {
		Failure(InvalidBase58Representation(value))
	}
}

typealias JsonResult<T> = Result<T, JsonFailure>

@Suppress("UNUSED_PARAMETER", "unused")
sealed class JsonFailure : FailureCode() {
	class MissingPropertyFailure(val key: String) : JsonFailure()
	class InvalidUriFailure(val value: String) : JsonFailure()
	class InvalidBase58Representation(val value: String) : JsonFailure()
	class InvalidCryptoSuiteFailure(val value: String) : JsonFailure()
}
