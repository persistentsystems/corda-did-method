package net.corda

import com.grack.nanojson.JsonArray
import com.grack.nanojson.JsonObject
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.flatMap
import com.natpryce.mapFailure
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.JSONObjectUtils
import io.ipfs.multiformats.multibase.MultiBase
import net.corda.JsonFailure.InvalidCryptoSuiteFailure
import net.corda.JsonFailure.InvalidEncoding
import net.corda.JsonFailure.InvalidUriFailure
import net.corda.JsonFailure.MissingPropertyFailure
import net.corda.core.crypto.AddressFormatException
import net.corda.core.crypto.Base58
import net.corda.did.CryptoSuite
import net.corda.did.PublicKeyEncoding
import net.corda.did.SignatureEncoding
import org.apache.commons.codec.binary.Hex
import java.net.URI
import java.util.Base64

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */
fun JsonObject.getMandatoryArray(key: String): JsonResult<JsonArray> = getArray(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */
fun JsonObject.getMandatoryNumber(key: String): JsonResult<Number> = getNumber(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */
fun JsonObject.getMandatoryObject(key: String): JsonResult<JsonObject> = getObject(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */

fun JsonObject.getMandatoryString(key: String?): JsonResult<String> = getString(key)?.let { value ->
	Success(value)
} ?: Failure(MissingPropertyFailure(key))

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */
fun JsonObject.getMandatoryUri(key: String): JsonResult<URI> = getMandatoryString(key).flatMap { value ->
	try {
		Success(URI.create(value))
	} catch (e: IllegalArgumentException) {
		Failure(InvalidUriFailure(value))
	}
}

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */
fun JsonObject.getMandatoryCryptoSuiteFromKeyID(keyID: String): JsonResult<CryptoSuite> = getMandatoryString(keyID).flatMap { value ->
	CryptoSuite.fromKeyID(value).mapFailure {
		InvalidCryptoSuiteFailure(value)
	}
}

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */
fun JsonObject.getMandatoryCryptoSuiteFromSignatureID(signatureID: String): JsonResult<CryptoSuite> = getMandatoryString(signatureID).flatMap { value ->
	CryptoSuite.fromSignatureID(value).mapFailure {
		InvalidCryptoSuiteFailure(value)
	}
}

/**
 *
 * @param key json key
 * @receiver [JsonObject]
 * @return [JsonResult]
 */

fun JsonObject.getMandatoryEncoding(key: String?): JsonResult<ByteArray> = getMandatoryString(key).flatMap { value ->
	try {
		when (key) {
			PublicKeyEncoding.PublicKeyBase58.encodingId    -> {
				try {
					val decodedValue = Base58.decode(value)
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			SignatureEncoding.SignatureBase58.encodingId    -> {
				try {
					val decodedValue = Base58.decode(value)
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			PublicKeyEncoding.PublicKeyHex.encodingId       -> {
				try {
					val decodedValue = Hex.decodeHex(value.toCharArray())
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			SignatureEncoding.SignatureHex.encodingId       -> {
				try {
					val decodedValue = Hex.decodeHex(value.toCharArray())
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			PublicKeyEncoding.PublicKeyBase64.encodingId    -> {
				try {
					val decodedValue = Base64.getDecoder().decode(value)
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			SignatureEncoding.SignatureBase64.encodingId    -> {
				try {
					val decodedValue = Base64.getDecoder().decode(value)
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			PublicKeyEncoding.PublicKeyMultibase.encodingId -> {
				try {
					val decodedValue = MultiBase.decode(value)
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			SignatureEncoding.SignatureMultibase.encodingId -> {
				try {
					val decodedValue = MultiBase.decode(value)
					Success(decodedValue)
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}

			}
			PublicKeyEncoding.PublicKeyPem.encodingId       -> {
				try {
					var encodedString = value.replace("\n", "").replace("\r", "")
					encodedString = encodedString.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
					Success(Base64.getDecoder().decode(encodedString.toByteArray()))
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}
			}
			PublicKeyEncoding.PublicKeyJwk.encodingId       -> {
				try {
					val parsedObject = JSONObjectUtils.parse(value)
					val kty = KeyType.parse(JSONObjectUtils.getString(parsedObject, "kty"))
					when (kty) {
						KeyType.RSA -> {
							val rsaKey = RSAKey.parse(parsedObject)
							return Success(rsaKey.toRSAPublicKey().encoded)
						}
						KeyType.EC  -> {
							val ecKey = ECKey.parse(parsedObject)
							return Success(ecKey.toECPublicKey().encoded)
						}
						KeyType.OCT -> {
							val octetKey = OctetSequenceKey.parse(parsedObject)
							return Success(octetKey.toByteArray())
						}
					}
					Failure(InvalidEncoding(value))
				} catch (e: Exception) {
					Failure(InvalidEncoding(value))
				}
			}
			else                                            -> Failure(InvalidEncoding(value))
		}

	} catch (e: AddressFormatException) {
		Failure(InvalidEncoding(value))
	}
}

typealias JsonResult<T> = Result<T, JsonFailure>

@Suppress("UNUSED_PARAMETER", "unused")
/**
 * Class for returning error in JSON payload
 *
 * @property [MissingPropertyFailure] Specifies that a property is missing in JSON payload.
 * @property [InvalidUriFailure] Specifies if uri is invalid.
 * @property [InvalidEncoding] Specifies if base58 representation is wrong.
 * @property [InvalidCryptoSuiteFailure] Specifies if the provided crypto suite is invalid
 * */
sealed class JsonFailure : FailureCode() {
	class MissingPropertyFailure(val key: String?) : JsonFailure()
	class InvalidUriFailure(val value: String) : JsonFailure()
	class InvalidEncoding(val value: String) : JsonFailure()
	class InvalidCryptoSuiteFailure(val value: String) : JsonFailure()
}
