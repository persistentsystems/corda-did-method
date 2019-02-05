package net.corda.did

import com.grack.nanojson.JsonObject
import net.corda.core.utilities.base58ToByteArray
import net.corda.core.utilities.hexToByteArray
import net.corda.did.CryptoSuite.Ed25519
import net.corda.did.CryptoSuite.EdDsaSASecp256k1
import net.corda.did.CryptoSuite.RSA
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * Supported Crypto Suites as registered in the "Linked Data Cryptographic Suite Registry" Draft Community Group Report
 * 09 December 2018
 *
 * https://w3c-ccg.github.io/ld-cryptosuite-registry/
 */
enum class CryptoSuite(
		val algorithm: String,
		val signatureIdentifier: String,
		val keyIndentifier: String
) {
	Ed25519("EdDSA", "Ed25519", "Ed25519VerificationKey2018"),
	RSA("TODO", "RSA", "RsaVerificationKey2018"),
	EdDsaSASecp256k1("TODO", "EdDsaSASecp256k1", "EdDsaSAPublicKeySecp256k1")
}

fun ByteArray.toEd25519PublicKey(): EdDSAPublicKey {
	val spec = EdDSAPublicKey(X509EncodedKeySpec(this)).let { key ->
		EdDSAPublicKeySpec(key.a, key.params)
	}
	return EdDSAPublicKey(spec)
}

// TODO moritzplatt 2019-02-05 -- Make this agnostic to the representation (so far, only one representation per key is supported)
fun JsonObject.toPublicKey(suite: CryptoSuite): PublicKey =
		when (suite) {
			Ed25519          -> {
				assert(has("publicKeyBase58"))
				getString("publicKeyBase58").base58ToByteArray().toEd25519PublicKey()
			}
			RSA              -> {
				assert(has("publicKeyPem"))
				getString("publicKeyPem").toRsaPublicKey()
			}
			EdDsaSASecp256k1 -> {
				assert(has("publicKeyHex"))
				getString("publicKeyPem").hexToByteArray().toEdDsaSAPublicKey()
			}
		}

private fun String.toRsaPublicKey(): PublicKey {
	TODO("do it!")
}

private fun ByteArray.toEdDsaSAPublicKey(): PublicKey {
	TODO("do it!")
}

fun ByteArray.isValidSignature(suite: CryptoSuite, originalMessage: ByteArray, signer: PublicKey): Boolean {
	return when (suite) {
		Ed25519          -> isValidEd25519Signature(originalMessage, signer)
		RSA              -> TODO()
		EdDsaSASecp256k1 -> TODO()
	}
}

private fun ByteArray.isValidEd25519Signature(originalMessage: ByteArray, signer: PublicKey): Boolean {
	val spec = EdDSANamedCurveTable.getByName("Ed25519")
	return EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm)).apply {
		initVerify(signer)
		update(originalMessage)
	}.verify(this)
}


