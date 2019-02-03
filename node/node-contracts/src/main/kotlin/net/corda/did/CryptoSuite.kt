package net.corda.did

import net.corda.did.CryptoSuite.Ed25519Signature2018
import net.corda.did.CryptoSuite.EdDsaSASignatureSecp256k1
import net.corda.did.CryptoSuite.RsaSignature2018
import org.bouncycastle.util.io.pem.PemReader
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * Supported Crypto Suites as registered in the "Linked Data Cryptographic Suite Registry" Draft Community Group Report
 * 09 December 2018
 *
 * https://w3c-ccg.github.io/ld-cryptosuite-registry/
 */
enum class CryptoSuite(
		val signatureIdentifier: String,
		val keyIndentifier: String
) {
	Ed25519Signature2018("Ed25519Signature2018", "Ed25519VerificationKey2018"),
	RsaSignature2018("RsaSignature2018", "RsaVerificationKey2018"),
	EdDsaSASignatureSecp256k1("EdDsaSASignatureSecp256k1", "EdDsaSAPublicKeySecp256k1")
}

fun String.toPublicKey(suite: CryptoSuite): PublicKey {
//	val raw = rawPEMString()
//	val spec = X509EncodedKeySpec(Base64.getDecoder().decode(raw))

	val pem = PemReader(reader()).readPemObject()
	val pubKeyBytes = pem.getContent()
	val keyFactory = KeyFactory.getInstance("RSA")
	val pubSpec = X509EncodedKeySpec(pubKeyBytes)
	val pubKey = keyFactory.generatePublic(pubSpec) as RSAPublicKey

	return when (suite) {
		Ed25519Signature2018      -> TODO()
		RsaSignature2018          -> keyFactory.generatePublic(pubSpec) as RSAPublicKey
		EdDsaSASignatureSecp256k1 -> TODO()
	}

}

private fun String.rawPEMString(): String = trim()
		.substringAfter("-----BEGIN PGP PUBLIC KEY BLOCK-----")
		.substringBefore("-----END PGP PUBLIC KEY BLOCK-----")
		.lines().joinToString("") { it.trim() }
