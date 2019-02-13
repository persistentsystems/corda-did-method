package net.corda.did

/**
 * Supported Crypto Suites as registered in the "Linked Data Cryptographic Suite Registry" Draft Community Group Report
 * 09 December 2018
 *
 * https://w3c-ccg.github.io/ld-cryptosuite-registry/
 *
 * @param keyID The external identifier for a key of this crypto suite as per the community report.
 *
 * @param signatureID The external identifier for a signature created by a private key of this crypto suite as per the
 * community report.
 */
@Suppress("MemberVisibilityCanBePrivate")
enum class CryptoSuite(
		val keyID: String,
		val signatureID: String
) {
	Ed25519("Ed25519VerificationKey2018", "Ed25519Signature2018"),
	RSA("RsaVerificationKey2018", "RsaSignature2018"),
	EdDsaSASecp256k1("EdDsaSAPublicKeySecp256k1", "EdDsaSASignatureSecp256k1");

	companion object {
		fun fromSignatureID(signatureID: String): CryptoSuite = filter {
			it.signatureID == signatureID
		}

		fun fromKeyID(keyID: String): CryptoSuite = filter {
			it.keyID == keyID
		}

		private fun filter(function: (CryptoSuite) -> Boolean) = values()
				.firstOrNull(function) ?: throw IllegalArgumentException("Unknown ID")
	}
}
