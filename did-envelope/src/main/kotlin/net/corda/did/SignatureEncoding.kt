package net.corda.did

/**

 * @param encodingId The well-know identifier for the mechanism the signature is encoded in according to the draft
 * community report.

 * @property[SignatureHex] Hex encoding of the signature
 * @property[SignatureBase64] Base64 encoding of signature
 * @property[SignatureBase58] base58 encoding of signature
 * @property[SignatureMultibase] Multibase encoding of signature
 */

@Suppress("MemberVisibilityCanBePrivate")
enum class SignatureEncoding(
		val encodingId: String
) {
	SignatureHex("signatureHex"),
	SignatureBase64("signatureBase64"),
	SignatureBase58("signatureBase58"),
	SignatureMultibase("signatureMultibase")
}
