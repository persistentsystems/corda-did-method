/**
 * R3 copy
 *
 */

package net.corda.did

/**
 * Public key encodings to be supported according to Decentralized Identifiers v0.11 Data Model: Draft Community Group
 * Report 06 February 2019.
 *
 * https://w3c-ccg.github.io/did-spec/#public-keys
 *
 * @param encodingId The well-know identifier for the mechanism the public key is encoded in according to the draft
 * community report.
 */
@Suppress("MemberVisibilityCanBePrivate")
enum class PublicKeyEncoding(
		val encodingId: String
) {
	PublicKeyPem("publicKeyPem"),
	PublicKeyJwk("publicKeyJwk"),
	PublicKeyHex("publicKeyHex"),
	PublicKeyBase64("publicKeyBase64"),
	PublicKeyBase58("publicKeyBase58"),
	PublicKeyMultibase("publicKeyMultibase")
}