package net.corda

import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 *
 * @param originalMessage message on which signature is obtained
 * @param signer [PublicKey] of the signer
 * @receiver [ByteArray]
 * @return [Boolean] returns true if signature is valid else false
 */
fun ByteArray.isValidEd25519Signature(originalMessage: ByteArray, signer: PublicKey): Boolean {
	val spec = EdDSANamedCurveTable.getByName("Ed25519")
	return EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm)).apply {
		initVerify(signer)
		update(originalMessage)
	}.verify(this)
}

/**
 *
 * @param originalMessage message on which signature is obtained
 * @param signer [PublicKey] of the signer
 * @receiver [ByteArray]
 * @return [Boolean] returns true if signature is valid else false
 */
fun ByteArray.isValidRSASignature(originalMessage: ByteArray, signer: PublicKey): Boolean {
	return Signature.getInstance("SHA256withRSA").apply {
		initVerify(signer)
		update(originalMessage)
	}.verify(this)
}

/**
 *
 * @param originalMessage message on which signature is obtained
 * @param signer [PublicKey] of the signer
 * @receiver [ByteArray]
 * @return [Boolean] returns true if signature is valid else false
 */
fun ByteArray.isValidEcdsaSignature(originalMessage: ByteArray, signer: PublicKey): Boolean {
	return Signature.getInstance("SHA256withECDSA").apply {
		initVerify(signer)
		update(originalMessage)
	}.verify(this)
}

/**
 *
 * @receiver [ByteArray]
 * @return [EdDSAPublicKey]
 */
fun ByteArray.toEd25519PublicKey(): EdDSAPublicKey {
	val spec = EdDSAPublicKey(X509EncodedKeySpec(this)).let { key ->
		EdDSAPublicKeySpec(key.a, key.params)
	}
	return EdDSAPublicKey(spec)
}

/**
 *
 * @receiver [ByteArray]
 * @return [PublicKey]
 */
fun ByteArray.toRSAPublicKey(): PublicKey {
	return KeyFactory.getInstance("RSA", "BC").generatePublic(X509EncodedKeySpec(this))
}

/**
 *
 * @receiver [ByteArray]
 * @return [PublicKey]
 */
fun ByteArray.toEcdsaPublicKey(): PublicKey {
	return KeyFactory.getInstance("ECDSA", "BC").generatePublic(X509EncodedKeySpec(this))
}