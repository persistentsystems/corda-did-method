package com.persistent.did.witness.flows

import com.persistent.did.state.DidState
import com.persistent.did.utils.DIDNotFoundException
import net.corda.core.contracts.TransactionVerificationException
import net.corda.core.crypto.sign
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.toBase58
import net.corda.did.CordaDid
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.testing.core.singleIdentity
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import kotlin.test.assertFailsWith

/**
 * Test cases for [UpdateDidFlow]
 */
class UpdateDidFlowTests : AbstractFlowTestUtils() {

	@Test
	fun `update did successfully`() {
		// update did
		updateDID(getDidStateForUpdateOperation().envelope)!!.tx
		mockNetwork.waitQuiescent()

		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument.equals(getDidStateForUpdateOperation().envelope.rawDocument))
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument.equals(getDidStateForUpdateOperation().envelope.rawDocument))
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument.equals(getDidStateForUpdateOperation().envelope.rawDocument))
		}
	}

	@Test
	fun `Validation succeeds for a request that adds a key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri1 = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey1 = oldKeyPair1.public.encoded.toBase58()

		val oldKeyUri2 = URI("${documentId.toExternalForm()}#2")
		val oldKeyPair2 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey2 = oldKeyPair2.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val originalSignatureFromOldKey2 = oldKeyPair2.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey2Encoded = originalSignatureFromOldKey2.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	},
        |	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey2Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey2"
		|	},
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey1"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromOldKey2 = oldKeyPair2.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey2Encoded = signatureFromOldKey2.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	},
		|	{
		|	  "id": "$oldKeyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey2Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		originator.startFlow(flow).getOrThrow()
		mockNetwork.waitQuiescent()

		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument.equals(newDocument))
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument.equals(newDocument))
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument.equals(newDocument))
		}
	}

	@Test
	fun `Validation succeeds for a request that removes a key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair1.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		/*
		 * Generate a new key pair
		 */
		val newKeyUri = URI("${documentId.toExternalForm()}#new-new-new")
		val newKeyPair = KeyPairGenerator().generateKeyPair()
		val newPublicKey = newKeyPair.public.encoded.toBase58()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newPublicKey"
		|	}
		|  ]
		|}""".trimMargin()
		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		originator.startFlow(flow).getOrThrow()
		mockNetwork.waitQuiescent()

		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument == newDocument)
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument == newDocument)
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.envelope.rawDocument == newDocument)
		}
	}

	@Test
	fun `Validation fails for an update that tampers with the creation date`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair1.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:01Z",
		|  "updated": "1970-01-01T00:00:01Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()
		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }

	}

	@Test
	fun `Validation fails if a created date is added`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair1.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2019-01-01T00:00:00Z",
		|  "updated": "2019-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()
		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }

	}

	@Test
	fun `Validation fails for an update that does not supply an update date`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair1.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }

	}

	@Test
	fun `Validation fails for an update that occurs before the creation date`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair1.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2019-02-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2019-02-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()
		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }

	}

	@Test
	fun `Validation fails for a potential replay attack`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val oldKeyUri = URI("${documentId.toExternalForm()}#1")
		val oldKeyPair1 = KeyPairGenerator().generateKeyPair()
		val oldPublicKey = oldKeyPair1.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2017-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$oldPublicKey"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = oldKeyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "2017-01-01T00:00:00Z",
		|  "updated": "2018-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()
		val signatureFromOldKey1 = oldKeyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()

		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$oldKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }
	}

	@Test
	fun `Validation fails for a request that doesn't provide signatures for all keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val keyUri1 = URI("${documentId.toExternalForm()}#uno")
		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val publicKey1 = keyPair1.public.encoded.toBase58()

		val keyUri2 = URI("${documentId.toExternalForm()}#dos")
		val keyPair2 = KeyPairGenerator().generateKeyPair()
		val publicKey2 = keyPair2.public.encoded.toBase58()

		val oldDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$publicKey1"
		|	},
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$publicKey2"
		|	}
		|  ]
		|}""".trimMargin()

		val originalSignatureFromOldKey1 = keyPair1.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey1Encoded = originalSignatureFromOldKey1.bytes.toBase58()

		val originalSignatureFromOldKey2 = keyPair2.private.sign(oldDocument.toByteArray(Charsets.UTF_8))
		val originalSignatureFromOldKey2Encoded = originalSignatureFromOldKey2.bytes.toBase58()

		val createInstruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey1Encoded"
		|	},
        |	{
		|	  "id": "$keyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$originalSignatureFromOldKey2Encoded"
		|	}
		|  ]
		|}""".trimMargin()

		createDID(DidEnvelope(createInstruction, oldDocument))
		mockNetwork.waitQuiescent()

		val newDocument = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$newKeyPairEncoded"
		|	}
		|  ]
		|}""".trimMargin()
		val signatureFromOldKey1 = keyPair1.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromOldKey1Encoded = signatureFromOldKey1.bytes.toBase58()

		val signatureFromNewKey = newKeyPair.private.sign(newDocument.toByteArray(Charsets.UTF_8))
		val signatureFromNewKeyEncoded = signatureFromNewKey.bytes.toBase58()
		val instruction = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromOldKey1Encoded"
		|	},
		|	{
		|	  "id": "$newKeyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$signatureFromNewKeyEncoded"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, newDocument)

		val flow = UpdateDidFlow(envelope)
		val future = originator.startFlow(flow)
		assertFailsWith<TransactionVerificationException> { future.getOrThrow() }
	}

	@Test
	fun `SignedTransaction returned by the flow is signed by the did originator`() {
		val signedTx = updateDID(getDidStateForUpdateOperation().envelope)!!
		signedTx.verifySignaturesExcept(listOf(w1.info.singleIdentity().owningKey, w2.info.singleIdentity().owningKey))
	}

	@Test
	fun `flow throws DIDNotFound exception for invalid did`() {
		val flow = UpdateDidFlow(getDidStateForUpdateOperation().envelope)
		val future = originator.startFlow(flow)
		mockNetwork.waitQuiescent()
		assertFailsWith<DIDNotFoundException> { future.getOrThrow() }
	}
}