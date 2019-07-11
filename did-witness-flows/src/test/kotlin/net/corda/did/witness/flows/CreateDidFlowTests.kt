package net.corda.did.witness.flows

import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CordaDid
import net.corda.did.CryptoSuite
import net.corda.did.DidEnvelope
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.did.utils.DIDAlreadyExistException
import net.corda.testing.core.singleIdentity
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Test
import java.net.URI
import kotlin.test.assertFailsWith



/**
 * Test cases for [CreateDidFlow]
 */
class CreateDidFlowTests : AbstractFlowTestUtils() {

	@Test
	fun `create new did successfully`() {
		// create did
		createDID(getDidStateForCreateOperation().envelope)!!.tx
		mockNetwork.waitQuiescent()

		// confirm did state with status as 'VALID' on all 3 nodes
		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}
	}

	@Test
	fun `DID creation succeeds for an envelope with multiple keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val keyPair2 = KeyPairGenerator().generateKeyPair()

		val encodedPubKey1 = keyPair1.public.encoded.toBase58()
		val encodedPubKey2 = keyPair2.public.encoded.toBase58()

		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")
		val keyUri2 = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey2"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = keyPair1.private.sign(document.toByteArray(Charsets.UTF_8))
		val signature2 = keyPair2.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()
		val encodedSignature2 = signature2.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	},
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)

		createDID(envelope)!!.tx
		mockNetwork.waitQuiescent()

		// confirm did state with status as 'VALID' on all 3 nodes
		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}
	}

	@Test
	fun `DID creation fails for an envelope with multiple signatures targeting the same key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uri = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))
		val signature2 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()
		val encodedSignature2 = signature2.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	},
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope clashing key IDs`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val keyPair2 = KeyPairGenerator().generateKeyPair()

		val encodedPubKey1 = keyPair1.public.encoded.toBase58()
		val encodedPubKey2 = keyPair2.public.encoded.toBase58()

		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey2"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = keyPair1.private.sign(document.toByteArray(Charsets.UTF_8))
		val signature2 = keyPair2.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()
		val encodedSignature2 = signature2.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope without keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [ ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [ ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope with fewer signatures than keys`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val keyPair1 = KeyPairGenerator().generateKeyPair()
		val keyPair2 = KeyPairGenerator().generateKeyPair()

		val encodedPubKey1 = keyPair1.public.encoded.toBase58()
		val encodedPubKey2 = keyPair2.public.encoded.toBase58()

		val keyUri1 = URI("${documentId.toExternalForm()}#keys-1")
		val keyUri2 = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri2",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey2"
		|	},
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$encodedPubKey1"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = keyPair1.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope using a non-Ed25519 key`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val ed25519KeyPair = KeyPairGenerator().generateKeyPair()

		// TODO moritzplatt 2019-02-18 -- this will become valid once the crypto suite limitation is removed
		val rsaKeyPair = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair()

		val ed25519PubKey = ed25519KeyPair.public.encoded.toBase58()
		val rsaPubKey2 = rsaKeyPair.public.encoded.toBase58()

		val ed25519keyUri = URI("${documentId.toExternalForm()}#keys-1")
		val rasKeyUri = URI("${documentId.toExternalForm()}#keys-2")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$rsaPubKey2"
		|	},
		|	{
		|	  "id": "$ed25519keyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ed25519PubKey"
		|	}
		|  ]
		|}""".trimMargin()

		val ed25519Signature = ed25519KeyPair.private.sign(document.toByteArray(Charsets.UTF_8))
		val rsaSignature = rsaKeyPair.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedEd25519Signature = ed25519Signature.bytes.toBase58()
		val encodedRsaSignature = rsaSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$ed25519keyUri",
		|	  "type": "${CryptoSuite.Ed25519.signatureID}",
		|	  "signatureBase58": "$encodedEd25519Signature"
		|	},
		|	{
		|	  "id": "$rasKeyUri",
		|	  "type": "${CryptoSuite.RSA.signatureID}",
		|	  "signatureBase58": "$encodedRsaSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope with mismatched crypto suites`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val ed25519KeyPair = KeyPairGenerator().generateKeyPair()
		val rsaKeyPair = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair()

		val ed25519PubKey = ed25519KeyPair.public.encoded.toBase58()

		val keyUri = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$ed25519PubKey"
		|	}
		|  ]
		|}""".trimMargin()

		val rsaSignature = rsaKeyPair.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedRsaSignature = rsaSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${CryptoSuite.RSA.signatureID}",
		|	  "signatureBase58": "$encodedRsaSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope with invalid signature`() {
		val documentId = CordaDid.parseExternalForm("did:corda:tcn:${java.util.UUID.randomUUID()}").assertSuccess()

		val keyPair = KeyPairGenerator().generateKeyPair()

		val pubKeyBase58 = keyPair.public.encoded.toBase58()

		val keyUri = URI("${documentId.toExternalForm()}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId.toExternalForm()}",
		|  "publicKey": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId.toExternalForm()}",
		|	  "publicKeyBase58": "$pubKeyBase58"
		|	}
		|  ]
		|}""".trimMargin()

		val wrongSignature = keyPair.private.sign("nonsense".toByteArray(Charsets.UTF_8))
		val encodedWrongSignature = wrongSignature.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$keyUri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedWrongSignature"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)

		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails for an envelope with malformed instructions`() {
		val document = """{
		  "@context": "https://w3id.org/did/v1",
		  "id": "did:corda:tcn:f85c1782-4dd4-4433-b375-6218c7e53600",
		  "publicKey": [
			{
			  "id": "did:corda:tcn:f85c1782-4dd4-4433-b375-6218c7e53600#keys-1",
			  "type": "Ed25519VerificationKey2018",
			  "controller": "did:corda:tcn:f85c1782-4dd4-4433-b375-6218c7e53600",
			  "publicKeyBase58": "GfHq2tTVk9z4eXgyL5pXiwbd7iK9Xf6d13z8zQqD3ys5VFuTJk2VA1GQGjz6"
			}
		  ]
		}""".trimMargin()

		val instruction = "Bogus"

		assertFailsWith<java.lang.IllegalArgumentException> {
			val envelope = DidEnvelope(instruction, document)
			createDID(envelope)
		}
	}

	@Test
	fun `DID creation succeeds for an envelope with a created date only`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyFWjZCLwoH9C7qZb3KvhZVfj2J2wti62dnrH9Hv4HvxZG"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "3jSNdLMeFmsXKy6155d2xSvSzkRcTYSMpXHefYFmGvUg72N3SveezRNbyTaVqvaZ8nD5MA8zGbznWzXdt54e5k8H"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		createDID(envelope)
		mockNetwork.waitQuiescent()

		// confirm did state with status as 'VALID' on all 3 nodes
		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}
	}

	@Test
	fun `DID creation succeeds for an envelope with an update date only`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyL5csGiHtwEydbBvQF4VgygSjxWYUM5sE34qe5Sf2ALk5"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:7915fe51-6073-461e-b116-1fcb839c9118#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "g4MgSetbN2YsR4bZe4qDeoxDXgyBqKWyfh2UjoRm8wQPnEhQjEuV46ttzH7XGFViBkL9tenTg7tfaAs6j61AAFD"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		createDID(envelope)
		mockNetwork.waitQuiescent()

		// confirm did state with status as 'VALID' on all 3 nodes
		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}
	}

	@Test
	fun `DID creation fails for an envelope stating it was updated before it was created`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|  "created": "2019-01-02T00:00:00Z",
		|  "updated": "2019-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyTPxte7rrotCf1ueoXyJfRob7vTv9kGDhed6ESWnjLXav"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "2CDG4wegz92QBRAEdZsy4Wc4Tyij6FjnPKrDNcsaM73azWPPLy7vcSi2zyaP9Sqo4PNKWgw4YzY38f5HCpSEvLiL"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `DID creation fails if publicKey id does not contain did as prefix`() {
		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|  "created": "1970-01-01T00:00:00Z",
		|
		|  "publicKey": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91ea-4795883fa781#keys-1",
		|	  "type": "Ed25519VerificationKey2018",
		|	  "controller": "did:corda:tcn:11f4e420-95dc-4969-91eb-4795883fa781",
		|	  "publicKeyBase58": "GfHq2tTVk9z4eXgyTPxte7rrotCf1ueoXyJfRob7vTv9kGDhed6ESWnjLXav"
		|	}
		|  ]
		|}""".trimMargin()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "did:corda:tcn:11f4e420-95dc-4969-91ea-4795883fa781#keys-1",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "2CDG4wegz92QBRAEdZsy4Wc4Tyij6FjnPKrDNcsaM73azWPPLy7vcSi2zyaP9Sqo4PNKWgw4YzY38f5HCpSEvLiL"
		|	}
		|  ]
		|}""".trimMargin()

		val envelope = DidEnvelope(instruction, document)
		assertFailsWith<net.corda.core.contracts.TransactionVerificationException> { createDID(envelope) }
	}

	@Test
	fun `create did should fail if did already exist`() {
		// create did
		createDID(getDidStateForCreateOperation().envelope)!!.tx
		mockNetwork.waitQuiescent()

		// confirm did state with status as 'VALID' on all 3 nodes
		w1.transaction {
			val states = w1.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		w2.transaction {
			val states = w2.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		originator.transaction {
			val states = originator.services.vaultService.queryBy(DidState::class.java).states
			assert(states.size == 1)
			assert(states[0].state.data.status == DidStatus.ACTIVE)
		}

		assertFailsWith<DIDAlreadyExistException> { createDID(getDidStateForCreateOperation().envelope) }
	}

	@Test
	fun `SignedTransaction returned by the flow is signed by the did originator`() {
		val signedTx = createDID(getDidStateForCreateOperation().envelope)!!
		signedTx.verifySignaturesExcept(listOf(w1.info.singleIdentity().owningKey, w2.info.singleIdentity().owningKey))
	}
}