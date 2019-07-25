package com.persistent.did.api

import com.nimbusds.jose.jwk.OctetSequenceKey
import io.ipfs.multiformats.multibase.MultiBase
import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.core.utilities.toBase64
import net.corda.core.utilities.toHex
import net.corda.did.CryptoSuite
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.simple.JSONObject
import org.junit.Before
import org.junit.Test
import org.springframework.mock.web.MockMultipartFile
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.io.FileInputStream
import java.net.URI
import java.security.SecureRandom
import java.security.Security
import java.util.Base64
import java.util.Properties
import java.util.UUID

/**
 * @property[mockMvc] MockMvc Class instance used for testing the spring API.
 * @property[mainController] The API controller being tested
 * @property[apiUrl] The url where the api will be running
 * */
class UpdateDIDAPITest {
	lateinit var mockMvc: MockMvc
	lateinit var mainController: MainController
	lateinit var apiUrl: String

	@Before
	fun setup() {
		/**
		 * reading configurations from the config.properties file and setting properties of the Class
		 * */
		val prop = Properties()
		prop.load(FileInputStream(System.getProperty("user.dir") + "/config.properties"))
		apiUrl = prop.getProperty("apiUrl")
		val rpcHost = prop.getProperty("rpcHost")
		val rpcPort = prop.getProperty("rpcPort")
		val username = prop.getProperty("username")
		val password = prop.getProperty("password")
		val rpc = NodeRPCConnection(rpcHost, username, password, rpcPort.toInt())
		rpc.initialiseNodeRPCConnection()
		mainController = MainController(rpc)
		mockMvc = MockMvcBuilders.standaloneSetup(mainController).build()
	}

	/**
	 * This test will try to create a DID then update by adding new public key
	 * */
	@Test
	fun `Create a DID and update the document with new public key`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `Create a DID and update the document with new RSA public key`() {
		val kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.RSA.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.RSA.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.RSA.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "RsaSignature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `Create a DID and update the document with new ECDSA public key`() {
		Security.addProvider(BouncyCastleProvider())
		val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
		val g = java.security.KeyPairGenerator.getInstance("ECDSA", "BC")
		g.initialize(ecSpec, SecureRandom())
		val kp = g.generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		g.initialize(ecSpec, SecureRandom())
		val kpNew = g.generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.EcdsaSecp256k1.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "EcdsaSignatureSecp256k1",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	/**
	 * This test will try to create a DID then update by adding new public key by signing payload using a single private key
	 * */

	@Test
	fun `Update document by using single private key to sign multiple public keys should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by adding new public key and replacing original public key with same key
	 * */

	@Test
	fun `Updating original public keys of a document should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by using create command instead of update
	 * */
	@Test
	fun `Calling an update operation with create command should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by using wrong document format
	 * */

	@Test
	fun `Update should fail for incorrect document format`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "created": "1970-01-01T00:00:00Z",
        |  "id": "${documentId}",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by using wrong instruction format
	 * */
	@Test
	fun `Update should fail if instruction format is incorrect`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update no missing public key
	 * */

	@Test
	fun `Create a DID and update the document with missing public key`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by not providing signature
	 * */
	@Test
	fun `Create a DID and update the document with missing signature`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by replacing all public keys with new ones
	 * */
	@Test
	fun `Update the document with all new public keys should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew1 = KeyPairGenerator().generateKeyPair()
		val kpNew2 = KeyPairGenerator().generateKeyPair()
		val pubNew1 = kpNew1.public.encoded.toBase58()
		val pubNew2 = kpNew2.public.encoded.toBase58()
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew1"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew2"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kpNew1.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew2.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to  update a  DIDdocument that does not exist
	 * */
	@Test
	fun `Update a DID that does not exist should fail`() {

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid
		val kp = KeyPairGenerator().generateKeyPair()
		val uri = URI("${documentId}#keys-1")
		val pub = kp.public.encoded.toBase58()
		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isNotFound())

	}

	/**
	 * This test will try to create a DID then update with same id for all public keys
	 * */
	@Test
	fun `Update of a document with wrong uri should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update without context field
	 * */
	@Test
	fun `Update of a document without context should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	/**
	 * This test will try to create a DID then update by replacing old public key with new public key
	 * */
	@Test
	fun `Create a DID and update the document with a single public key`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	/**
	 * This test will try to create a DID then update by sending wrong did as request parameter
	 * */
	@Test
	fun `Update the document with mismatching DID should fail`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase58()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + UUID.randomUUID().toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

	@Test
	fun `Create a DID and update the document using base64 encoding`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase64()
		val pubOld = kp.public.encoded.toBase64()
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase64": "$pubOld"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase64": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase58()
		val encodedSignature2New = signature2New.bytes.toBase64()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `Create a DID and update the document using Hex encoding`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toHex()
		val pubOld = kp.public.encoded.toHex()
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyHex": "$pubOld"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyHex": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase64()
		val encodedSignature2New = signature2New.bytes.toBase64()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `Create a DID and update the document using PEM encoding`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()
		val encoder = Base64.getEncoder()
		val keyBegin = "-----BEGIN PUBLIC KEY-----"
		val keyEnd = "-----END PUBLIC KEY-----"
		val pubOld = keyBegin + String(encoder.encode(kp.public.encoded)) + keyEnd
		val pubNew = keyBegin + String(encoder.encode(kpNew.public.encoded)) + keyEnd
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyPem": "$pubOld"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyPem": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase64()
		val encodedSignature2New = signature2New.bytes.toBase64()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `Create a DID and update the document using Multibase encoding`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubOld = MultiBase.encode(MultiBase.Base.BASE32, kp.public.encoded)
		val pubNew = MultiBase.encode(MultiBase.Base.BASE32, kpNew.public.encoded)
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyMultibase": "$pubOld"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyMultibase": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase64()
		val encodedSignature2New = signature2New.bytes.toBase64()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `Create a DID and update the document using JWK encoding`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val eddsaJWKOld = OctetSequenceKey.Builder(kp.public.encoded).build()
		val pubOld = JSONObject.escape(eddsaJWKOld.toString())
		val eddsaJWKNew = OctetSequenceKey.Builder(kpNew.public.encoded).build()
		val pubNew = JSONObject.escape(eddsaJWKNew.toString())
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyJwk": "$pubOld"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyJwk": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase64()
		val encodedSignature2New = signature2New.bytes.toBase64()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isOk()).andExpect(MockMvcResultMatchers.content().json(documentNew)).andReturn()

	}

	@Test
	fun `update fails for invalid encoding`() {
		val kp = KeyPairGenerator().generateKeyPair()

		val pub = kp.public.encoded.toBase58()

		val uuid = UUID.randomUUID()

		val documentId = "did:corda:tcn:" + uuid

		val uri = URI("${documentId}#keys-1")

		val document = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1 = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignature1 = signature1.bytes.toBase58()

		val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
		val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
		val builder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
			request.method = "PUT"
			request
		}
		val result = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

		/* update test*/
		val kpNew = KeyPairGenerator().generateKeyPair()

		val eddsaJWKOld = OctetSequenceKey.Builder(kp.public.encoded).build()
		val pubOld = JSONObject.escape(eddsaJWKOld.toString())
		val eddsaJWKNew = OctetSequenceKey.Builder(kpNew.public.encoded).build()
		val pubNew = JSONObject.escape(eddsaJWKNew.toString())
		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-02T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase64": "$pubOld"
		|	},
        | {
		|	  "id": "$uriNew",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyJwk": "$pubNew"
		|	}
		|  ]
		|}""".trimMargin()

		val signature1New = kp.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val signature2New = kpNew.private.sign(documentNew.toByteArray(Charsets.UTF_8))
		val encodedSignature1New = signature1New.bytes.toBase64()
		val encodedSignature2New = signature2New.bytes.toBase64()
		val instructionNew = """{
		|  "action": "update",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature1New"
		|	},
		|	{
		|	  "id": "$uriNew",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase64": "$encodedSignature2New"
		|	}
		|  ]
		|}""".trimMargin()
		val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).param("instruction", instructionNew).param("document", documentNew)
		val resultUpdate = mockMvc.perform(updateBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultUpdate)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}

}
