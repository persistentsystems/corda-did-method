package com.persistent.did.api

import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Before
import org.junit.Test
import org.springframework.mock.web.MockMultipartFile
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.io.FileInputStream
import java.net.URI
import java.util.Properties
import java.util.UUID

/**
 * @property[mockMvc] MockMvc Class instance used for testing the spring API.
 * @property[mainController] The API controller being tested
 * @property[apiUrl] The url where the api will be running
 * */
class DeleteDIDAPITest {
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

	/** This test will try to create a DID and then delete it*/
	@Test
	fun ` Create DID and Delete it`() {
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

		val signatureDelete = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignatureDelete = signatureDelete.bytes.toBase58()
		val instructionDelete = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignatureDelete"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionDeletejsonFile = MockMultipartFile("instruction", "", "application/json", instructionDelete.toByteArray())
		//val documentDeletejsonFile = MockMultipartFile("document", "", "application/json", documentDelete.toByteArray())
		val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionDeletejsonFile).with { request ->
			request.method = "DELETE"
			request
		}
		val resultDelete = mockMvc.perform(deleteBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultDelete)).andExpect(MockMvcResultMatchers.status().isOk())

	}

	/** This test will try to create a DID , delete it and then update it*/
	@Test
	fun `Delete a DID and then update should fail`() {
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

		val signatureDelete = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignatureDelete = signatureDelete.bytes.toBase58()
		val instructionDelete = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignatureDelete"
		|	}
		|  ]
		|}""".trimMargin()

		val instructionDeletejsonFile = MockMultipartFile("instruction", "", "application/json", instructionDelete.toByteArray())
		val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionDeletejsonFile).with { request ->
			request.method = "DELETE"
			request
		}
		val resultDelete = mockMvc.perform(deleteBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultDelete)).andExpect(MockMvcResultMatchers.status().isOk())

		val kpNew = KeyPairGenerator().generateKeyPair()

		val pubNew = kpNew.public.encoded.toBase58()

		val uriNew = URI("${documentId}#keys-2")

		val documentNew = """{
        |  "@context": "https://w3id.org/did/v1",
		|  "id": "${documentId}",
        |  "created": "1970-01-01T00:00:00Z",
		|  "updated": "1970-01-03T00:00:00Z",
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

	/** This test will try to create a DID ,delete it and fetch it*/
	@Test
	fun `Delete a DID and then fetch should fail`() {
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

		val signatureDelete = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignatureDelete = signatureDelete.bytes.toBase58()
		val instructionDelete = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignatureDelete"
		|	}
		|  ]
		|}""".trimMargin()

		val instructionDeletejsonFile = MockMultipartFile("instruction", "", "application/json", instructionDelete.toByteArray())
		val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionDeletejsonFile).with { request ->
			request.method = "DELETE"
			request
		}
		val resultDelete = mockMvc.perform(deleteBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultDelete)).andExpect(MockMvcResultMatchers.status().isOk())
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:" + uuid.toString())).andExpect(MockMvcResultMatchers.status().isNotFound()).andReturn()

	}

	/** This test will try to create a DID , delete it and then recreate it*/
	@Test
	fun `Recreating a deleted DID should fail`() {
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

		val signatureDelete = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignatureDelete = signatureDelete.bytes.toBase58()
		val instructionDelete = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignatureDelete"
		|	}
		|  ]
		|}""".trimMargin()

		val instructionDeletejsonFile = MockMultipartFile("instruction", "", "application/json", instructionDelete.toByteArray())
		val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + uuid.toString()).file(instructionDeletejsonFile).with { request ->
			request.method = "DELETE"
			request
		}
		val resultDelete = mockMvc.perform(deleteBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultDelete)).andExpect(MockMvcResultMatchers.status().isOk())
		val result2 = mockMvc.perform(builder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(result2)).andExpect(MockMvcResultMatchers.status().is4xxClientError()).andReturn()

	}

	/** This test will try to create a DID and then delete it with incorrect request parameter*/
	@Test
	fun `Delete it with incorrect DID as request parameter`() {
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

		val signatureDelete = kp.private.sign(document.toByteArray(Charsets.UTF_8))

		val encodedSignatureDelete = signatureDelete.bytes.toBase58()
		val instructionDelete = """{
		|  "action": "delete",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignatureDelete"
		|	}
		|  ]
		|}""".trimMargin()
		val instructionDeletejsonFile = MockMultipartFile("instruction", "", "application/json", instructionDelete.toByteArray())
		val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl + "did:corda:tcn:" + UUID.randomUUID().toString()).file(instructionDeletejsonFile).with { request ->
			request.method = "DELETE"
			request
		}
		val resultDelete = mockMvc.perform(deleteBuilder).andReturn()
		mockMvc.perform(MockMvcRequestBuilders.asyncDispatch(resultDelete)).andExpect(MockMvcResultMatchers.status().is4xxClientError())

	}
}