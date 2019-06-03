/**
 * Persistent code
 *
 */
package net.corda.did.api

import net.corda.core.crypto.sign
import net.corda.core.utilities.toBase58
import net.corda.did.CryptoSuite
import net.i2p.crypto.eddsa.KeyPairGenerator
import org.junit.Before
import org.junit.Test
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.net.URI
import java.util.*
import java.io.FileInputStream

class DIDAPITest{
    lateinit var mockMvc: MockMvc
    lateinit var mainController : MainController
    lateinit var apiUrl:String

    @Before
    fun setup() {
        val prop = Properties()
        prop.load(FileInputStream(System.getProperty("user.dir")+"/config.properties"))
        apiUrl = prop.getProperty("apiUrl")
        val rpcHost = prop.getProperty("rpcHost")
        val rpcPort = prop.getProperty("rpcPort")
        val username = prop.getProperty("username")
        val password = prop.getProperty("password")
        val rpc = NodeRPCConnection(rpcHost,username,password,rpcPort.toInt())
        rpc.initialiseNodeRPCConnection()
        mainController = MainController(rpc)
        mockMvc = MockMvcBuilders.standaloneSetup(mainController).build()
    }
    @Test
    fun `Fetch a DID that does not exist`() {
        mockMvc.perform(MockMvcRequestBuilders.get(apiUrl+"did:corda:tcn:6aaa437d-b62a-4170-b357-7a1c5ede2364")).andExpect(status().isNotFound()).andReturn()

    }
    @Test
    fun `Create a DID` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().isOk()).andReturn()

    }
    @Test
    fun `Create API should return 400 if DID format is wrong` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()
        val uuid=UUID.randomUUID()
        val documentId="did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString().substring(0,2)).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()
    }
    @Test
    fun `Create API should return 400 if DID instruction is wrong` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()
        val uuid=UUID.randomUUID()
        val documentId="did:corda:tcn:"+uuid

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
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018",
		|	  "signatureBase58": "$encodedSignature1"
		|	}
		|  ]
		|}""".trimMargin()
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()

    }
    @Test
    fun `Create API should return 400 if document format is wrong` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

        val uri = URI("${documentId}#keys-1")

        val document = """{
		|  "@context": "https://w3id.org/did/v1",
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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()
    }
    @Test
    fun `Create  DID should return 409 is DID already exists` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().isOk()).andReturn()
        mockMvc.perform(builder).andExpect(status().isConflict()).andReturn()

    }
    @Test
    fun `Create a DID and fetch it` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().isOk()).andReturn()
        mockMvc.perform(MockMvcRequestBuilders.get(apiUrl+"did:corda:tcn:"+uuid.toString())).andExpect(status().isOk()).andReturn()

    }

    @Test
    fun `Create a DID with document being signed should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

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
        val alteredDocument="""{
		|  "@context": "https://w3id.org/did/v1",
		|  "id": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|  "created": "1970-01-01T00:00:00Z",
		|  "publicKey": [
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "did:corda:tcn:77ccbf5e-4ddd-4092-b813-ac06084a3eb0",
		|	  "publicKeyBase58": "$pub"
		|	}
		|  ]
		|}""".trimMargin()
        val signature1 = kp.private.sign(alteredDocument.toByteArray(Charsets.UTF_8))

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()

    }
    @Test
    fun `Create a DID with no signature should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

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
		|	  "type": "Ed25519Signature2018"
		|	}
		|  ]
		|}""".trimMargin()
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()

    }
    @Test
    fun `Create a DID should fail if document signed with wrong key` () {
        val kp = KeyPairGenerator().generateKeyPair()
        val kp2 = KeyPairGenerator().generateKeyPair()
        val pub = kp.public.encoded.toBase58()

        val uuid=UUID.randomUUID()

        val documentId="did:corda:tcn:"+uuid

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

        val signature1 = kp2.private.sign(document.toByteArray(Charsets.UTF_8))

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instruction).param("document",document)
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()

    }


    }