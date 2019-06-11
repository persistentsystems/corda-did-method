package net.corda.did.api
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
import java.util.*

class DeleteDIDAPITest {
    lateinit var mockMvc: MockMvc
    lateinit var mainController: MainController
    lateinit var apiUrl: String

    @Before
    fun setup() {
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

    @Test
    fun ` Create DID and Delete it` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid = UUID.randomUUID()

        val documentId = "did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        mockMvc.perform(builder).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

        val documentDelete = """{
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

        val signatureDelete = kp.private.sign(documentDelete.toByteArray(Charsets.UTF_8))

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
        val documentDeletejsonFile = MockMultipartFile("document", "", "application/json", documentDelete.toByteArray())
        val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionDeletejsonFile).file(documentDeletejsonFile).with { request ->
            request.method = "DELETE"
            request
        }
        mockMvc.perform(deleteBuilder).andExpect(MockMvcResultMatchers.status().isOk())


    }

    @Test
    fun `Delete a DID and then update should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid = UUID.randomUUID()

        val documentId = "did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        mockMvc.perform(builder).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

        val documentDelete = """{
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

        val signatureDelete = kp.private.sign(documentDelete.toByteArray(Charsets.UTF_8))

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
        val documentDeletejsonFile = MockMultipartFile("document", "", "application/json", documentDelete.toByteArray())
        val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionDeletejsonFile).file(documentDeletejsonFile).with { request ->
            request.method = "DELETE"
            request
        }
        mockMvc.perform(deleteBuilder).andExpect(MockMvcResultMatchers.status().isOk())


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
        val updateBuilder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).param("instruction",instructionNew).param("document",documentNew)
        mockMvc.perform(updateBuilder).andExpect(MockMvcResultMatchers.status().isNotFound())



    }

    @Test
    fun `Delete a DID and then fetch should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid = UUID.randomUUID()

        val documentId = "did:corda:tcn:"+uuid

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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        mockMvc.perform(builder).andExpect(MockMvcResultMatchers.status().isOk()).andReturn()

        val documentDelete = """{
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

        val signatureDelete = kp.private.sign(documentDelete.toByteArray(Charsets.UTF_8))

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
        val documentDeletejsonFile = MockMultipartFile("document", "", "application/json", documentDelete.toByteArray())
        val deleteBuilder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionDeletejsonFile).file(documentDeletejsonFile).with { request ->
            request.method = "DELETE"
            request
        }
        mockMvc.perform(deleteBuilder).andExpect(MockMvcResultMatchers.status().isOk())
        mockMvc.perform(MockMvcRequestBuilders.get(apiUrl+"did:corda:tcn:"+uuid.toString())).andExpect(MockMvcResultMatchers.status().isNotFound()).andReturn()



    }
}