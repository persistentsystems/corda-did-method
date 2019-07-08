/**
 * Persistent code
 *
 */

/*
* The tests need a corda node to be running. The configuration can be found in config.properties
*
* */

// ??? moritzplatt 2019-06-20 -- Gradle is missing a dependency:
// `testCompile group: 'org.springframework.boot', name: 'spring-boot-test', version: '1.5.7.RELEASE'`

//TODO is there a way to mock a Corda node so it can be tested via these tests?

// ??? moritzplatt 2019-06-20 -- yes, using the Test Node Driver https://docs.corda.net/corda-api.html#public-api
// see this for an example:
// https://github.com/corda/samples/blob/0473ea84da6d96305af65dc5ec85120533931cbd/timesheet-example/workflows-kotlin/src/integrationTest/kotlin/com/example/DriverBasedTests.kt
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
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.net.URI
import java.util.*
import java.io.FileInputStream
import org.springframework.mock.web.MockMultipartFile
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch

/**
 * Persistent code
 *
 */
/**
 * @property[mockMvc] MockMvc Class instance used for testing the spring API.
 * @property[mainController] The API controller being tested
 * @property[apiUrl] The url where the api will be running
 * */
class CreateDIDAPITest{
    lateinit var mockMvc: MockMvc
    lateinit var mainController : MainController
    lateinit var apiUrl:String

    @Before
    fun setup() {
        /**
         * reading configurations from the config.properties file and setting properties of the Class
         * */
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
/**
 * This test will try to create a DID with no context field
 * */
    @Test
    fun `Create a DID with no context should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid = UUID.randomUUID()

        val documentId = "did:corda:tcn:"+uuid

        val uri = URI("${documentId}#keys-1")

        val document = """{
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()
    }
    /**
     * This test will try to create a DID with all the correct parameters
     * */
    @Test
    fun `Create a DID` () {
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().isOk()).andReturn()
    }
    /**
     * This test will try to create a DID with wrong DID format
     * */
    @Test
    fun `Create API should return 400 if DID format is wrong` () {
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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString().substring(0,2)).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()
    }
    /**
     * This test will try to create a DID with wrong instruction format
     * */
    @Test
    fun `Create API should return 400 if DID instruction is wrong` () {
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with wrong document format
     * */
    @Test
    fun `Create API should return 400 if document format is wrong` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()

        val uuid = UUID.randomUUID()

        val documentId = "did:corda:tcn:"+uuid

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
        val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
        val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()
    }
    /**
     * This test will try to create a DID which already exists
     * */
    @Test
    fun `Create  DID should return 409 is DID already exists` () {
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().isOk()).andReturn()
        val result2=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result2)).andExpect(status().isConflict()).andReturn()

    }
    /**
     * This test will try to create a DID and fetch it
     * */
    @Test
    fun `Create a DID and fetch it` () {
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().isOk()).andReturn()
        mockMvc.perform(MockMvcRequestBuilders.get(apiUrl+"did:corda:tcn:"+uuid.toString())).andExpect(status().isOk()).andExpect(content().json(document)).andReturn()

    }
    /**
     * This test will try to create a DID  and modify the document before sending without updating instruction
     * */
    @Test
    fun `Create a DID with altered document being signed should fail` () {
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
        val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
        val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with no signature
     * */
    @Test
    fun `Create a DID with no signature should fail` () {
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

        val instruction = """{
		|  "action": "create",
		|  "signatures": [
		|	{
		|	  "id": "$uri",
		|	  "type": "Ed25519Signature2018"
		|	}
		|  ]
		|}""".trimMargin()
        val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
        val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with document signed using wrong private key
     * */
    @Test
    fun `Create a DID should fail if document signed with wrong key` () {
        val kp = KeyPairGenerator().generateKeyPair()
        val kp2 = KeyPairGenerator().generateKeyPair()
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
        val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
        val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        val result = mockMvc.perform(builder).andReturn()
        mockMvc.perform( asyncDispatch(result)).andExpect( status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with multiple public keys mapping to same id.
     * */
    @Test
    fun `Create a DID with multiple public keys of same id should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()

        val pub = kp.public.encoded.toBase58()
        val kp2 = KeyPairGenerator().generateKeyPair()

        val pub2 = kp2.public.encoded.toBase58()

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
		|	},
		|	{
		|	  "id": "$uri",
		|	  "type": "${CryptoSuite.Ed25519.keyID}",
		|	  "controller": "${documentId}",
		|	  "publicKeyBase58": "$pub2"
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with no instruction .
     * */
    @Test
    fun `Create a DID with no instruction should fail` () {
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



        val instruction = "".trimMargin()
        val instructionjsonFile = MockMultipartFile("instruction", "", "application/json", instruction.toByteArray())
        val documentjsonFile = MockMultipartFile("document", "", "application/json", document.toByteArray())
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+uuid.toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }

        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with no document
     * */
    @Test
    fun `Create DID with no document should fail` () {
        val kp = KeyPairGenerator().generateKeyPair()


        val uuid = UUID.randomUUID()

        val documentId = "did:corda:tcn:"+uuid

        val uri = URI("${documentId}#keys-1")

        val document = "data".trimMargin()

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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with no DID parameter
     * */
    @Test
    fun `Create DID with no DID parameter should fail` () {
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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"").file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        mockMvc.perform(builder).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with no public key in the document
     * */
    @Test
    fun `Create  DID should fail if no public key is provided` () {
        val kp = KeyPairGenerator().generateKeyPair()

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
		|	  "controller": "${documentId}"
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
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()

    }
    /**
     * This test will try to create a DID with different DID as request parameter from the document
     * */
    @Test
    fun `Create a DID with incorrect DID in parameter` () {
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
        val builder = MockMvcRequestBuilders.fileUpload(apiUrl+"did:corda:tcn:"+UUID.randomUUID().toString()).file(instructionjsonFile).file(documentjsonFile).with { request ->
            request.method = "PUT"
            request
        }
        val result=mockMvc.perform(builder).andReturn()
        mockMvc.perform(asyncDispatch(result)).andExpect(status().is4xxClientError()).andReturn()
    }




    }