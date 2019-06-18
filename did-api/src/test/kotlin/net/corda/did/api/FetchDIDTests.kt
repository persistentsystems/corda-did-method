package net.corda.did.api
import org.junit.Before
import org.junit.Test
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.io.FileInputStream
import java.util.*
/**
 * Persistent code
 *
 */

class FetchDIDAPITest {
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
    fun `Fetch a DID that does not exist`() {
        mockMvc.perform(MockMvcRequestBuilders.get(apiUrl+"did:corda:tcn:6aaa437d-b62a-4170-b357-7a1c5ede2364")).andExpect(MockMvcResultMatchers.status().isNotFound()).andReturn()

    }
    @Test
    fun `Fetch a DID with incorrect format`() {
        mockMvc.perform(MockMvcRequestBuilders.get(apiUrl+"99")).andExpect(MockMvcResultMatchers.status().is4xxClientError()).andReturn()

    }

}