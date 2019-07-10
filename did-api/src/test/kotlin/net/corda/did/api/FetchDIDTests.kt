package net.corda.did.api

import org.junit.Before
import org.junit.Test
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.io.FileInputStream
import java.util.Properties

/**
 * @property[mockMvc] MockMvc Class instance used for testing the spring API.
 * @property[mainController] The API controller being tested
 * @property[apiUrl] The url where the api will be running
 * */
class FetchDIDAPITest {
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
	 * This test will try to fetch a DID that does not exist.
	 * */
	@Test
	fun `Fetch a DID that does not exist`() {
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "did:corda:tcn:6aaa437d-b62a-4170-b357-7a1c5ede2364")).andExpect(MockMvcResultMatchers.status().isNotFound()).andReturn()

	}

	/**
	 * This test will try to fetch a DID with incorrect format.
	 * */
	@Test
	fun `Fetch a DID with incorrect format`() {
		mockMvc.perform(MockMvcRequestBuilders.get(apiUrl + "99")).andExpect(MockMvcResultMatchers.status().is4xxClientError()).andReturn()

	}

}