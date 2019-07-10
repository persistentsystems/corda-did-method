package net.corda.did

/**
 * Enum with supported corda networks
 *
 * @property[CordaNetwork] Corda network
 * @property[CordaNetworkUAT] Corda UAT network
 * @property[Testnet] Corda test network
 */
enum class Network {
	CordaNetwork,
	CordaNetworkUAT,
	Testnet
}