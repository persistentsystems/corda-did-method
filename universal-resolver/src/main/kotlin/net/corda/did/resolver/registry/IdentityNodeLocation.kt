package net.corda.did.resolver.registry

data class IdentityNodeLocation(
		val host: String,
		val port: Int?
)