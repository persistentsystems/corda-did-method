package corda.net.did.resolver.registry

data class IdentityNodeLocation(
        val host: String,
        val port: Int?
)