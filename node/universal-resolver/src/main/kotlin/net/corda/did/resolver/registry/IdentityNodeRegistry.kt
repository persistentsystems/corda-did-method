package net.corda.did.resolver.registry

/**
 * TODO This should contain some cryptographic property that allows for validating the identity of the node
 */
interface IdentityNodeRegistry : Set<IdentityNodeLocation> {
	fun location(): IdentityNodeLocation
}

/**
 * A naïve static node registry, picking randomly from a static set of nodes every time a new location is requested.
 */
class StaticIdentityNodeRegistry(private val nodes: Set<IdentityNodeLocation>) : Set<IdentityNodeLocation> by nodes, IdentityNodeRegistry {
	override fun location(): IdentityNodeLocation = nodes.shuffled().first()
}