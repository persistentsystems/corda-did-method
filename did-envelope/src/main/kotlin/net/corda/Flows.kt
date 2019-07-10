package net.corda

import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatingFlow

/**
 * Abstract initiating flow to fetch a did document from did-registry node.
 * Any flow that wishes to receive did document from a did-registry node has to sub-class this.
 *
 */
@InitiatingFlow
abstract class AbstractFetchDidDocumentFromRegistryNodeFlow<out T> : FlowLogic<T>()