package net.corda

import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatingFlow

@InitiatingFlow
abstract class AbstractFetchDidDocumentFromRegistryNodeFlow<out T> : FlowLogic<T>()