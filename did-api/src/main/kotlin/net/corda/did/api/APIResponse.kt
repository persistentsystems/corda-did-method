package net.corda.did.api

import net.corda.did.state.DidState

data class ApiResponse (

     var message: String? = null


)

fun ApiResponse.toResponseObj(): ApiResponse {

    return ApiResponse(
            message.toString()
    )
}

fun DidState.toResponseObj():DidState{
    return DidState(
        envelope,
        originator,
        witnesses,
        status,
        linearId,
        participants

    )
}