package net.corda.did.api

data class ApiResponse (

     var message: String? = null


)

fun ApiResponse.toResponseObj(): ApiResponse {

    return ApiResponse(
            message.toString()
    )
}
