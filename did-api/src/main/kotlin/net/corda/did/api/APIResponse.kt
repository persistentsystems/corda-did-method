package net.corda.did.api

/**
 * Class to turn the response string into a Response object
 *
 * @param[message] Takes a string message input
 * @return A proper message object which can then be sent as response
 * */
data class ApiResponse(val message: String?) {
	/** @param[apiMessage] Takes input of type APIMessage and passes the message as string to constructor
	 * */
	constructor(apiMessage: APIMessage) : this(apiMessage.message) {

	}
}

/**
 * Transforms the string message into a Response Object to be used by ResponseEntity class
 * */
fun ApiResponse.toResponseObj(): ApiResponse {

	return ApiResponse(
			message.toString()
	)
}
// ??? moritzplatt 2019-06-20 -- what purpose has this method? seems to do a `copy`?
//pranav 2019-06-27 removed as per comment
