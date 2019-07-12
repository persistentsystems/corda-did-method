package com.persistent.did.api

import org.springframework.boot.Banner
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

/**
 * A Spring Boot application.
 */

@SpringBootApplication

open class Server

/**
 * Starts our Spring Boot application.
 *
 */

/**
 * @param[args] Arguments passed to the spring boot server during initialization
 * */
fun main(args: Array<String>) {

	val app = SpringApplication(Server::class.java)
	app.setBannerMode(Banner.Mode.OFF)
	app.isWebEnvironment = true
	app.run(*args)

}
