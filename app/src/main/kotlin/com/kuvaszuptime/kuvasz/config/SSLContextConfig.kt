package com.kuvaszuptime.kuvasz.config

import io.micronaut.context.annotation.Bean
import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Primary
import jakarta.inject.Singleton
import org.slf4j.LoggerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

@Factory
class SSLContextConfig {

    private val logger = LoggerFactory.getLogger(SSLContextConfig::class.java)

    /**
     * Creates a TrustManager that accepts all certificates (including expired/invalid ones).
     * This allows uptime checks to work even with self-signed or expired certificates,
     * while SSL certificate expiry monitoring will still report the actual certificate status.
     */
    @Bean
    @Primary
    @Singleton
    fun trustAllSslContext(): SSLContext {
        logger.info("Configuring SSL context to accept all certificates for uptime checks")
        val trustAllCerts = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            }
        )
        
        return SSLContext.getInstance("TLS").apply {
            init(null, trustAllCerts, java.security.SecureRandom())
        }
    }
}

