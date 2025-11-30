package com.kuvaszuptime.kuvasz.config

import io.micronaut.context.annotation.Bean
import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Primary
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
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

    /**
     * Creates a Netty SslContext that accepts all certificates (including expired/invalid ones).
     * This is used by Micronaut's Netty-based HTTP client for uptime checks.
     * 
     * Note: Micronaut may not automatically use this bean. We also set the default SSL context
     * in HttpCheckerClientConfiguration to ensure it's applied.
     */
    @Bean
    @Primary
    @Singleton
    fun trustAllNettySslContext(): SslContext {
        logger.info("Configuring Netty SSL context to accept all certificates for uptime checks")
        val sslContext = SslContextBuilder
            .forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        
        // Also set as system property for Netty to pick up
        System.setProperty("io.netty.handler.ssl.util.InsecureTrustManagerFactory", "true")
        
        return sslContext
    }
}

