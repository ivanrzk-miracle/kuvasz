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

    init {
        // Configure SSL to trust all certificates as early as possible
        // This must happen before any HTTP clients are created
        configureTrustAllSSL()
    }

    /**
     * Configures the JVM and Netty to trust all certificates
     * This is called during bean initialization to ensure it happens early
     */
    private fun configureTrustAllSSL() {
        logger.info("Configuring SSL to accept all certificates for uptime checks")
        
        val trustAllCerts = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            }
        )
        
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, trustAllCerts, java.security.SecureRandom())
        }
        
        // Set as default for the entire JVM
        javax.net.ssl.SSLContext.setDefault(sslContext)
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.socketFactory)
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
        
        // Also set system properties that Netty might use
        System.setProperty("io.netty.handler.ssl.util.InsecureTrustManagerFactory", "true")
        
        logger.info("SSL configured to trust all certificates")
    }

    /**
     * Creates a TrustManager that accepts all certificates (including expired/invalid ones).
     * This allows uptime checks to work even with self-signed or expired certificates,
     * while SSL certificate expiry monitoring will still report the actual certificate status.
     */
    @Bean
    @Primary
    @Singleton
    fun trustAllSslContext(): SSLContext {
        logger.info("Creating SSL context bean to accept all certificates for uptime checks")
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

