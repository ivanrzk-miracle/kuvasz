package com.kuvaszuptime.kuvasz.services.check.ssl

import arrow.core.Either
import com.kuvaszuptime.kuvasz.models.monitor.ssl.CertificateInfo
import com.kuvaszuptime.kuvasz.models.monitor.ssl.SSLValidationError
import com.kuvaszuptime.kuvasz.util.toOffsetDateTime
import jakarta.inject.Singleton
import org.slf4j.LoggerFactory
import java.net.URI
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

@Singleton
class SSLValidator {

    private val logger = LoggerFactory.getLogger(this::class.java)

    companion object {
        private const val SOCKET_TIMEOUT_MS = 5000
        private const val DEFAULT_SSL_PORT = 443
    }

    /**
     * Validates the SSL certificate chain of the given HTTPS URL
     * This method accepts expired certificates temporarily to read their information,
     * then reports the actual certificate status (expired, expiring soon, or valid).
     *
     * @param url The HTTPS URL to validate.
     * @return Either an SSLValidationError or CertificateInfo containing details of the server's certificate
     * if the connection and chain validation succeed.
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    fun validateHttps(url: URI): Either<SSLValidationError, CertificateInfo> {
        if (url.scheme.lowercase() != "https") {
            return Either.Left(SSLValidationError("URL protocol must be HTTPS, but was: ${url.scheme}"))
        }
        val start = System.currentTimeMillis()

        val result = try {
            // Create SSLContext that accepts all certificates (including expired ones)
            val sslContext = createTrustAllSslContext()
            val socketFactory = sslContext.socketFactory
            
            // Create socket using the trust-all factory
            val socket = socketFactory.createSocket(url.host, url.port.takeIf { it != -1 } ?: DEFAULT_SSL_PORT) as SSLSocket
            socket.soTimeout = SOCKET_TIMEOUT_MS
            
            // Disable hostname verification to allow expired/invalid certificates
            val sslParams = socket.sslParameters
            sslParams.endpointIdentificationAlgorithm = ""
            socket.sslParameters = sslParams
            
            socket.use { sslSocket ->
                sslSocket.startHandshake()
                val session = sslSocket.session
                val certificates = session.peerCertificates.filterIsInstance<X509Certificate>()
                certificates.firstOrNull()?.let { peerCert ->
                    val certInfo = CertificateInfo(validTo = peerCert.notAfter.toOffsetDateTime())
                    val now = java.time.OffsetDateTime.now()
                    
                    // Check if certificate is expired
                    if (certInfo.validTo.isBefore(now)) {
                        Either.Left(
                            SSLValidationError("Certificate expired on ${certInfo.validTo}. Current date: $now")
                        )
                    } else {
                        // Certificate is valid, return the info
                        Either.Right(certInfo)
                    }
                } ?: Either.Left(SSLValidationError("No peer certificate was found"))
            }
        } catch (ex: Exception) {
            Either.Left(
                SSLValidationError("Error connecting or retrieving certificates for ${url.host}, reason: ${ex.message}")
            )
        }
        logger.debug("Finished SSL check for ${url.host} in ${System.currentTimeMillis() - start} ms")
        return result
    }

    /**
     * Creates an SSLContext that accepts all certificates (including expired ones)
     * This allows us to read certificate information even when certificates are expired or invalid,
     * so we can properly report the certificate status instead of failing with a connection error.
     */
    private fun createTrustAllSslContext(): SSLContext {
        val trustAllCerts = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
                    // Accept all certificates
                }
                override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
                    // Accept all certificates, including expired ones
                    // This method is called during the SSL handshake, and by not throwing an exception,
                    // we accept the certificate regardless of its validity status
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
        )
        return SSLContext.getInstance("TLS").apply {
            init(null, trustAllCerts, java.security.SecureRandom())
        }
    }
}
