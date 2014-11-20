At the time of writing this, the Nessus server only supports TLS1.0.

Output via iSec's SSLyze tool:

```bash
(venv)chris:sslyze/ $ ./sslyze.py localhost:8834 --regular

 REGISTERING AVAILABLE PLUGINS
 -----------------------------

  PluginCompression
  PluginCertInfo
  PluginSessionResumption
  PluginChromeSha1Deprecation
  PluginOpenSSLCipherSuites
  PluginSessionRenegotiation
  PluginHeartbleed
  PluginHSTS

 CHECKING HOST(S) AVAILABILITY
 -----------------------------

   localhost:8834                      => ::1:8834

 SCAN RESULTS FOR LOCALHOST:8834 - ::1:8834
 ------------------------------------------

  * Deflate Compression:
      OK - Compression disabled

  * Session Renegotiation:
      Client-initiated Renegotiations:   OK - Rejected
      Secure Renegotiation:              OK - Supported

  * TLSV1_2 Cipher Suites:
      Server rejected all cipher suites.

  * Certificate - OCSP Stapling:
      NOT SUPPORTED - Server did not send back an OCSP response.

  * Session Resumption:
      With Session IDs:                  OK - Supported (5 successful, 0 failed, 0 errors, 5 total attempts).
      With TLS Session Tickets:          NOT SUPPORTED - TLS ticket not assigned.

  * TLSV1_1 Cipher Suites:
      Server rejected all cipher suites.

  * TLSV1 Cipher Suites:
      Preferred:
                 AES128-SHA                    -              128 bits

      Accepted:
                 AES256-SHA                    -              256 bits
                 AES128-SHA                    -              128 bits

  * SSLV3 Cipher Suites:
      Server rejected all cipher suites.

  * SSLV2 Cipher Suites:
      Undefined - An unexpected error happened:
                 RC4-MD5                             timeout - timed out
                 RC2-CBC-MD5                         timeout - timed out
                 IDEA-CBC-MD5                        timeout - timed out
                 EXP-RC4-MD5                         timeout - timed out
                 EXP-RC2-CBC-MD5                     timeout - timed out
                 DES-CBC3-MD5                        timeout - timed out
                 DES-CBC-MD5                         timeout - timed out
```