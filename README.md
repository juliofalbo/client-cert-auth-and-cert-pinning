# Client Certification Authentication + Certification Pinning Implementation

## TL;DR
#### Blocked Certificates:
- client1
- client2

#### Allowed Certificates:
- client3
- client4

## What is a Client Certification Authentication?

Client Certificate Authentication is a mutual certificate based authentication, where the client provides its Client Certificate to the Server to prove its identity. This happens as a part of the SSL Handshake (it is optional).

So, it is a way to ensure that your server will only accept requests from a known clients. 
Basically the server will know the certificates (or only the CA) of the clients and will only allow the HTTPS connection if the client certificate sent matches with the certificates or CA that it trusted.

In our scenario we are saying that my webserver (in our case Nginx) will only accept requests sent with the certificate issued from a trusted CA (nginx.conf#ssl_client_certificate).

Read more: 
- https://techcommunity.microsoft.com/t5/iis-support-blog/client-certificate-authentication-part-1/ba-p/324623#:~:text=Client%20Certificate%20Authentication%20is%20a,Handshake%20(it%20is%20optional).
- https://textslashplain.com/2020/05/04/client-certificate-authentication/
- https://freedomben.medium.com/what-is-mtls-and-how-does-it-work-9dcdbf6c1e41

## What is a Certification Pinning?
Certificate Pinning restricts which certificates are considered valid for a particular website, limiting risk. Instead of allowing any trusted certificate to be used, the client will “pin” the certificate authority (CA) issuer(s), public keys or even end-entity certificates of their choice, any other certificate that isn't in the allowed-list will be blocked and the TLS connection will be terminated.

In our case we are using Certification Pinning to ensure that our client is receiving the HTTPS response from a known server.
With that we can cover the HTTPS request/response security and avoiding Man-in-the-Middle attacks (or making it harder to be done).

Reade more:
- https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
- https://carvesystems.com/news/cert_pin/
- [PT-BR] https://cryptoid.com.br/banco-de-noticias/o-que-e-o-certificate-ou-public-key-pinning-e-qual-a-sua-importancia/

### What are we pinning?
In this implementation I'm using the certificate fingerprint and pinning only his base64. It is easier than loading the certificate file and converting to DER format to compare, we actually don't need the server certificate public key, just his fingerprint.

## Generation your own certificates
The password for the generated certificates is `julio`, but if you want to play around by yourself, you can find the scripts to generate and test the certificates over Nginx in `./scripts/generate_certs_and_curl.txt`