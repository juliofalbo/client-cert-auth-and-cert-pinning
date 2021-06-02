require 'rest-client'
require "base64"

ssl_client_cert = "certificates/client3.pem"
ssl_client_key = "certificates/client3.key"
key_pass = "julio"

ssl_ca_file = "certificates/ca.crt"

# Result of: openssl x509 -in ca.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
FINGERPRINT_SSL_SERVER_CERT_RECEIVED_PINNED = 'uQkVJEKVim6UUkpd+z629j3LI954/xRrMAAvVBcFLyc='

puts 'Request SSL Certificates:'
puts "ssl_client_cert: #{ssl_client_cert}"
puts "ssl_client_key: #{ssl_client_key}"
puts "key_pass: #{key_pass}"
puts "ssl_ca_file: #{ssl_ca_file}"

puts '...'

# Check if the fingerprint of the received cert from the sever matches to the pinned fingerprint
def same_fingerprint?(ref_cert)
  ref_cert_pk = ref_cert.public_key

  puts "Pinned fingerprint: #{FINGERPRINT_SSL_SERVER_CERT_RECEIVED_PINNED}"
  fingerprint_ssl_server_cert_received = Base64.encode64(OpenSSL::Digest::SHA256.new(ref_cert_pk.to_der).digest)
  puts "Received fingerprint: #{fingerprint_ssl_server_cert_received}"

  fingerprint_ssl_server_cert_received.strip == FINGERPRINT_SSL_SERVER_CERT_RECEIVED_PINNED
end

# verify_callback will be called once for every certificate in the chain,
# starting with the top level certificate and ending with the actual certificate
# presented by the server we are contacting. Returning false from that callback
# will terminate the TLS session. Exceptions within the block will be suppressed.
#
# Citing the Ruby OpenSSL docs:
#
# A callback for additional certificate verification. The callback is invoked
# for each certificate in the chain.
#
# The callback is invoked with two values. preverify_ok indicates if the verification
# was passed (true) or not (false). store_context is an OpenSSL::X509::StoreContext
# containing the context used for certificate verification.
#
# If the callback returns false verification is stopped.

def ssl_verify_callback(preverify_ok, cert_store)
  return false unless preverify_ok

  # We only want to verify once, and fail the first time the callback is invoked (as opposed to checking only the last time it's called).
  # Therefore we get at the whole authorization chain.
  # The end certificate is at the beginning of the chain (the certificate for the host we are talking to)
  end_cert = cert_store.chain[0]

  # Only perform the checks if the current cert is the end certificate in the chain.
  # We can compare using the DER representation (OpenSSL::X509::Certificate objects are not comparable).
  # If we don't di that, we are going to perform the verification many times - once per certificate in the chain of trust, which is wasteful
  return true unless end_cert.to_der == cert_store.current_cert.to_der

  # Perform the Certification Pinning using the fingerprints
  same_fingerprint?(end_cert)
end

begin

  # The value of ssl_verify_callback is assigned to Net::HTTP#verify_callback
  response = RestClient::Resource.new(
    'https://localhost?q=Foo',
    :ssl_client_cert => OpenSSL::X509::Certificate.new(File.read(ssl_client_cert)), # Part of the Client Certificate Validation
    :ssl_client_key => OpenSSL::PKey::RSA.new(File.read(ssl_client_key), key_pass), # Part of the Client Certificate Validation
    :ssl_ca_file => ssl_ca_file, # Part of the Client Certificate Validation
    :verify_ssl => OpenSSL::SSL::VERIFY_PEER, # Part of the Client Certificate Validation
    :ssl_verify_callback => lambda(&method(:ssl_verify_callback)) # Part of the Client Certificate Validation
  ).get

  puts "Response: #{response.code} - #{response.body}"
rescue RestClient::ExceptionWithResponse => e
  puts "Response: #{e.response.code} - #{e.response.body}" unless e.response.nil?
rescue => e
  puts "Error Message: #{e.message}"
end
