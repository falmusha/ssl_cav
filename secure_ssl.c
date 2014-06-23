/* OpenSSL headers */

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


void init_openssl() {
  /* Initializing OpenSSL */
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

int main() {

  init_openssl();


  SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
  SSL * ssl;

  if (NULL == ctx) {
    printf("ctx is NULL\n");
    exit(1);
  }

  if(!SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL)) {
        // Failed to load trusted certificates from file
        printf("Fail on loading TrustStore.pem\n");
  }

  BIO *bio;

  // Create secure BIO object
  bio = BIO_new_ssl_connect(ctx);

  if (NULL == bio) {
    // BIO object creation failed
    printf("Failed to create the BIO object");
    exit(1);
  }

  // Get the SSL connection from bio struct to ssl
  BIO_get_ssl(bio, &ssl);
  // Set SSL_MODE_AUTO_RETRY flag to allow retrying ssl handshake
  // int the background
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  // Set up connection hostname and port
  BIO_set_conn_hostname(bio, "www.verisign.com:https");

  // Verify the connection opened and perform the handshake 
  if (BIO_do_connect(bio) <= 0) {
    // Connection failed
    ERR_print_errors_fp(stderr);
    BIO_free_all(bio);
    exit(1);
  }

  // Verify certificate
   if(SSL_get_verify_result(ssl) != X509_V_OK) {
     // Problem in certificate
     printf("CERTIFCATE IS BROKEN\n");
   }

  char *request = "GET / HTTP/1.1\x0D\x0AHost: www.verisign.com\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A";
  int request_len = strlen(request);

  // Send the request
  BIO_write(bio, request, request_len);

  char response[1024];
  int response_len = sizeof(response);

  // Read respone
  for(;;) {

    int bytes_read = BIO_read(bio, response, response_len);

    if (bytes_read == 0) {
      // Connection is closed
      break;
    } else if (bytes_read < 0) {
      // Error
      // Check if connection can be retried
      break;
      if (!BIO_should_retry(bio)) {
        // Cannot retry, handle failure
      }
      // Handle the the retry
    }

    // There is a response
    // Put null charecter at end of read bytes
    response[bytes_read] = '\0';
    printf("%s", response);

  }

  // Clean context structure
  SSL_CTX_free(ctx);

  /* To reuse the connection, use this line */
  /*BIO_reset(bio);*/

  /* To free it from memory, use this line */
  BIO_free_all(bio);

  return 0;
}
