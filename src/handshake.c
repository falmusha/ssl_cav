#include "handshake.h"

void init_openssl() {
  /* Initializing OpenSSL */
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

int test_self_signed_ssl_certificate() {
  return 0;
}

int test_ssl_certificate() {

  init_openssl();

  SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
  SSL * ssl;

  if (NULL == ctx) {
    printf("ctx is NULL\n");
    exit(1);
  }

  if(!SSL_CTX_load_verify_locations(ctx, NULL ,"/etc/ssl/certs")) {
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
  } else {
    printf("CERTIFCATE IS GOOD\n");
  }

  // Clean context structure
  SSL_CTX_free(ctx);

  /* To reuse the connection, use this line */
  /*BIO_reset(bio);*/

  /* To free it from memory, use this line */
  BIO_free_all(bio);

  return 0;
}

int main() {

  int err = test_ssl_certificate();

  if (err != 0) {
    exit(1);
  }
  return 0;
}
