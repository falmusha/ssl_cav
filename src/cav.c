#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "cav.h"

//These typedefs just point to aliases with function types and arguments identical to the functions being hijacked.
typedef long (*orig_SSL_get_verify_result_f_type)(const SSL *ssl);
typedef int (*orig_do_handshake_f_type)(SSL *s);
typedef int (*orig_SSL_connect_f_type)(SSL *s);

long SSL_get_verify_result(const SSL *ssl) {

  printf("SSL_get_verify_result(): Hijacked\n");
  int err = 0; 

  //Is it a problem that a const value is being passed into veridy_cert?
  if (0 != (err = verify_cert(ssl))) {
    return err;
  } else {
    // Call the original SSL_get_verify_result from openssl
    // RTLD_NEXT simply looks at the next library with the method definition
    orig_SSL_get_verify_result_f_type orig_SSL_get_verify_result;
    orig_SSL_get_verify_result = (orig_SSL_get_verify_result_f_type)dlsym(RTLD_NEXT,"SSL_get_verify_result");
    return orig_SSL_get_verify_result(ssl);
  }
}

int SSL_do_handshake(SSL *s) {

  printf("SSL_do_handshake(): Hijacked\n");
  int err = 0; 
  if (0 != (err = verify_cert(s))) {
    return err;
  } 
  else {
  // Call the original SSL_do_handshake from openssl
  // RTLD_NEXT simply looks at the next library with the method definition 
  orig_do_handshake_f_type orig_do_handshake;
  orig_do_handshake = (orig_do_handshake_f_type) dlsym(RTLD_NEXT, "SSL_do_handshake");
  return orig_do_handshake(s);
   }
}


int SSL_connect(SSL *s) {  

  printf("SSL_connect(): Hijacked\n");
  
  int err = 0; 
  if (0 != (err = verify_cert(s))) {
    return err;
  } 
  else {
    // Call the original SSL_Connect from openssl
    // RTLD_NEXT simply looks at the next library with the method definition 
    orig_SSL_connect_f_type orig_SSL_connect;
    orig_SSL_connect = (orig_SSL_connect_f_type) dlsym(RTLD_NEXT, "SSL_connect");
    return orig_SSL_connect(s);
  }
}

int write_X509_to_BIO(X509 * cert, BIO * bio) {

  if (!PEM_write_bio_X509(bio, cert)) {
    /* Error */
    return -1;
  }

  return 0;
}


int verify_cert(SSL *s) {

  int err = 0;

  // Find the peer certificate
  X509 * peer_cert = SSL_get_peer_certificate(s);
  if (NULL == peer_cert) {
    printf("verify_cert(): Certificate is not presented by peer\n");
    return (err = -1);
  }

  // Initilize new BIO to write certifcate to
  BIO * bio = BIO_new(BIO_s_mem());
  
  if (NULL == bio) {
    printf("verify_cert(): Failed to allocate memory to BIO\n");
    return (err = -1);
  }

  if (0 != (err = write_X509_to_BIO(peer_cert, bio))) {
    printf("verify_cert(): Failed to fill BIO with X509 certificate\n");
    return -1;
  }

  printf("verify_cert(): Certificate is presented by peer\n");

  return 0;
}



#define CA_FILE "CAfile.pem"
#define CA_DIR "/etc/ssl"
#define CRL_FILE "CRLfile.pem"
#define CLIENT_CERT "cert.pem"

int verify_callback(int ok, X509_STORE_CTX *stor) {

  if(!ok) {

    fprintf(stderr, "Error: %s\n",
        X509_verify_cert_error_string(stor->error)
    );
  }

  return ok; 
}

void handle_error(const char *file, int lineno, const char *msg) {
  fprintf(stderr, "** %s:%i %s\n", file, lineno, msg); ERR_print_errors_fp(stderr);
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

int verify_X509_cert(X509 * cert) {

  /*X509           *cert;*/
  X509_STORE     *store;
  X509_LOOKUP    *lookup;
  X509_STORE_CTX *verify_ctx;
  FILE           *fp;

  /* first read the client certificate */
  if (!(fp = fopen(CLIENT_CERT, "r"))) {
    int_error("Error reading client certificate file");
    return -1;
  }

  // Read certifcate from BIO
  if (!(cert = PEM_read_X509(fp, NULL, NULL, NULL))) {
    int_error("Error reading client certificate in file");
    return -1;
  }

  fclose(fp);

  /* create the cert store and set the verify callback  */
  if (!(store = X509_STORE_new())) {
    int_error("Error creating X509_STORE_CTX object");
    return -1;
  }

  X509_STORE_set_verify_cb_func(store, verify_callback);

  /* load the CA certificates and CRLs */
  if (X509_STORE_load_locations(store, CA_FILE, CA_DIR) != 1) {
    int_error("Error loading the CA file or directory"); 
    return -1;
  }

  if (X509_STORE_set_default_paths(store) != 1) {
    int_error("Error loading the system-wide CA certificates");
    return -1;
  }

  if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))) {
    int_error("Error creating X509_LOOKUP object");
    return -1;
  }

  if (X509_load_crl_file(lookup, CRL_FILE, X509_FILETYPE_PEM) != 1) {
    int_error("Error reading the CRL file");
    return -1;
  }

  /* enabling verification against CRLs is not possible in prior versions */
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
  /* set the flags of the store so that CRLs are consulted */
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif

  /* create a verification context and initialize it  */
  if (!(verify_ctx = X509_STORE_CTX_new())) {
    int_error("Error creating X509_STORE_CTX object");
    return -1;
  }
  /* X509_STORE_CTX_init did not return an error conditionin prior versions */

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
  if (X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1) {
    int_error("Error initializing verification context"); 
    return -1;
  }
#else
  X509_STORE_CTX_init(verify_ctx, store, cert, NULL);
#endif

  /* verify the certificate */
  if (X509_verify_cert(verify_ctx) != 1) {
    int_error("Error verifying the certificate");
    return -1;
  } else {
    printf("Certificate verified correctly!\n");
  }

  return 0;
}
