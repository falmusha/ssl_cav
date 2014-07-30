#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "cav.h"

/*#define CA_FILE "/home/master/work/ssl_cav/src/ca-bundle.crt"*/
#define CA_DIR "/usr/lib/ssl/certs"
/*#define CRL_FILE "CRLfile.pem"*/

#define MAX_LENGTH 1024

#define cav_error(msg) handle_error(__FILE__, __LINE__, msg)

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

int verify_callback(int ok, X509_STORE_CTX * store) {

  char buf[256];
  if(!ok) {

    X509 * cert = X509_STORE_CTX_get_current_cert(store);

    fprintf(stderr, "Callback Error: %s\n", X509_verify_cert_error_string(store->error));
    X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
    fprintf(stderr, "\tissuer = %s\n", buf);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    fprintf(stderr, "\tsubject = %s\n", buf);

  }

  return ok; 
}

void handle_error(const char *file, int lineno, const char *msg) {
  fprintf(stderr, "CAV ERROR in %s:%i %s\n", file, lineno, msg); ERR_print_errors_fp(stderr);
}

int verify_cert(SSL *s) {

  int err = 0;

  // Find the peer certificate
  X509 * peer_cert = SSL_get_peer_certificate(s);
  if (NULL == peer_cert) {
    printf("verify_cert(): Certificate is not presented by peer\n");
    return (err = -1);
  }

  // Find the peer certificate chain
  STACK_OF(X509) * sk = SSL_get_peer_cert_chain(s);

  if (NULL == sk) {
    printf("verify_cert(): Certificate chain is not available\n");
    return (err = -1);
  }

  if (0 != (err = verify_X509_cert_chain(sk))) {
    printf("verify_cert(): Failed verify X509 certificate chain\n");
    return (err = -1);
  }

  return 0;
}

int verify_X509_cert_chain(STACK_OF(X509) * sk) {

  int err = 0;

  X509_STORE * store;

  /* create the cert store */
  if (!(store = X509_STORE_new())) {
    cav_error("Error creating X509_STORE_CTX object");
    return -1;
  }

  /* set the verify callback */
  X509_STORE_set_verify_cb_func(store, verify_callback);

  /* load the CA certificates and CRLs */
  if (X509_STORE_load_locations(store, NULL, CA_DIR) != 1) {
    cav_error("Error loading the CA file or directory"); 
    return -1;
  }

  if (X509_STORE_set_default_paths(store) != 1) {
    cav_error("Error loading the system-wide CA certificates");
    return -1;
  }

  unsigned len = sk_num(sk);
  unsigned i;

  X509 * cert;
  int verified = 0;

  for(i=0; i<len; i++) {

    cert = (X509 *) sk_value(sk, i);
    if (0 == (err = verify_X509_cert(cert, store))) {
      verified = 1;
      break;
    }

  }

  X509_STORE_free(store);

  if (verified) {
    return 0;
  } else {
    return (err = -1);
  }
}

int verify_X509_cert(X509 * cert, X509_STORE * store) {

  X509_STORE_CTX * verify_ctx;

  /* create a verification context and initialize it  */
  if (!(verify_ctx = X509_STORE_CTX_new())) {
    cav_error("Error creating X509_STORE_CTX object");
    return -1;
  }
  /* X509_STORE_CTX_init did not return an error conditionin prior versions */

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
  if (X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1) {
    cav_error("Error initializing verification context"); 
    return -1;
  }
#else
  X509_STORE_CTX_init(verify_ctx, store, cert, NULL);
#endif

  if (NULL == verify_ctx) {
    cav_error("Error initializing verification context is NULL"); 
  }

  /* verify the certificate */
  if (X509_verify_cert(verify_ctx) != 1) {
    cav_error("Error verifying the certificate");
    return -1;
  } else {
    printf("Certificate verified correctly!\n");
  }

  X509_STORE_CTX_free(verify_ctx);

  return 0;
}

void print_certificate(X509 * cert) {

  char subj[MAX_LENGTH+1  ];
  char issuer[MAX_LENGTH+1];

  X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
  X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);

  printf("certificate: %s\n", subj);
  printf("\tissuer: %s\n\n", issuer);

}

void print_stack(STACK_OF(X509) * sk) {

  unsigned len = sk_num(sk);
  unsigned i;

  X509 *cert;
  printf("Begin Certificate Stack:\n");
  for(i=0; i<len; i++) {
    cert = (X509*) sk_value(sk, i);
    print_certificate(cert);
  }
  printf("End Certificate Stack\n");
}

int write_X509_to_BIO(X509 * cert, BIO * bio) {

  if (!PEM_write_bio_X509(bio, cert)) {
    return -1;
  }

  return 0;
}
