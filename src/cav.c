#define _GNU_SOURCE
#include "cav.h"
#include <dlfcn.h>

//These typedefs just point to aliases with function types and arguments identical to the functions being hijacked.
typedef long (*orig_SSL_get_verify_result_f_type)(const SSL *ssl);
typedef int (*orig_do_handshake_f_type)(SSL *s);
typedef int (*orig_SSL_connect_f_type)(SSL *s);

long SSL_get_verify_result(const SSL *ssl) {

  printf("SSL_get_verify_result(): Hijacked\n");
  int err = 0; 
  if (0 != (err = verify_cert(ssl))) {
    return err;
  } else {
    // Call the original SSL_get_verify_result from openssl
    // RTLD_NEXT simply looks at the next library 
    // with a definition for SSL_get_verify_result 
    orig_SSL_get_verify_result_f_type orig_SSL_get_verify_result;
    orig_SSL_get_verify_result = (orig_SSL_get_verify_result_f_type)dlsym(RTLD_NEXT,"SSL_get_verify_result");
    return orig_SSL_get_verify_result(ssl);
  }

  return 0;
}

int SSL_do_handshake(SSL *s) {

  printf("SSL_do_handshake(): Hijacked\n");

  // Call the original SSL_do_handshake from openssl
  // RTLD_NEXT simply looks at the next library 
  // with a definition for SSL_do_handshake  
  orig_do_handshake_f_type orig_do_handshake;
  orig_do_handshake = (orig_do_handshake_f_type) dlsym(RTLD_NEXT, "SSL_do_handshake");
  return SSL_do_handshake(s);

  return -1;
}

int SSL_connect(SSL *s) {  

  printf("SSL_connect(): Hijacked\n");
  
  int err = 0; 
  if (0 != (err = verify_cert(s))) {
    return err;
  } else {
    // Call the original SSL_Connect from openssl
    // RTLD_NEXT simply looks at the next library 
    // with a definition for SSL_Connect
    orig_SSL_connect_f_type orig_SSL_connect;
    orig_SSL_connect = (orig_SSL_connect_f_type) dlsym(RTLD_NEXT, "SSL_connect");
    return orig_SSL_connect(s);
  }
}

int verify_cert(SSL *s) {

  // Find the peer certificate
  X509 * peer_cert = SSL_get_peer_certificate(s);
  if (NULL == peer_cert) {
    printf("verify_cert(): Certificate is not presented by peer\n");
    return -1;
  }

  printf("verify_cert(): Certificate is presented by peer\n");

  return 0;
}
