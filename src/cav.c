#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "cav_common.h"
#include "verify.h"
#include "cav.h"

// These typedefs just point to aliases with function types and arguments
// identical to the functions being hijacked.
typedef long (*orig_SSL_get_verify_result_f_type)(const SSL *ssl);
typedef int (*orig_do_handshake_f_type)(SSL *s);
typedef int (*orig_SSL_connect_f_type)(SSL *s);


long SSL_get_verify_result(const SSL *ssl) {

  DEBUG_PRINT("%s\n","Hijacked");
  int err = 0;

  if (0 != (err = verify_cert(ssl))) {
    return err;
  } else {
    DEBUG_PRINT("%s\n","Return execution to OpenSSL");
    orig_SSL_get_verify_result_f_type orig_SSL_get_verify_result;
    orig_SSL_get_verify_result = (orig_SSL_get_verify_result_f_type)dlsym(RTLD_NEXT,"SSL_get_verify_result");
    return orig_SSL_get_verify_result(ssl);
  }
}

int SSL_do_handshake(SSL *s) {

  DEBUG_PRINT("%s\n","Hijacked");
  int err = 0;
  if (0 != (err = verify_cert(s))) {
    return err;
  } else {
    DEBUG_PRINT("%s\n","Return execution to OpenSSL");
    orig_do_handshake_f_type orig_do_handshake;
    orig_do_handshake = (orig_do_handshake_f_type) dlsym(RTLD_NEXT, "SSL_do_handshake");
    return orig_do_handshake(s);
  }
}
