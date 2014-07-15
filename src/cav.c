#define _GNU_SOURCE
#include "cav.h"
#include <dlfcn.h>

//These typedefs just point to aliases with function types and arguments identical to the functions being hijacked.
typedef long (*orig_SSL_get_verify_result_f_type)(const SSL *ssl);
typedef int (*orig_do_handshake_f_type)(SSL *s);
typedef int (*orig_SSL_connect_f_type)(SSL *s);

long SSL_get_verify_result(const SSL *ssl) {
  //Our hijacked implementation
  printf("Hijacked SSL_get_verify_result\n");

  //Call the original SSL_Connect function from the SSL library. RTLD_NEXT simply looks at the
  //next library with a definition for SSL_Connect 
  orig_SSL_get_verify_result_f_type orig_SSL_get_verify_result;
  orig_SSL_get_verify_result = (orig_SSL_get_verify_result_f_type)dlsym(RTLD_NEXT,"SSL_get_verify_result");
  return orig_SSL_get_verify_result(ssl);

  return 0;
}

int SSL_do_handshake(SSL *s) {
  //our hijacked implementation
  printf("Hijacked SSL_do_handshake\n");

  //Call the original SSL_do_handshke function from the SSL library. RTLD_NEXT simply looks at the
  //next library with a definition for SSL_do_handshake 
  orig_do_handshake_f_type orig_do_handshake;
  orig_do_handshake = (orig_do_handshake_f_type)dlsym(RTLD_NEXT,"SSL_do_handshake");
  return SSL_do_handshake(s);

  return -1;
}

int SSL_connect(SSL *s) {  
  //our hijacked implementation
  printf("Hijacked SSL_connect\n");
  
  //Call the original SSL_Connect function from the SSL library. RTLD_NEXT simply looks at the
  //next library with a definition for SSL_Connect
  orig_SSL_connect_f_type orig_SSL_connect;
  orig_SSL_connect = (orig_SSL_connect_f_type)dlsym(RTLD_NEXT,"SSL_connect");
  return orig_SSL_connect(s);

  return 0;
}

