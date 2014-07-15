#define _GNU_SOURCE
#include "cav.h"
#include <dlfcn.h>

typedef int (*orig_SSL_get_verify_result_f_type)(const SSL *ssl);
typedef int (*orig_do_handshake_f_type)(SSL *s);
typedef int (*orig_SSL_connect_f_type)(SSL *s);

long SSL_get_verify_result(const SSL *ssl) {
  printf("Hijacked SSL_get_verify_result\n");
  return 0;
}

int SSL_do_handshake(SSL *s) {
  printf("Hijacked SSL_do_handshake\n");
  return -1;
}

int SSL_connect(SSL *s) {
  printf("Hijacked SSL_connect\n");
  orig_SSL_connect_f_type orig_SSL_connect;
  return 0;
}

