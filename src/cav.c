#include "cav.h"

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
  return 0;
}

