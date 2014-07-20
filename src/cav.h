#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

long SSL_get_verify_result(const SSL *ssl);

int SSL_do_handshake(SSL *s);

int SSL_connect(SSL *s);

int verify_cert(SSL *s);
