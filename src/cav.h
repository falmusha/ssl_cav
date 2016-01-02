#ifndef CAV_H
#define CAV_H

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

long SSL_get_verify_result(const SSL *ssl);

int SSL_do_handshake(SSL *s);

#endif /* CAV_H */
