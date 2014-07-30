#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

long SSL_get_verify_result(const SSL *ssl);

int SSL_do_handshake(SSL *s);

int SSL_connect(SSL *s);

int verify_cert(SSL *s);

int verify_X509_cert_chain(STACK_OF(X509)* sk);

int verify_X509_cert(X509 * cert, X509_STORE * store);

int verify_callback(int ok, X509_STORE_CTX *stor);

int write_X509_to_BIO(X509 * cert, BIO * bio);

void handle_error(const char *file, int lineno, const char *msg);

