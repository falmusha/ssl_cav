#ifndef VERIFY_H
#define VERIFY_H


#include "util.h"
#include "cav_common.h"

extern char CA_DIR[256];
extern char CA_FILE[256];
extern char LOG_FILE[256];

int verify_X509_cert_chain(STACK_OF(X509)* sk);

int verify_X509_cert(X509 * cert, X509_STORE * store, STACK_OF(X509) * sk);

int verify_callback(int ok, X509_STORE_CTX *stor);

int verify_cert(const SSL *s);

#endif /* VERIFY_H */
