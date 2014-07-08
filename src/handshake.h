#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


void init_openssl(void);

int test_self_signed_ssl_certificate(void);

int test_ssl_certificate(void);
