#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "util.h"
#include "verify.h"
#include "cav_common.h"

int verify_callback(int ok, X509_STORE_CTX * store) {

  X509 * cert = X509_STORE_CTX_get_current_cert(store);
  print_certificate(cert);

  return ok;
}

int verify_cert(const SSL *s) {

  init_config_file();
  int err = 0;

  // Find the peer certificate
  X509 * peer_cert = SSL_get_peer_certificate(s);
  if (NULL == peer_cert) {
    DEBUG_PRINT("%s\n", "Certificate is not presented by peer");
    return (err = -1);
  } else {
    DEBUG_PRINT("%s\n", "Found peer certificate");
  }

  // Find the peer certificate chain
  STACK_OF(X509) * sk = SSL_get_peer_cert_chain(s);

  if (NULL == sk) {
    DEBUG_PRINT("%s\n", "Certificate chain is not available");
    return (err = -1);
  } else {
    DEBUG_PRINT("%s\n", "Found peer certificate chain");
  }

  if (0 != (err = verify_X509_cert_chain(sk))) {
    DEBUG_PRINT("%s\n", "Failed to verify X509 certificate chain");
    return (err = -1);
  }

  DEBUG_PRINT("%s\n", "Successfully verified X509 certificate chain");

  return 0;
}

int verify_X509_cert_chain(STACK_OF(X509) * sk) {

  int err = 0;

  /* create the cert store */
  X509_STORE *store = X509_STORE_new();
  if (store == NULL) {
    DEBUG_PRINT("%s\n", "Unable to create new X509 store");
    return -1;
  } else {
    DEBUG_PRINT("%s\n", "Create new X509 store");
  }

  /* set the verify callback */
  /* X509_STORE_set_verify_cb_func(store, verify_callback); */

  int rc = X509_STORE_load_locations(store, NULL, CA_DIR);
  if (rc != 1) {
    DEBUG_PRINT("%s %s\n", "Unable to load certificates to store from ", CA_DIR);
    X509_STORE_free(store);
    return -1;
  } else {
    DEBUG_PRINT("%s %s\n", "Loaded certificates to store from ", CA_DIR);
  }

  /* iterate over the certificate chain */
  X509 * cert;
  int verified = 0;

  unsigned len = sk_num(sk);
  unsigned i;
  for(i=0; i<len; i++) {

    cert = (X509 *) sk_value(sk, i);

    verified = verify_X509_cert(cert, store, sk);
    if (verified == 0) {
      DEBUG_PRINT("%s %d\n", "Verified certificate in chain at index ", i);
    } else {
      DEBUG_PRINT("%s %d\n", "Failed to verify certificate in chain at index ",
          i);
      verified = -1;
      break;
    }

  }

  X509_STORE_free(store);

  return verified;
}

int verify_X509_cert(X509 * cert, X509_STORE * store, STACK_OF(X509) * sk) {

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();

  if (!ctx) {
    DEBUG_PRINT("%s\n", "Unable to create STORE CTX");
    return -1;
  } else {
    DEBUG_PRINT("%s\n", "Created STORE CTX");
  }

  if (X509_STORE_CTX_init(ctx, store, cert, sk) != 1) {
    DEBUG_PRINT("%s\n", "Unable to initialize STORE CTX");
    X509_STORE_CTX_free(ctx);
    return -1;
  } else {
    DEBUG_PRINT("%s\n", "Initlized STORE CTX");
  }

  int rc = X509_verify_cert(ctx);
  X509_STORE_CTX_free(ctx);

  if (rc == 1) {
    return 0;
  } else {
    return -1;
  }

}
