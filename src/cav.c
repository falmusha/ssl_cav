#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "cav.h"

#define CONFIG_FILE "/home/master/cavrc"
#define CA_FILE cavrc.ca_file
#define CA_DIR cavrc.ca_dir
#define CAV_LOG cavrc.log_file

#define MAX_LENGTH 1024

#define cav_error(msg) handle_error(__FILE__, __LINE__, msg)

//These typedefs just point to aliases with function types and arguments identical to the functions being hijacked.
typedef long (*orig_SSL_get_verify_result_f_type)(const SSL *ssl);
typedef int (*orig_do_handshake_f_type)(SSL *s);
typedef int (*orig_SSL_connect_f_type)(SSL *s);

struct config_opt {
  char ca_dir[32];
  char ca_file[32];
  char log_file[32];
};

struct config_opt cavrc;

long SSL_get_verify_result(const SSL *ssl) {

  printf("SSL_get_verify_result(): Hijacked\n");
  int err = 0; 

  //Is it a problem that a const value is being passed into veridy_cert?
  if (0 != (err = verify_cert(ssl))) {
    return err;
  } else {
    // Call the original SSL_get_verify_result from openssl
    // RTLD_NEXT simply looks at the next library with the method definition
    orig_SSL_get_verify_result_f_type orig_SSL_get_verify_result;
    orig_SSL_get_verify_result = (orig_SSL_get_verify_result_f_type)dlsym(RTLD_NEXT,"SSL_get_verify_result");
    return orig_SSL_get_verify_result(ssl);
  }
}

int SSL_do_handshake(SSL *s) {

  printf("SSL_do_handshake(): Hijacked\n");
  int err = 0; 
  if (0 != (err = verify_cert(s))) {
    return err;
  } 
  else {
    // Call the original SSL_do_handshake from openssl
    // RTLD_NEXT simply looks at the next library with the method definition 
    orig_do_handshake_f_type orig_do_handshake;
    orig_do_handshake = (orig_do_handshake_f_type) dlsym(RTLD_NEXT, "SSL_do_handshake");
    return orig_do_handshake(s);
  }
}

int init_config_file() {
  
  FILE * fp = NULL;
  char * buff = NULL;
  size_t buff_len;
  size_t bytes_read = 0;

  char * option = malloc(32);
  char * assignment = malloc(32);

  if (0 != (fp = fopen(CONFIG_FILE, "r"))) {
    while(!feof(fp)) {
      if(fscanf(fp, "%s %s", option, assignment) == 2){
        if(strcmp(option, "CA_DIR") == 0) {
          memcpy(cavrc.ca_dir, assignment, 32);
        }

        if(strcmp(option, "CA_FILE") == 0) {
          memcpy(cavrc.ca_file, assignment, 32);
        }

        if(strcmp(option, "LOG") == 0) {
          memcpy(cavrc.log_file, assignment, 32);
        }
      }
    }
  } else {
      printf("init_config_file(): error opening file\n");
  }

  printf("init_config_file(): CA_DIR = %s, CA_FILE = %s, LOG_FILE = %s\n", cavrc.ca_dir, cavrc.ca_file, cavrc.log_file);

  free(buff);
  free(option);
  free(assignment);

  fclose(fp);

  return 0; 
}

int verify_callback(int ok, X509_STORE_CTX * store) {


  FILE * fp = NULL;
  char buf[256];

  if (0 != (fp = fopen(CAV_LOG, "w"))) {
    printf("verify_callback(): failed to open file\n");
  }

  X509 * cert = X509_STORE_CTX_get_current_cert(store);

  if(!ok) {
    fprintf(stderr, "Callback Error: %s\n", X509_verify_cert_error_string(store->error));
    fprintf(fp, "Callback Error: %s\n", X509_verify_cert_error_string(store->error));
  }

  fprintf(stderr, "No Callback Error:\n");
  fprintf(fp, "No Callback Error:\n");

  X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
  fprintf(stderr, "\tissuer = %s\n", buf);
  fprintf(fp, "\tissuer = %s\n", buf);

  X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
  fprintf(stderr, "\tsubject = %s\n", buf);
  fprintf(fp, "\tsubject = %s\n", buf);

  fclose(fp);
  return ok; 
}

void handle_error(const char *file, int lineno, const char *msg) {
  fprintf(stderr, "CAV ERROR in %s:%i %s\n", file, lineno, msg); ERR_print_errors_fp(stderr);
}

int verify_cert(SSL *s) {

  init_config_file();
  int err = 0;

  // Find the peer certificate
  X509 * peer_cert = SSL_get_peer_certificate(s);
  if (NULL == peer_cert) {
    printf("verify_cert(): Certificate is not presented by peer\n");
    return (err = -1);
  }

  // Find the peer certificate chain
  STACK_OF(X509) * sk = SSL_get_peer_cert_chain(s);

  if (NULL == sk) {
    printf("verify_cert(): Certificate chain is not available\n");
    return (err = -1);
  }

  if (0 != (err = verify_X509_cert_chain(sk))) {
    printf("verify_cert(): Failed verify X509 certificate chain\n");
    return (err = -1);
  }

  return 0;
}

int verify_X509_cert_chain(STACK_OF(X509) * sk) {

  int err = 0;

  X509_STORE * store;

  /* create the cert store */
  if (!(store = X509_STORE_new())) {
    cav_error("Error creating X509_STORE_CTX object");
    return -1;
  }

  /* set the verify callback */
  X509_STORE_set_verify_cb_func(store, verify_callback);

  /* load the CA certificates and CRLs */
  if (X509_STORE_load_locations(store, NULL, CA_DIR) != 1) {
    cav_error("Error loading the CA file or directory"); 
    return -1;
  }

  unsigned len = sk_num(sk);
  unsigned i;

  X509 * cert;
  int verified = 0;

  for(i=0; i<len; i++) {

    cert = (X509 *) sk_value(sk, i);
    if (0 == (err = verify_X509_cert(cert, store))) {
      verified = 1;
      break;
    }

  }

  X509_STORE_free(store);

  if (verified) {
    return 0;
  } else {
    return (err = -1);
  }
}

int verify_X509_cert(X509 * cert, X509_STORE * store) {

  X509_STORE_CTX * verify_ctx;

  /* create a verification context and initialize it  */
  if (!(verify_ctx = X509_STORE_CTX_new())) {
    cav_error("Error creating X509_STORE_CTX object");
    return -1;
  }
  /* X509_STORE_CTX_init did not return an error conditionin prior versions */

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
  if (X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1) {
    cav_error("Error initializing verification context"); 
    return -1;
  }
#else
  X509_STORE_CTX_init(verify_ctx, store, cert, NULL);
#endif

  if (NULL == verify_ctx) {
    cav_error("Error initializing verification context is NULL"); 
  }

  /* verify the certificate */
  if (X509_verify_cert(verify_ctx) != 1) {
    cav_error("Error verifying the certificate");
    X509_STORE_CTX_free(verify_ctx);
    return -1;
  } else {
    printf("Certificate verified correctly!\n");
    X509_STORE_CTX_free(verify_ctx);
    return 0;
  }


}

void print_certificate(X509 * cert) {

  char subj[MAX_LENGTH+1  ];
  char issuer[MAX_LENGTH+1];

  X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
  X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);

  printf("certificate: %s\n", subj);
  printf("\tissuer: %s\n\n", issuer);

}

void print_stack(STACK_OF(X509) * sk) {

  unsigned len = sk_num(sk);
  unsigned i;

  X509 *cert;
  printf("Begin Certificate Stack:\n");
  for(i=0; i<len; i++) {
    cert = (X509*) sk_value(sk, i);
    print_certificate(cert);
  }
  printf("End Certificate Stack\n");
}

int write_X509_to_BIO(X509 * cert, BIO * bio) {

  if (!PEM_write_bio_X509(bio, cert)) {
    return -1;
  }

  return 0;
}
