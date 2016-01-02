#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "cav_common.h"
#include "util.h"

#define MAX_LENGTH 1024

char CA_DIR[256];
char CA_FILE[256];
char LOG_FILE[256];

int init_config_file(void) {

  int props_read = 0;
  char path[1024];
  sprintf(path, "%s/%s", getenv("HOME"), ".cavrc" );

  DEBUG_PRINT("%s %s\n", "Looking for CAV configuration in", path);

  FILE * fp = NULL;

  if (0 != (fp = fopen(path, "r"))) {

    char * option = malloc(256);
    char * assignment = malloc(256);

    while(!feof(fp)) {

      if(fscanf(fp, "%s %s", option, assignment) == 2) {

        if(strcmp(option, "CA_DIR") == 0) {
          memcpy(CA_DIR, assignment, 256);
          props_read++;
        } else if(strcmp(option, "CA_FILE") == 0) {
          memcpy(CA_FILE, assignment, 256);
          props_read++;
        } else if(strcmp(option, "LOG") == 0) {
          memcpy(LOG_FILE, assignment, 256);
          props_read++;
        }

      }

    }

    free(option);
    free(assignment);
  } else {
    DEBUG_PRINT("%s %s\n", "Error opening file", path);
    exit(1);
  }

  DEBUG_PRINT("%s %s\n", "Loaded CAV configurations from", path);
  DEBUG_PRINT("%s %s\n", "CA_DIR =", CA_DIR);
  DEBUG_PRINT("%s %s\n", "CA_FILE =", CA_FILE);
  DEBUG_PRINT("%s %s\n", "LOG_FILE =", LOG_FILE);

  if (fp)
    fclose(fp);

  return (props_read == 3 ? 0 : -1);
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

void print_certificate(X509 * cert) {

  char subj[MAX_LENGTH+1  ];
  char issuer[MAX_LENGTH+1];

  X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
  X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);

  printf("certificate: %s\n", subj);
  printf("\tissuer: %s\n\n", issuer);
}
