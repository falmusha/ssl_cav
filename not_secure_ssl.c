/* OpenSSL headers */

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


void init_openssl() {
  /* Initializing OpenSSL */

  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

int main() {

  init_openssl();

  BIO *bio;

  // Create BIO object
  bio = BIO_new_connect("www.verisign.com:80");

  if (NULL == bio) {
    // BIO object creation failed
    printf("Failed to create the BIO object");
    exit(1);
  }

  if (BIO_do_connect(bio) <= 0) {
    // Connection failed
    ERR_print_errors_fp(stderr);
    BIO_free_all(bio);
    exit(1);
  }

  char *request = "GET / HTTP/1.1\x0D\x0AHost: www.verisign.com\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A";
  int request_len = strlen(request);

  // Send the request
  BIO_write(bio, request, request_len);

  char response[1024];
  int response_len = sizeof(response);

  // Read respone
  for(;;) {

    int bytes_read = BIO_read(bio, response, response_len);

    if (bytes_read == 0) {
      // Connection is closed
      break;
    } else if (bytes_read < 0) {
      // Error
      // Check if connection can be retried
      break;
      if (!BIO_should_retry(bio)) {
        // Cannot retry, handle failure
      }
      // Handle the the retry
    }

    // There is a response
    // Put null charecter at end of read bytes
    response[bytes_read] = '\0';
    printf("%s", response);

  }

  /* To reuse the connection, use this line */
  /*BIO_reset(bio);*/

  /* To free it from memory, use this line */
  BIO_free_all(bio);

  return 0;
}
