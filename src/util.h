#ifndef UTIL_H
#define UTIL_H

int init_config_file(void);

int write_X509_to_BIO(X509 * cert, BIO * bio);

void handle_error(const char *file, int lineno, const char *msg);

void print_stack(STACK_OF(X509) * sk);

void print_certificate(X509 * cert);

#endif /* UTIL_H */
