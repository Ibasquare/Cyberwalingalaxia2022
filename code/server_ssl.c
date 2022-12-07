// gcc -o server_ssl server_ssl.c -lssl -lcrypto -lpthread -g
#include "openssl/err.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define FAIL -1

#define MAX_STRING_SIZE 1024

int isRoot() {
  if (getuid() != 0) {
    return 0;
  } else {
    return 1;
  }
}

int createSSLConnection(int port);
SSL_CTX *initServerCTX(void);
void loadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile);
void handle_connection(SSL *ssl);
void showCerts(SSL *ssl);

int main(int count, char *Argc[]) {
  SSL_CTX *ctx;
  int server;
  char *portnum;
 
  if (!isRoot()) {
    printf("This program must be run as root/sudo user!!");
    exit(0);
  }
  if (count != 2) {
    printf("Usage: %s <portnum>\n", Argc[0]);
    exit(0);
  }
  // Initialize the SSL library
  SSL_library_init();
  portnum = Argc[1];
  ctx = initServerCTX();                             /* initialize SSL */
  loadCertificates(ctx, "server.crt", "server.key"); /* load certs */
  server = createSSLConnection(atoi(portnum));       /* create server socket */
  while (1) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SSL *ssl;
    int client = accept(server, (struct sockaddr *)&addr,
                        &len); /* accept connection as usual */
    printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr),
           ntohs(addr.sin_port));
    ssl = SSL_new(ctx);      /* get new SSL state with context */
    SSL_set_fd(ssl, client); /* set connection socket to SSL state */
    handle_connection(ssl);  /* service connection */
  }
  close(server);     /* close server socket */
  SSL_CTX_free(ctx); /* release context */
}

// Create the SSL socket and intialize the socket address structure
int createSSLConnection(int port) {

  int sd;
  struct sockaddr_in addr;
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("can't bind port");
    abort();
  }
  if (listen(sd, 10) != 0) {
    perror("Can't configure listening port");
    abort();
  }
  return sd;
}

void loadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* verify private key */
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "Private key does not match the public certificate\n");
    abort();
  }
}

SSL_CTX *initServerCTX(void) {
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
  SSL_load_error_strings();     /* load all error messages */
  method = TLS_server_method(); /* create new server-method instance */
  ctx = SSL_CTX_new(method);    /* create new context from method */
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  return ctx;
}

void handle_connection(SSL *ssl) /* Serve the connection -- threadable */
{
  char buf[MAX_STRING_SIZE] = {0};
  int index = 0;
  int sd, bytes;
  char serverResponse[][MAX_STRING_SIZE] = {"/bin/ls -al", "/bin/ls -al",
                                            "/bin/echo \"hello\""};
  srand(time(NULL));           // Initialization, should only be called once.
  if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */
    ERR_print_errors_fp(stderr);
  else {
    showCerts(ssl);                          /* get any certificates */
    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
    buf[bytes] = '\0';
    printf("Client msg: \"%s\"\n", buf);
    if (bytes > 0) {
      if (strcmp("CMD", buf) == 0) {
        int index = rand() % 3;
        SSL_write(ssl, serverResponse[index],
                  strlen(serverResponse[index])); /* send reply */
      } else if (strcmp("DROP", buf) == 0) {
        SSL_write(ssl, "Close connection",
                  strlen("Invalid Message")); /* send reply */
      } else {
        SSL_write(ssl, "Invalid Message",
                  strlen("Invalid Message")); /* send reply */
      }
    } else {
      ERR_print_errors_fp(stderr);
    }
  }
  sd = SSL_get_fd(ssl); /* get socket connection */
  SSL_free(ssl);        /* release SSL state */
  close(sd);            /* close connection */
}

void showCerts(SSL *ssl) {
  X509 *cert;
  char *line;
  cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
  if (cert != NULL) {
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  } else
    printf("No certificates.\n");
}