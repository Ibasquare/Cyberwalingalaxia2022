// gcc -o client_ssl client_ssl.c -lssl -lcrypto -lpthread -g
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_STRING_SIZE 1024

int create_socket(char *url);
void execute(char *buf);
int verify_cert_time_valid(X509 *cert);
void cleanup(int server, SSL_CTX *ctx, SSL *ssl, X509 *cert);
void send_msg(SSL *ssl, const char *message);
void receive_msg(SSL *ssl, char *buf);

static void display(const char *buf) { printf("Received: \"%s\"\n", buf); }

int main() {

  char dest_url[] = "https://sauron.run.montefiore.ulg.ac.be";
  char buf[MAX_STRING_SIZE];

  X509 *cert = NULL;
  X509_NAME *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int ret, i;

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  if (SSL_library_init() < 0) {
    fprintf(stderr, "Could not initialize the OpenSSL library !\n");
    exit(1);
  }

  method = SSLv23_client_method();
  ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    fprintf(stderr, "Unable to create a new SSL context structure.\n");
    exit(1);
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  ssl = SSL_new(ctx);
  server = create_socket(dest_url);
  if (server != 0) {
    printf("Successfully made the TCP connection to: %s.\n", dest_url);
  }

  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) != 1) {
    fprintf(stderr, "Error: Could not build a SSL session to: %s.\n", dest_url);
    exit(1);
  }

  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    fprintf(stderr, "Error: Could not get a certificate from: %s.\n", dest_url);
  }

  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);
  if (!verify_cert_time_valid(cert)) {
    fprintf(stderr, "Certificat is expired");
    send_msg(ssl, "DROP");
    receive_msg(ssl, buf);
    cleanup(server, ctx, ssl, cert);
    exit(1);
  }

  send_msg(ssl, "CMD");
  receive_msg(ssl, buf);
  execute(buf);

  cleanup(server, ctx, ssl, cert);

  return (0);
}

void send_msg(SSL *ssl, const char *message) {
  int bytes;
  char *cmd = malloc(sizeof(char) * (strlen(message) + 1));
  if (!cmd) {
    fprintf(stderr, "failed to allocate memory");
    exit(1);
  }
  strcpy(cmd, message);

  bytes = SSL_write(ssl, cmd, strlen(cmd)); /* encrypt & send message */
  free(cmd);

  if (bytes <= 0) {
    fprintf(stderr, "failed to send message");
    exit(1);
  }
}

void receive_msg(SSL *ssl, char *buf) {
  int bytes;
  memset(buf, 0, MAX_STRING_SIZE);
  bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
  buf[bytes] = 0;
}

/* ---------------------------------------------------------- *
 * Free the structures we don't need anymore                  *
 * -----------------------------------------------------------*/
void cleanup(int server, SSL_CTX *ctx, SSL *ssl, X509 *cert) {
  SSL_free(ssl);
  close(server);
  X509_free(cert);
  SSL_CTX_free(ctx);
}

void execute(char *buf) {

  //TODO
  exit(1);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[]) {
  int sockfd;
  char hostname[256] = "";
  char portnum[6] = "443";
  char proto[6] = "";
  char *tmp_ptr = NULL;
  int port;
  struct hostent *host;
  struct sockaddr_in dest_addr;

  if (url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

  strncpy(proto, url_str, (strchr(url_str, ':') - url_str));

  strncpy(hostname, strstr(url_str, "://") + 3, sizeof(hostname));

  if (strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr + 1, sizeof(portnum));
    *tmp_ptr = '\0';
  }

  port = atoi(portnum);

  if ((host = gethostbyname(hostname)) == NULL) {
    fprintf(stderr, "Error: Cannot resolve hostname %s.\n", hostname);
    abort();
  }

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = *(long *)(host->h_addr);

  memset(&(dest_addr.sin_zero), '\0', 8);
  tmp_ptr = inet_ntoa(dest_addr.sin_addr);
  if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) ==
      -1) {
    fprintf(stderr, "Error: Cannot connect to host %s [%s] on port %d.\n",
            hostname, tmp_ptr, port);
    exit(1);
  }

  return sockfd;
}

int verify_cert_time_valid(X509 *cert) {
  time_t t;

  t = time(0);
  if (X509_cmp_time(X509_get_notBefore(cert), &t) > 0) {
    return -1;
  }

  if (X509_cmp_time(X509_get_notAfter(cert), &t) < 0) {
    return -1;
  }

  return 1;
}