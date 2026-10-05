// SPDX-License-Identifier: MIT
// v1240_client_musl.c — run as the agent by test_v1240.sh, built statically
// with musl (musl-gcc -static): musl's resolver reads /etc/hosts itself, then
// /etc/resolv.conf, and has no nsswitch. Prints "OK|ERR <case> <detail> <ms>".
//
//   v1240_client_musl <port>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static long ms_since(const struct timeval *t0) {
    struct timeval t1;
    gettimeofday(&t1, NULL);
    return (t1.tv_sec - t0->tv_sec) * 1000 + (t1.tv_usec - t0->tv_usec) / 1000;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *port = argv[1];
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *ai = NULL;
    struct timeval t0;

    gettimeofday(&t0, NULL);
    int rc = getaddrinfo("api.example.com", port, &hints, &ai);
    char a[INET_ADDRSTRLEN] = "";
    if (rc == 0) inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, a, sizeof a);
    printf("%s resolve %s %ld\n", rc == 0 ? "OK" : "ERR", rc == 0 ? a : gai_strerror(rc), ms_since(&t0));

    gettimeofday(&t0, NULL);
    int ok = 0;
    if (rc == 0) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0 && connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            const char req[] = "GET / HTTP/1.0\r\nHost: api.example.com\r\n\r\n";
            char buf[64] = "";
            if (write(s, req, sizeof req - 1) == (ssize_t)(sizeof req - 1) && read(s, buf, sizeof buf - 1) > 12)
                ok = !strncmp(buf, "HTTP/1.0 200", 12) || !strncmp(buf, "HTTP/1.1 200", 12);
        }
        if (s >= 0) close(s);
        freeaddrinfo(ai);
    }
    printf("%s http %s %ld\n", ok ? "OK" : "ERR", ok ? "200" : "-", ms_since(&t0));

    gettimeofday(&t0, NULL);
    rc = getaddrinfo("other.example.com", port, &hints, &ai);
    printf("%s unlisted %s %ld\n", rc == 0 ? "OK" : "ERR", rc == 0 ? "resolved" : "-", ms_since(&t0));
    if (rc == 0) freeaddrinfo(ai);
    return 0;
}
