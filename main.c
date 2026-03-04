#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/_types/_timeval.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// максимальное количество хопов = 30
#define MAX_HOPS 30

// максимлаьное количество пакетов на хоп
#define PACKET_PER_HOP 3

int main(int argc, char *argv[]) {
  int resolve_names = 0;
  char *target = NULL;

  if (argc == 2) {
    target = argv[1];
  } else if (argc == 3 && strcmp(argv[1], "-dns") == 0) {
    resolve_names = 1;
    target = argv[2];
  } else {
    fprintf(stderr, "Using: %s [-dns] <host>\n", argv[0]);
    exit(1);
  }

  if (geteuid() != 0) {
    fprintf(stderr, "Root required\n");
    exit(1);
  }

  printf("traceroute to %s\n", target);

  struct hostent *host = gethostbyname(target);
  if (host == NULL) {
    fprintf(stderr, "Not allowed host: %s\n", target);
    exit(1);
  }

  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr = *(struct in_addr *)host->h_addr;
  dest_addr.sin_port = htons(33434);

  printf("IP: %s\n", inet_ntoa(dest_addr.sin_addr));

  // ICMP сокет для получения
  int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (icmp_sock < 0) {
    perror("Socket creating error(icmp)");
    exit(1);
  }

  // UDP сокет для отправки
  int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (udp_sock < 0) {
    perror("Socket creatin error(udp)");
    close(icmp_sock);
    exit(1);
  }

  // таймаут на прием
  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  char packet[64] = {0};
  char buffer[1024];
  struct sockaddr_in from_addr;
  socklen_t from_len = sizeof(from_addr);

  for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
    int done = 0;
    for (int probe = 0; probe < PACKET_PER_HOP; probe++) {

      printf("|%2d.%d ", ttl,
             probe); // указываю какой ttl и какой probe в данный момент

      setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

      dest_addr.sin_port = htons(33434 + (ttl - 1) * PACKET_PER_HOP + probe);

      struct timeval start, end;
      gettimeofday(&start, NULL);

      sendto(udp_sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr,
             sizeof(dest_addr));

      from_len = sizeof(from_addr);
      int len = recvfrom(icmp_sock, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&from_addr, &from_len);

      gettimeofday(&end, NULL);
      double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                   (end.tv_usec - start.tv_usec) / 1000.0;

      if (len < 0) {
        printf("*\n");
        continue;
      }

      char hostname[NI_MAXHOST] = "";
      if (resolve_names) {
        getnameinfo((struct sockaddr *)&from_addr, sizeof(from_addr), hostname,
                    sizeof(hostname), NULL, 0, 0);
      }

      struct ip *ip = (struct ip *)buffer;
      int ip_hlen = ip->ip_hl * 4;
      struct icmp *icmp = (struct icmp *)(buffer + ip_hlen);

      if (icmp->icmp_type == ICMP_UNREACH &&
          icmp->icmp_code == ICMP_UNREACH_PORT) {

        printf("%s (%.2f ms) [DONE]\n", inet_ntoa(from_addr.sin_addr), rtt);
        done = 1;
        break;
      } else {
        if (strlen(hostname) > 0) {
          printf("%s (%s) (%.2f ms)\n", hostname, inet_ntoa(from_addr.sin_addr),
                 rtt);
        } else {
          printf("%s (%.2f ms)\n", inet_ntoa(from_addr.sin_addr), rtt);
        }
      }
    }
    if (done)
      break;
  }

  close(icmp_sock);
  close(udp_sock);
  return 0;
}
