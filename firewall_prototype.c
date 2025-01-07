// prototype of a firewall i made in C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <pthread.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#define MAX_RULES 10
struct firewall_rule {
    char action[10];
    uint32_t ip_address;
    uint16_t port;
};

struct firewall_rule rules[MAX_RULES];
int rule_count = 0;
pthread_mutex_t rule_mutex = PTHREAD_MUTEX_INITIALIZER;
void packet_handler(unsigned char *buffer, int size);
void view_rules();
void add_rule();
void log_traffic(struct ip *ip_header, struct tcphdr *tcp_header);
void *command_line_interface(void *arg);
#ifdef _WIN32
void init_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        exit(1);
    }
}
#endif
void log_traffic(struct ip *ip_header, struct tcphdr *tcp_header) {
    FILE *logfile = fopen("firewall_log.txt", "a");
    if (logfile == NULL) {
        perror("[!] Failed to open log file");
        return;
    }

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ip_header->ip_src, src_ip, sizeof(src_ip));
  inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, sizeof(dst_ip));

    fprintf(logfile, "[+] Packet: %s:%d -> %s:%d\n", 
             src_ip, ntohs(tcp_header->th_sport),
            dst_ip, ntohs(tcp_header->th_dport));
    fclose(logfile);
}

void view_rules() {
    printf("\n[+] Current Firewall Rules:\n");
    if (rule_count == 0) {
        printf("No rules defined.\n");
    } else {
        for (int i = 0; i < rule_count; i++) {
            struct in_addr ip_addr;
             ip_addr.s_addr = rules[i].ip_address;
            printf("Rule %d: %s %s:%d\n", i + 1, rules[i].action,
                    inet_ntoa(ip_addr), rules[i].port);
        }}}
void add_rule() {
    if (rule_count >= MAX_RULES) {
        printf("[!] Maximum rule count reached.\n");
        return;
    }
       char action[10];
         char ip_address[16];
       uint16_t port;

    printf("[-] Enter rule action (BLOCK/ALLOW): ");
    scanf("%s", action);
    printf("[-] Enter IP address: ");
    scanf("%s", ip_address);
    printf("[-] Enter port: ");
    scanf("%hu", &port);

    struct firewall_rule new_rule;
    strncpy(new_rule.action, action, sizeof(new_rule.action) - 1);
        new_rule.ip_address = inet_addr(ip_address);
      new_rule.port = port;

    pthread_mutex_lock(&rule_mutex);
    rules[rule_count++] = new_rule;
    pthread_mutex_unlock(&rule_mutex);
      printf("[+] Rule added successfully.\n");
}

void packet_handler(unsigned char *buffer, int size) {
    struct ip *ip_header = (struct ip *)(buffer + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(buffer + 14 + (ip_header->ip_hl << 2));

    log_traffic(ip_header, tcp_header);
      pthread_mutex_lock(&rule_mutex);
    for (int i = 0; i < rule_count; i++) {
        if (rules[i].ip_address == ip_header->ip_dst.s_addr && rules[i].port == ntohs(tcp_header->th_dport)) {
            if (strncmp(rules[i].action, "BLOCK", 5) == 0) {
                printf("Blocked packet from %s:%d\n", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport));
                pthread_mutex_unlock(&rule_mutex);
                return;
            }
        }
    }
    pthread_mutex_unlock(&rule_mutex); }
void *command_line_interface(void *arg) {
    char command[100];
    
    while (1) {
        printf("\nSimple Firewall Prototype\n");
        printf("1. View Current Rules\n");
        printf("2. Add New Rule\n");
        printf("3. Exit\n");
        printf("[-] Enter command: ");
        fgets(command, sizeof(command), stdin);

        if (strncmp(command, "1", 1) == 0) {
            view_rules();
        } else if (strncmp(command, "2", 1) == 0) {
            add_rule();
        } else if (strncmp(command, "3", 1) == 0) {
            break;
        } else {
            printf("Unknown command.\n");
        }
    }
    return NULL;
}
int main() {
    pthread_t cli_thread;
    pthread_create(&cli_thread, NULL, command_line_interface, NULL);

    int sockfd;
    unsigned char *buffer = (unsigned char *)malloc(65536);

#ifdef _WIN32
    init_winsock();
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
#else
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#endif

    if (sockfd < 0) {
        printf("Socket creation failed\n");
        exit(1);
    }

    while (1) {
        int size = recv(sockfd, buffer, 65536, 0);
        if (size < 0) {
            printf("Recv failed\n");
            exit(1);
        }
        packet_handler(buffer, size);
    }

#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif

    free(buffer);
    return 0;
}
