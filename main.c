#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <time.h>
#include <linux/if_packet.h>
#include <net/if.h>

#define MAX_RULES 128
#define MAX_RATE_ENTRIES 64

typedef enum {
    ACTION_ALLOW = 0,
    ACTION_DENY
} action_t;

typedef enum {
    PROTO_ANY = 0,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP
} proto_t;

typedef struct {
    action_t action;
    proto_t protocol;
    uint32_t src_ip;  /* network byte order */
    uint32_t dst_ip;  /* network byte order */
    uint16_t src_port;
    uint16_t dst_port;
    int src_ip_any;
    int dst_ip_any;
    int src_port_any;
    int dst_port_any;
    char description[64];
} rule_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    proto_t protocol;
    int tcp_syn;
} packet_info_t;

typedef struct rate_entry {
    uint32_t src_ip;
    time_t window_start;
    unsigned int count;
} rate_entry_t;

typedef struct {
    rule_t rules[MAX_RULES];
    size_t rule_count;
    action_t default_action;
    char interface[IFNAMSIZ];
    char log_path[256];
    unsigned int rate_limit_per_sec;
    unsigned int rate_window_sec;
} config_t;

static FILE *g_log = NULL;
static rate_entry_t g_rate_table[MAX_RATE_ENTRIES];

static const char *action_to_str(action_t action) {
    return action == ACTION_ALLOW ? "ALLOW" : "DENY";
}

static const char *proto_to_str(proto_t proto) {
    switch (proto) {
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case PROTO_ICMP: return "ICMP";
        default: return "ANY";
    }
}

static int parse_protocol(const char *tok, proto_t *proto) {
    if (strcasecmp(tok, "tcp") == 0) {
        *proto = PROTO_TCP;
    } else if (strcasecmp(tok, "udp") == 0) {
        *proto = PROTO_UDP;
    } else if (strcasecmp(tok, "icmp") == 0) {
        *proto = PROTO_ICMP;
    } else if (strcasecmp(tok, "any") == 0) {
        *proto = PROTO_ANY;
    } else {
        return -1;
    }
    return 0;
}

static int parse_ip_any(const char *tok, uint32_t *out_ip, int *is_any) {
    if (strcmp(tok, "*") == 0 || strcasecmp(tok, "any") == 0) {
        *is_any = 1;
        *out_ip = 0;
        return 0;
    }
    struct in_addr addr;
    if (inet_aton(tok, &addr) == 0) {
        return -1;
    }
    *is_any = 0;
    *out_ip = addr.s_addr;
    return 0;
}

static int parse_port_any(const char *tok, uint16_t *out_port, int *is_any) {
    if (strcmp(tok, "*") == 0 || strcasecmp(tok, "any") == 0) {
        *is_any = 1;
        *out_port = 0;
        return 0;
    }
    char *end = NULL;
    long val = strtol(tok, &end, 10);
    if (end == tok || val < 0 || val > 65535) {
        return -1;
    }
    *is_any = 0;
    *out_port = (uint16_t) val;
    return 0;
}

static int add_rule(config_t *cfg, const rule_t *rule) {
    if (cfg->rule_count >= MAX_RULES) {
        return -1;
    }
    cfg->rules[cfg->rule_count++] = *rule;
    return 0;
}

static int parse_rule_line(const char *line, config_t *cfg) {
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, " \t", &saveptr);
    if (!tok) return 0; /* empty line */
    if (tok[0] == '#') return 0; /* comment */

    rule_t rule; memset(&rule, 0, sizeof(rule));

    /* action */
    if (strcasecmp(tok, "allow") == 0) rule.action = ACTION_ALLOW; else if (strcasecmp(tok, "deny") == 0) rule.action = ACTION_DENY; else return -1;

    /* protocol */
    tok = strtok_r(NULL, " \t", &saveptr); if (!tok) return -1;
    if (parse_protocol(tok, &rule.protocol) != 0) return -1;

    /* src ip */
    tok = strtok_r(NULL, " \t", &saveptr); if (!tok) return -1;
    if (parse_ip_any(tok, &rule.src_ip, &rule.src_ip_any) != 0) return -1;

    /* dst ip */
    tok = strtok_r(NULL, " \t", &saveptr); if (!tok) return -1;
    if (parse_ip_any(tok, &rule.dst_ip, &rule.dst_ip_any) != 0) return -1;

    /* src port */
    tok = strtok_r(NULL, " \t", &saveptr); if (!tok) return -1;
    if (parse_port_any(tok, &rule.src_port, &rule.src_port_any) != 0) return -1;

    /* dst port */
    tok = strtok_r(NULL, " \t", &saveptr); if (!tok) return -1;
    if (parse_port_any(tok, &rule.dst_port, &rule.dst_port_any) != 0) return -1;

    /* optional description */
    tok = strtok_r(NULL, "\n", &saveptr);
    if (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        strncpy(rule.description, tok, sizeof(rule.description) - 1);
    }

    return add_rule(cfg, &rule);
}

static int load_config(const char *path, config_t *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Failed to open config %s: %s\n", path, strerror(errno));
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->default_action = ACTION_DENY;
    strncpy(cfg->interface, "lo", sizeof(cfg->interface) - 1);
    strncpy(cfg->log_path, "firewall.log", sizeof(cfg->log_path) - 1);
    cfg->rate_limit_per_sec = 100;
    cfg->rate_window_sec = 1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "interface", 9) == 0) {
            char *val = strchr(line, '=');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t') val++;
                val[strcspn(val, "\n")] = '\0';
                strncpy(cfg->interface, val, sizeof(cfg->interface) - 1);
            }
        } else if (strncmp(line, "default", 7) == 0) {
            char *val = strchr(line, '=');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t') val++;
                if (strncasecmp(val, "allow", 5) == 0) cfg->default_action = ACTION_ALLOW; else cfg->default_action = ACTION_DENY;
            }
        } else if (strncmp(line, "log", 3) == 0) {
            char *val = strchr(line, '=');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t') val++;
                val[strcspn(val, "\n")] = '\0';
                strncpy(cfg->log_path, val, sizeof(cfg->log_path) - 1);
            }
        } else if (strncmp(line, "rate_limit_per_sec", 19) == 0) {
            char *val = strchr(line, '=');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t') val++;
                cfg->rate_limit_per_sec = (unsigned int)strtoul(val, NULL, 10);
                if (cfg->rate_limit_per_sec == 0) {
                    cfg->rate_limit_per_sec = 1;
                }
            }
        } else if (strncmp(line, "rate_window_sec", 15) == 0) {
            char *val = strchr(line, '=');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t') val++;
                cfg->rate_window_sec = (unsigned int)strtoul(val, NULL, 10);
                if (cfg->rate_window_sec == 0) {
                    cfg->rate_window_sec = 1;
                }
            }
        } else {
            if (parse_rule_line(line, cfg) != 0) {
                fprintf(stderr, "Invalid rule line: %s", line);
            }
        }
    }

    fclose(f);
    return 0;
}

static void init_rate_table(void) {
    memset(g_rate_table, 0, sizeof(g_rate_table));
}

static int rate_limited(uint32_t src_ip, const config_t *cfg) {
    time_t now = time(NULL);
    for (size_t i = 0; i < MAX_RATE_ENTRIES; i++) {
        if (g_rate_table[i].src_ip == src_ip) {
            if (now - g_rate_table[i].window_start >= (time_t)cfg->rate_window_sec) {
                g_rate_table[i].window_start = now;
                g_rate_table[i].count = 1;
                return 0;
            }
            g_rate_table[i].count++;
            if (g_rate_table[i].count > cfg->rate_limit_per_sec) {
                return 1;
            }
            return 0;
        }
    }

    for (size_t i = 0; i < MAX_RATE_ENTRIES; i++) {
        if (g_rate_table[i].src_ip == 0) {
            g_rate_table[i].src_ip = src_ip;
            g_rate_table[i].window_start = now;
            g_rate_table[i].count = 1;
            return 0;
        }
    }
    /* table full, conservatively limit */
    return 1;
}

static int parse_packet(const uint8_t *buf, ssize_t len, packet_info_t *info) {
    if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return -1;
    const struct ethhdr *eth = (const struct ethhdr *)buf;
    if (ntohs(eth->h_proto) != ETH_P_IP) return -1; /* only IPv4 */

    const struct iphdr *ip = (const struct iphdr *)(buf + sizeof(struct ethhdr));
    size_t ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr) || (size_t)len < sizeof(struct ethhdr) + ip_header_len) return -1;

    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;
    info->tcp_syn = 0;

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            info->protocol = PROTO_TCP;
            if ((size_t)len < sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr)) return -1;
            const struct tcphdr *tcp = (const struct tcphdr *)(buf + sizeof(struct ethhdr) + ip_header_len);
            info->src_port = ntohs(tcp->source);
            info->dst_port = ntohs(tcp->dest);
            info->tcp_syn = (tcp->syn == 1);
            break;
        }
        case IPPROTO_UDP: {
            info->protocol = PROTO_UDP;
            if ((size_t)len < sizeof(struct ethhdr) + ip_header_len + sizeof(struct udphdr)) return -1;
            const struct udphdr *udp = (const struct udphdr *)(buf + sizeof(struct ethhdr) + ip_header_len);
            info->src_port = ntohs(udp->source);
            info->dst_port = ntohs(udp->dest);
            break;
        }
        case IPPROTO_ICMP: {
            info->protocol = PROTO_ICMP;
            info->src_port = 0;
            info->dst_port = 0;
            break;
        }
        default:
            info->protocol = PROTO_ANY;
            info->src_port = info->dst_port = 0;
            break;
    }
    return 0;
}

static int ip_match(uint32_t rule_ip, int any, uint32_t pkt_ip) {
    return any || rule_ip == pkt_ip;
}

static int port_match(uint16_t rule_port, int any, uint16_t pkt_port) {
    return any || rule_port == pkt_port;
}

static action_t evaluate_rules(const config_t *cfg, const packet_info_t *info, const rule_t **matched_rule) {
    for (size_t i = 0; i < cfg->rule_count; i++) {
        const rule_t *r = &cfg->rules[i];
        if (r->protocol != PROTO_ANY && r->protocol != info->protocol) continue;
        if (!ip_match(r->src_ip, r->src_ip_any, info->src_ip)) continue;
        if (!ip_match(r->dst_ip, r->dst_ip_any, info->dst_ip)) continue;
        if (!port_match(r->src_port, r->src_port_any, info->src_port)) continue;
        if (!port_match(r->dst_port, r->dst_port_any, info->dst_port)) continue;
        if (matched_rule) *matched_rule = r;
        return r->action;
    }
    if (matched_rule) *matched_rule = NULL;
    return cfg->default_action;
}

static void log_decision(const packet_info_t *info, action_t action, const rule_t *rule, int limited) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &info->dst_ip, dst, sizeof(dst));

    char ts[64];
    struct timeval tv; gettimeofday(&tv, NULL);
    struct tm tm; localtime_r(&tv.tv_sec, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(g_log ? g_log : stdout,
            "%s.%03ld action=%s proto=%s src=%s:%u dst=%s:%u syn=%d limited=%d rule=%s\n",
            ts, tv.tv_usec / 1000,
            action_to_str(action), proto_to_str(info->protocol),
            src, info->src_port, dst, info->dst_port,
            info->tcp_syn, limited,
            rule ? rule->description : "default");
    fflush(g_log ? g_log : stdout);
}

static int bind_socket_interface(int fd, const char *ifname) {
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }

    struct sockaddr_ll sll; memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return -1;
    }
    return 0;
}

static int run_firewall(const config_t *cfg) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    if (bind_socket_interface(fd, cfg->interface) != 0) {
        close(fd);
        return -1;
    }

    uint8_t buf[2048];
    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        packet_info_t info; memset(&info, 0, sizeof(info));
        if (parse_packet(buf, n, &info) != 0) {
            continue; /* skip non-IPv4 or malformed */
        }

        int limited = 0;
        if (info.protocol == PROTO_TCP && info.tcp_syn) {
            limited = rate_limited(info.src_ip, cfg);
        }

        const rule_t *matched = NULL;
        action_t decision = limited ? ACTION_DENY : evaluate_rules(cfg, &info, &matched);
        log_decision(&info, decision, matched, limited);
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config>\n", argv[0]);
        return 1;
    }

    config_t cfg;
    if (load_config(argv[1], &cfg) != 0) {
        return 1;
    }

    g_log = fopen(cfg.log_path, "a");
    if (!g_log) {
        perror("fopen log");
    }

    init_rate_table();

    int rc = run_firewall(&cfg);

    if (g_log) fclose(g_log);
    return rc == 0 ? 0 : 1;
}
