/*
    A virtual router basedon WinTAP and NPcap for multi-network link aggregation.
    Copyright (C) <2024> <Repeerc>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2def.h>
#include <pthread.h>
#include <iphlpapi.h>
#include <assert.h>

#include <time.h>
#include <pcap.h>

#define REG_PATH "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\"
#define NAME_REG_PATH "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
#define NPF_PREFIX "\\Device\\NPF_"

#define MAX_OUTPUT_DEVS 32
#define QUEUE_SIZE 1024
#define MAX_THREADS 5

#define STATUS_UPDATE_TIME 1000

#define BLACK 0
#define BLUE 1
#define GREEN 2
#define TURQUOISE 3
#define RED 4
#define PURPLE 5
#define YELLOW 0xE
#define WHITE 7

void SetColor(UINT8 fg, UINT8 bg)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, MAKEWORD(fg, bg));
}

static UINT8 self_mac[] = {0xCC, 0x14, 0x40, 0x80, 0x20, 0x22};
static UINT8 TAP_DEV_MAC[6];
static IN_ADDR self_ip;


HANDLE tap_send_thread[MAX_THREADS];
HANDLE tap_recv_thread[MAX_THREADS];

typedef struct
{
    void *buffer[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE notEmpty;
    CONDITION_VARIABLE notFull;
} Queue;

typedef struct net_status_t
{
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t tx_last_bytes;
    uint64_t rx_last_bytes;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t arp;
} net_status_t;

typedef struct output_dev_t
{
    int index;
    char *dev_guid;
    char *dev_path;
    char *dev_desc;
    pcap_t *fp;
    BOOL connected;
    UINT32 ip;
    UINT32 gateway_ip;
    UINT8 dev_mac[6];
    UINT8 gateway_mac[6];
    HANDLE thread;
    HANDLE send_thread[MAX_THREADS];
    HANDLE recv_thread[MAX_THREADS];

    Queue dev_rx_queue;
    Queue dev_tx_queue;
    net_status_t status;
} output_dev_t;

Queue tap_rx_queue;
Queue tap_tx_queue;

net_status_t tap_net_status;

void initQueue(Queue *q)
{
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    InitializeCriticalSection(&q->lock);
    InitializeConditionVariable(&q->notEmpty);
    InitializeConditionVariable(&q->notFull);
}

void destroyQueue(Queue *q)
{
    DeleteCriticalSection(&q->lock);
}

void enqueue(Queue *q, void *value)
{
    EnterCriticalSection(&q->lock);
    while (q->count == QUEUE_SIZE)
    {
        SleepConditionVariableCS(&q->notFull, &q->lock, INFINITE);
    }
    q->buffer[q->tail] = value;
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;
    WakeConditionVariable(&q->notEmpty);
    LeaveCriticalSection(&q->lock);
}

void *dequeue(Queue *q)
{
    EnterCriticalSection(&q->lock);
    while (q->count == 0)
    {
        SleepConditionVariableCS(&q->notEmpty, &q->lock, INFINITE);
    }
    void *value = q->buffer[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;
    WakeConditionVariable(&q->notFull);
    LeaveCriticalSection(&q->lock);
    return value;
}

#define TCP_STATUS_CLOSED 0
#define TCP_STATUS_SYN_SEND 1
#define TCP_STATUS_ESTABLISHED 2

typedef struct tcp_port_status_t
{
    uint8_t out_dev_id;
    uint8_t occupany;
    uint16_t keepalive_cnt;
    int tcp_status;
} tcp_port_status_t;

tcp_port_status_t tcp_port[65536];

output_dev_t out_dev[MAX_OUTPUT_DEVS];
unsigned int registered_devs = 0;

typedef struct __attribute__((packed)) ipParames_t
{
    IN_ADDR ip;
    IN_ADDR gateway;
    IN_ADDR mask;
} ipParames_t;

typedef struct __attribute__((packed)) eth_header_t
{
    UINT8 dst_mac[6];
    UINT8 src_mac[6];
    UINT16 eth_type;
} eth_header_t;

typedef struct __attribute__((packed)) ip_hdr_t
{
    UINT8 header_len : 4;
    UINT8 version : 4;
    UINT8 tos;
    UINT16 total_length;
    UINT16 id;
    UINT16 frag_offset;
    UINT8 ttl;
    UINT8 protocol;
    UINT16 checksum;
    union
    {
        UINT32 src_ip_dw;
        UINT8 src_ip[4];
    } src_ip_u;
    union
    {
        UINT32 dst_ip_dw;
        UINT8 dst_ip[4];
    } dst_ip_u;
} ip_hdr_t;

typedef struct __attribute__((packed)) tcp_hdr_t
{
    UINT16 source;
    UINT16 dest;
    UINT32 seq;
    UINT32 ack_seq;
    UINT16 res1 : 4,
        doff : 4,
        fin : 1,
        syn : 1,
        rst : 1,
        psh : 1,
        ack : 1,
        urg : 1,
        ece : 1,
        cwr : 1;
    UINT16 winsz;
    UINT16 checksum;
    UINT16 urgent_ptr;
} tcp_hdr_t;

typedef struct __attribute__((packed)) udp_hdr_t
{
    UINT16 source;
    UINT16 dest;
    UINT16 len;
    UINT16 checksum;
} udp_hdr_t;

typedef struct icmp_header_t
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short sequence;
} icmp_header_t;

typedef struct __attribute__((packed)) arp_header_t
{
    UINT16 hdwr_type;
    UINT16 protocol_type;
    UINT8 hdwr_sz;
    UINT8 protocol_sz;
    UINT16 opcode;
    UINT8 sender_mac[6];
    union
    {
        UINT8 sender_ip[4];
        UINT32 sender_ip_4;
    };
    UINT8 target_mac[6];
    union
    {
        UINT8 target_ip[4];
        UINT32 target_ip_4;
    };
} arp_header_t;

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IPV6 0x86DD

#define ETH_ALEN 6
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002

#define TAP_WIN_CONTROL_CODE(request, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_MAC TAP_WIN_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_VERSION TAP_WIN_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_MTU TAP_WIN_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_INFO TAP_WIN_CONTROL_CODE(4, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_CONTROL_CODE(5, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ TAP_WIN_CONTROL_CODE(7, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_LOG_LINE TAP_WIN_CONTROL_CODE(8, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT TAP_WIN_CONTROL_CODE(9, METHOD_BUFFERED)

int get_tap_instance(wchar_t *id, char *name)
{
    for (int seq = 0; seq <= 9999; seq++)
    {
        HKEY hKey;
        HKEY hKeyNetwork;
        LONG status;
        DWORD dwSize;
        DWORD dwType;
        BYTE byData[1024];

        DWORD dwSizeName;
        DWORD dwTypeName;
        BYTE byDataName[1024];

        char path[1024];
        sprintf_s(path, sizeof(path), REG_PATH "%04d", seq);
        status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(path), 0, KEY_READ, &hKey);
        if (status != ERROR_SUCCESS)
        {
            // printf("RegOpenKeyEx failed: %ld\n", status);
            printf("No found TAP adapter \"mix-tap\": %ld\n", status);
            return -1;
        }

        dwSize = sizeof(byData) - 1;
        memset(byData, 0, sizeof(byData));
        status = RegQueryValueEx(hKey, TEXT("MatchingDeviceId"), NULL, &dwType, byData, &dwSize);

        if (status == ERROR_SUCCESS && dwType == REG_SZ)
        {
            if (strcmp("tap0901", (char *)byData) == 0)
            {
                dwSize = sizeof(byData) - 1;
                memset(byData, 0, sizeof(byData));
                status = RegQueryValueEx(hKey, TEXT("NetCfgInstanceId"), NULL, &dwType, byData, &dwSize);
                if (status == ERROR_SUCCESS && dwType == REG_SZ)
                {
                    sprintf_s(path, sizeof(path), NAME_REG_PATH "%s\\Connection", (char *)byData);
                    // printf("adapter reg path:%s\n", path);
                    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(path), 0, KEY_READ, &hKeyNetwork);
                    ;
                    if (status != ERROR_SUCCESS)
                    {
                        RegCloseKey(hKey);
                        continue;
                    }
                    dwSizeName = sizeof(byDataName) - 1;
                    memset(byDataName, 0, sizeof(byDataName));
                    status = RegQueryValueEx(hKeyNetwork, TEXT("Name"), NULL, &dwTypeName, byDataName, &dwSizeName);

                    if (strcmp((char *)byDataName, "mix-tap"))
                    {
                        RegCloseKey(hKeyNetwork);
                        RegCloseKey(hKey);
                        continue;
                    }

                    printf("adapter name:%s\n", (char *)byDataName);
                    strcpy(name, (char *)byDataName);

                    int len = strlen((char *)byData);
                    for (int i = 0; i < len; i++)
                    {
                        id[i] = byData[i];
                    }
                    id[len] = 0;
                    RegCloseKey(hKeyNetwork);
                    RegCloseKey(hKey);
                    return 0;
                }
                else
                {
                    printf("err: %ld\n", status);
                }
                printf("Value: [%s]\n", byData);
            }
        }
        RegCloseKey(hKey);
    }
    return -1;
}

HANDLE tuntap = INVALID_HANDLE_VALUE;

ipParames_t defConf = {
    .ip.S_un.S_un_b = {0, 0, 0, 0},
    .gateway.S_un.S_un_b = {0, 0, 0, 0},
    .mask.S_un.S_un_b = {0, 0, 0, 0},
};

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT)
    {
        printf("CTRL+C received. Exiting...\n");

        for(int j = 0; j < MAX_THREADS ; j++)
        {
            CloseHandle(tap_recv_thread[j]);
            CloseHandle(tap_send_thread[j]);
        }

        destroyQueue(&tap_rx_queue);
        destroyQueue(&tap_tx_queue);

        CloseHandle(tuntap);
        for(int i = 0; i < registered_devs; i++)
        {   
            for(int j = 0; j < MAX_THREADS ; j++)
            {
                CloseHandle(out_dev[i].send_thread[j]);
                CloseHandle(out_dev[i].recv_thread[j]);
            }
            CloseHandle(out_dev[i].thread);

            destroyQueue(&out_dev[i].dev_rx_queue);
            destroyQueue(&out_dev[i].dev_tx_queue);
            
            pcap_close(out_dev[i].fp);
        }


        WSACleanup();
        exit(0);
        return TRUE;
    }
    return FALSE;
}

int info(const char *__format, ...)
{
    int __retval;
    va_list __local_argv;
    va_start(__local_argv, __format);
    __retval = vfprintf(stdout, __format, __local_argv);

    va_end(__local_argv);
    return __retval;
}

UINT32 MTU = 0;
UINT32 MAX_FRAME_SZ = 0;

void print_mac(UINT8 mac[6])
{
    for (int i = 0; i < 5; i++)
        info("%02X:", mac[i]);
    info("%02X", mac[5]);
}

void print_ip(UINT8 ip[4])
{
    for (int i = 0; i < 3; i++)
        info("%d.", ip[i]);
    info("%d", ip[3]);
}

void print_inaddr(struct in_addr ip)
{
    printf("%d.%d.%d.%d", ip.S_un.S_un_b.s_b1, ip.S_un.S_un_b.s_b2, ip.S_un.S_un_b.s_b3, ip.S_un.S_un_b.s_b4);
}

UINT16 calc_ip_checksum(UINT16 *buf, int nbyte)
{
    UINT32 sum = 0;
    while (nbyte > 1)
    {
        sum += *buf;
        buf++;
        nbyte -= 2;
    }
    if (nbyte)
    {
        sum += *buf & 0xFF;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (UINT16)(~sum);
}

struct __attribute__((packed)) pseudo_header
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

UINT16 calc_tcp_checksum(UINT32 src_ip, UINT32 dst_ip, UINT8 *tcp_head, int nbyte)
{
    UINT16 res = 0;
    struct pseudo_header psh;
    psh.source_address = src_ip;
    psh.dest_address = dst_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(nbyte);

    int psize = sizeof(struct pseudo_header) + nbyte;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_head, nbyte);
    res = calc_ip_checksum((UINT16 *)pseudogram, psize);
    free(pseudogram);
    return res;
}

UINT16 calc_udp_checksum(UINT32 src_ip, UINT32 dst_ip, UINT8 *udp_head, int nbyte)
{
    UINT16 res = 0;
    struct pseudo_header psh;
    psh.source_address = src_ip;
    psh.dest_address = dst_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = htons(nbyte);

    int psize = sizeof(struct pseudo_header) + nbyte;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udp_head, nbyte);
    res = calc_ip_checksum((UINT16 *)pseudogram, psize);
    free(pseudogram);
    return res;
}

struct frame_tx_info
{
    void *dat;
    size_t len;
};

DWORD WINAPI tap_tx_thread(LPVOID arg)
{

    while (1)
    {
        struct frame_tx_info *inf = dequeue(&tap_tx_queue);
        OVERLAPPED txOverLapped = {0};
        DWORD wrSz = 0;
        txOverLapped.hEvent = CreateEvent(0, 0, 0, "");
        WriteFile(tuntap, inf->dat, inf->len, &wrSz, &txOverLapped);
        InterlockedExchangeAdd64((int64_t *)&tap_net_status.tx_bytes, inf->len);
        InterlockedIncrement64((int64_t *)&tap_net_status.tx_packets);
        
        WaitForSingleObject(txOverLapped.hEvent, INFINITE);
        free(inf->dat);
        free(inf);
    }

    return 0;
}

// void *frame_tx(void *dat, size_t len)
// {
//     // struct frame_tx_info *arg = calloc(1, sizeof(struct frame_tx_info));
//     // arg->dat = dat;
//     // arg->len = len;
//     // pthread_create(NULL, NULL, frame_tx_thread, arg);

//     OVERLAPPED txOverLapped = {0};
//     DWORD wrSz = 0;
//     txOverLapped.hEvent = CreateEvent(0, 0, 0, "");
//     WriteFile(tuntap, dat, len, &wrSz, &txOverLapped);
//     WaitForSingleObject(txOverLapped.hEvent, INFINITE);
//     free(dat);

//     return NULL;
// }

typedef struct dev_pack_send_info_t
{
    int dev;
    void *dat;
    size_t len;
    uint16_t tcp_port;
} dev_pack_send_info_t;

DWORD WINAPI dev_send_pack_thread(LPVOID arg)
{
    uint32_t dev_idx = (uint64_t)arg;
    while (1)
    {
        dev_pack_send_info_t *inf = dequeue(&out_dev[dev_idx].dev_tx_queue);
        if (out_dev[inf->dev].connected)
        {
            if (pcap_sendpacket(out_dev[inf->dev].fp, // Adapter
                                inf->dat,             // buffer with the packet
                                inf->len              // size
                                ) < 0)
            {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(out_dev[inf->dev].fp));
                out_dev[inf->dev].connected = FALSE;
                out_dev[inf->dev].ip = 0;
                tcp_port[inf->tcp_port].tcp_status = TCP_STATUS_CLOSED;
            }
            InterlockedAdd64((int64_t *)&out_dev[inf->dev].status.tx_bytes, inf->len);
            InterlockedIncrement64((int64_t *)&out_dev[inf->dev].status.tx_packets);
        }
        free(inf->dat);
        free(inf);
    }
    return 0;
}

void *frame_rx(void *dat)
{
    UINT8 *frame_dat = dat;
    eth_header_t *eth_head = dat;

    // info("src_mac:");
    // print_mac(eth_head->src_mac);
    // info("   dst_mac:");
    // print_mac(eth_head->dst_mac);
    // info("   eth_type:%04X\n", eth_head->eth_type);

    switch (htons(eth_head->eth_type))
    {
    case ETHERTYPE_ARP:
    {
        arp_header_t *arp_head = (void *)&frame_dat[sizeof(eth_header_t)];
        if (arp_head->target_ip_4 == self_ip.S_un.S_addr)
        {
            InterlockedIncrement64((int64_t *)&tap_net_status.arp);
            // info("sender mac:");
            // print_mac(arp_head->sender_mac);
            // info("  sender ip:");
            // print_ip(arp_head->sender_ip);

            // info("  target mac:");
            // print_mac(arp_head->target_mac);
            // info("  target ip:");
            // print_ip(arp_head->target_ip);
            // info("  arp_type:%04X\n", arp_head->opcode);

            int reply_len = sizeof(eth_header_t) + sizeof(arp_header_t);
            UINT8 *reply = malloc(reply_len);
            assert(reply);
            eth_header_t *rep_eth = (void *)reply;
            arp_header_t *rep_arp = (void *)&reply[sizeof(eth_header_t)];

            memcpy(rep_eth->src_mac, self_mac, ETH_ALEN);
            memcpy(rep_eth->dst_mac, arp_head->sender_mac, ETH_ALEN);
            rep_eth->eth_type = htons(ETHERTYPE_ARP);
            rep_arp->hdwr_type = htons(1);          // Ethernet
            rep_arp->protocol_type = htons(0x0800); // ETHERTYPE_IP
            rep_arp->hdwr_sz = ETH_ALEN;
            rep_arp->protocol_sz = 4;
            rep_arp->opcode = htons(ARP_REPLY);

            rep_arp->sender_ip_4 = self_ip.S_un.S_addr;
            memcpy(rep_arp->sender_mac, self_mac, ETH_ALEN);

            rep_arp->target_ip_4 = arp_head->sender_ip_4;
            memcpy(rep_arp->target_mac, arp_head->sender_mac, ETH_ALEN);

            struct frame_tx_info *frame_tx_inf = malloc(sizeof(struct frame_tx_info));
            frame_tx_inf->dat = reply;
            frame_tx_inf->len = reply_len;
            enqueue(&tap_tx_queue, frame_tx_inf);
            // frame_tx(reply, reply_len);
        }
    }
    break;

    case ETHERTYPE_IP:
    {
        void *ip_head_addr = (void *)&frame_dat[sizeof(eth_header_t)];
        ip_hdr_t *ip_head = ip_head_addr;
        if (ip_head->version == 4)
        {
            // UINT16 chksum = calc_ip_checksum((UINT16 *)ip_head_addr, ip_head->header_len * 4);
            // if (!chksum)
            {
                void *ip_payload_addr = (void *)(((UINT32 *)ip_head_addr) + ip_head->header_len);
                size_t ip_payload_len = ntohs(ip_head->total_length) - ip_head->header_len * 4;

                InterlockedAdd64((int64_t *)&tap_net_status.rx_bytes, ntohs(ip_head->total_length) + 14);

                // printf(" IP packet: src:");
                // print_ip(ip_head->src_ip_u.src_ip);
                // printf(" dst:");
                // print_ip(ip_head->dst_ip_u.dst_ip);
                // printf("  len: %d\n", ntohs(ip_head->total_length));

                //========================== to this virtual router ==================
                if (ip_head->dst_ip_u.dst_ip_dw == self_ip.S_un.S_addr)
                {
                    switch (ip_head->protocol)
                    {
                    case IPPROTO_ICMP:
                    {

                        InterlockedIncrement64((int64_t *)&tap_net_status.icmp);
                        icmp_header_t *icmp_head = ip_payload_addr;

                        size_t reply_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                        UINT8 *reply = malloc(reply_len);
                        assert(reply);
                        eth_header_t *rep_eth = (void *)reply;

                        void *rep_ip_head = (void *)&reply[sizeof(eth_header_t)];
                        ip_hdr_t *rep_ip = rep_ip_head;

                        memcpy(rep_eth->src_mac, self_mac, ETH_ALEN);
                        memcpy(rep_eth->dst_mac, eth_head->src_mac, ETH_ALEN);
                        rep_eth->eth_type = htons(ETHERTYPE_IP);

                        rep_ip->header_len = 5;
                        rep_ip->version = 4;
                        rep_ip->tos = 0;
                        rep_ip->total_length = ip_head->total_length;
                        rep_ip->id = htons(rand());
                        rep_ip->frag_offset = 0;
                        rep_ip->ttl = ip_head->ttl - 1;
                        rep_ip->protocol = IPPROTO_ICMP;
                        rep_ip->src_ip_u.src_ip_dw = self_ip.S_un.S_addr;
                        rep_ip->dst_ip_u.dst_ip_dw = ip_head->src_ip_u.src_ip_dw;
                        rep_ip->checksum = 0;

                        rep_ip->checksum = (calc_ip_checksum((UINT16 *)rep_ip_head, rep_ip->header_len * 4));

                        void *rep_ip_payload_addr = (void *)&reply[sizeof(eth_header_t) + sizeof(ip_hdr_t)];

                        memcpy(rep_ip_payload_addr, ip_payload_addr, ip_payload_len);

                        icmp_header_t *rep_icmp = rep_ip_payload_addr;

                        rep_icmp->type = 0;
                        rep_icmp->code = 0;
                        rep_icmp->id = icmp_head->id;
                        rep_icmp->sequence = icmp_head->sequence;
                        rep_icmp->checksum = 0;

                        rep_icmp->checksum = (calc_ip_checksum((UINT16 *)rep_ip_payload_addr, ip_payload_len));

                        struct frame_tx_info *frame_tx_inf = malloc(sizeof(struct frame_tx_info));
                        frame_tx_inf->dat = reply;
                        frame_tx_inf->len = reply_len;
                        enqueue(&tap_tx_queue, frame_tx_inf);
                        

                        // frame_tx(reply, reply_len);
                        // free(reply);
                    }
                    break;

                    default:
                        break;
                    }
                }
                else
                //========================== IP forward =========================
                {
                    switch (ip_head->protocol)
                    {
                    case IPPROTO_ICMP:
                    {
                        InterlockedIncrement64((int64_t *)&tap_net_status.icmp);

                        int select = rand() % registered_devs; // = ((ntohs(tcp_head->source) % 3) == 0);
                        // static int sadd = 0;

                        size_t fwd_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                        UINT8 *fwd_packet = malloc(fwd_len);
                        assert(fwd_packet);
                        eth_header_t *fwd_eth_hdr = (void *)fwd_packet;
                        // printf("sel:%s\n", out_dev[select].dev_path);

                        memcpy(fwd_eth_hdr->src_mac, out_dev[select].dev_mac, ETH_ALEN);
                        memcpy(fwd_eth_hdr->dst_mac, out_dev[select].gateway_mac, ETH_ALEN);
                        fwd_eth_hdr->eth_type = htons(ETHERTYPE_IP);

                        void *fwd_ip_head = (void *)&fwd_packet[sizeof(eth_header_t)];
                        memcpy(fwd_ip_head, ip_head, ntohs(ip_head->total_length));

                        ip_hdr_t *fwd_ip_h = fwd_ip_head;
                        fwd_ip_h->checksum = 0;
                        fwd_ip_h->ttl -= 1;

                        void *fwd_ip_payload_addr = (void *)&fwd_packet[sizeof(eth_header_t) + fwd_ip_h->header_len * 4];

                        fwd_ip_h->src_ip_u.src_ip_dw = out_dev[select].ip;
                        fwd_ip_h->checksum = calc_ip_checksum((UINT16 *)fwd_ip_head, fwd_ip_h->header_len * 4);
                        memcpy(fwd_ip_payload_addr, ip_payload_addr, ip_payload_len);

                        dev_pack_send_info_t *inf = malloc(sizeof(dev_pack_send_info_t));
                        inf->dev = select;
                        inf->dat = fwd_packet;
                        inf->len = fwd_len;

                        InterlockedIncrement64((int64_t *)&out_dev[select].status.icmp);
                        enqueue(&out_dev[select].dev_tx_queue, inf);
                    }
                    break;
                    case IPPROTO_TCP:
                    {
                        InterlockedIncrement64((int64_t *)&tap_net_status.tcp);
                        tcp_hdr_t *tcp_head = ip_payload_addr;
                        // chksum = calc_tcp_checksum(ip_head->src_ip_u.src_ip_dw, ip_head->dst_ip_u.dst_ip_dw, ip_payload_addr, ip_payload_len);
                        // if (chksum == 0)
                        {
                            // printf("TCP src port:%d, dst port:%d\n", ntohs(tcp_head->source), ntohs(tcp_head->dest));
                            // printf("ack:%d, syn:%d, rst:%d, fin:%d\n", tcp_head->ack, tcp_head->syn, tcp_head->rst, tcp_head->fin);

                            int select = 0; // = ((ntohs(tcp_head->source) % 3) == 0);
                            static int sadd = 0;

                            select = tcp_port[ntohs(tcp_head->source)].out_dev_id;

                            if (tcp_head->syn)
                            {
                                select = rand() % registered_devs;

                                // select = ntohs(tcp_head->source) % 2;

                                sadd += 1;

                                if (tcp_port[ntohs(tcp_head->source)].tcp_status != TCP_STATUS_CLOSED)
                                {
                                    // printf("port %d collision\n", ntohs(tcp_head->source));
                                }
                                tcp_port[ntohs(tcp_head->source)].tcp_status = TCP_STATUS_SYN_SEND;
                                tcp_port[ntohs(tcp_head->source)].out_dev_id = select;
                            }
                            else if (tcp_head->rst || tcp_head->fin)
                            {
                                tcp_port[ntohs(tcp_head->source)].tcp_status = TCP_STATUS_CLOSED;
                            }
                            else
                            {
                                if (tcp_port[ntohs(tcp_head->source)].tcp_status == TCP_STATUS_ESTABLISHED)
                                {
                                    // if((rand() % 100) > 80)
                                    //     break;
                                }
                                else
                                {
                                    // printf("port %d closed\n", ntohs(tcp_head->source));

                                    break;
                                }
                            }

                            size_t fwd_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                            UINT8 *fwd_packet = malloc(fwd_len);
                            assert(fwd_packet);
                            eth_header_t *fwd_eth_hdr = (void *)fwd_packet;
                            // printf("sel:%s\n", out_dev[select].dev_path);

                            memcpy(fwd_eth_hdr->src_mac, out_dev[select].dev_mac, ETH_ALEN);
                            memcpy(fwd_eth_hdr->dst_mac, out_dev[select].gateway_mac, ETH_ALEN);
                            fwd_eth_hdr->eth_type = htons(ETHERTYPE_IP);

                            void *fwd_ip_head = (void *)&fwd_packet[sizeof(eth_header_t)];
                            memcpy(fwd_ip_head, ip_head, ntohs(ip_head->total_length));

                            ip_hdr_t *fwd_ip_h = fwd_ip_head;
                            fwd_ip_h->checksum = 0;
                            // fwd_ip_h->ttl -= 1;

                            void *fwd_ip_payload_addr = (void *)&fwd_packet[sizeof(eth_header_t) + fwd_ip_h->header_len * 4];
                            tcp_hdr_t *fwd_tcp_head = fwd_ip_payload_addr;

                            fwd_ip_h->src_ip_u.src_ip_dw = out_dev[select].ip;

                            fwd_ip_h->checksum = calc_ip_checksum((UINT16 *)fwd_ip_head, fwd_ip_h->header_len * 4);

                            memcpy(fwd_ip_payload_addr, ip_payload_addr, ip_payload_len);

                            fwd_tcp_head->checksum = 0;

                            fwd_tcp_head->checksum = calc_tcp_checksum(fwd_ip_h->src_ip_u.src_ip_dw, fwd_ip_h->dst_ip_u.dst_ip_dw, fwd_ip_payload_addr, ip_payload_len);
                            if (!fwd_tcp_head->checksum)
                                fwd_tcp_head->checksum = 0xFFFF;

                            dev_pack_send_info_t *inf = malloc(sizeof(dev_pack_send_info_t));
                            inf->dev = select;
                            inf->dat = fwd_packet;
                            inf->len = fwd_len;
                            inf->tcp_port = ntohs(tcp_head->source);

                            enqueue(&out_dev[select].dev_tx_queue, inf);
                            
                            InterlockedIncrement64((int64_t *)&out_dev[select].status.tcp);
                            /*
                                                        if (pcap_sendpacket(out_dev[select].fp, // Adapter
                                                                            fwd_packet,         // buffer with the packet
                                                                            fwd_len             // size
                                                                            ) < 0)
                                                        {
                                                            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(out_dev[select].fp));
                                                            out_dev[select].connected = FALSE;
                                                            tcp_port[ntohs(tcp_head->source)].tcp_status = TCP_STATUS_CLOSED;
                                                        }

                                                        free(fwd_packet);
                            */
                        }
                    }
                    break;
                    case IPPROTO_UDP:
                    {
                        InterlockedIncrement64((int64_t *)&tap_net_status.udp);
                        // udp_hdr_t *udp_head = ip_payload_addr;
                        if (ip_head->dst_ip_u.dst_ip[0] < 253)
                        {

                            int select = rand() % registered_devs; // = ((ntohs(tcp_head->source) % 3) == 0);
                            // static int sadd = 0;

                            size_t fwd_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                            UINT8 *fwd_packet = malloc(fwd_len);
                            assert(fwd_packet);
                            eth_header_t *fwd_eth_hdr = (void *)fwd_packet;
                            // printf("sel:%s\n", out_dev[select].dev_path);

                            memcpy(fwd_eth_hdr->src_mac, out_dev[select].dev_mac, ETH_ALEN);
                            memcpy(fwd_eth_hdr->dst_mac, out_dev[select].gateway_mac, ETH_ALEN);
                            fwd_eth_hdr->eth_type = htons(ETHERTYPE_IP);

                            void *fwd_ip_head = (void *)&fwd_packet[sizeof(eth_header_t)];
                            memcpy(fwd_ip_head, ip_head, ntohs(ip_head->total_length));

                            ip_hdr_t *fwd_ip_h = fwd_ip_head;
                            fwd_ip_h->checksum = 0;
                            // fwd_ip_h->ttl -= 1;

                            void *fwd_ip_payload_addr = (void *)&fwd_packet[sizeof(eth_header_t) + fwd_ip_h->header_len * 4];
                            udp_hdr_t *fwd_udp_head = fwd_ip_payload_addr;

                            fwd_ip_h->src_ip_u.src_ip_dw = out_dev[select].ip;

                            fwd_ip_h->checksum = calc_ip_checksum((UINT16 *)fwd_ip_head, fwd_ip_h->header_len * 4);

                            memcpy(fwd_ip_payload_addr, ip_payload_addr, ip_payload_len);

                            fwd_udp_head->checksum = 0;

                            fwd_udp_head->checksum = calc_udp_checksum(fwd_ip_h->src_ip_u.src_ip_dw, fwd_ip_h->dst_ip_u.dst_ip_dw, fwd_ip_payload_addr, ip_payload_len);
                            if (!fwd_udp_head->checksum)
                                fwd_udp_head->checksum = 0xFFFF;

                            dev_pack_send_info_t *inf = malloc(sizeof(dev_pack_send_info_t));
                            inf->dev = select;
                            inf->dat = fwd_packet;
                            inf->len = fwd_len;

                            enqueue(&out_dev[select].dev_tx_queue, inf);
                            InterlockedIncrement64((int64_t *)&out_dev[select].status.udp);

                        }
                    }
                    break;
                    }
                }
            }
        }
    }
    break;

    default:
        break;
    }
    // for(int i = 0; i < 16; i++)
    //{
    //     printf("%02X ", frame_dat[i]);
    // }
    // printf("\n");

    free(frame_dat);
    return NULL;
}

DWORD WINAPI tap_rx_thread(LPVOID arg)
{
    while (1)
    {
        void *dat = dequeue(&tap_rx_queue);
        frame_rx(dat);
    }
    return 0;
}

int get_adapter_ip(output_dev_t *dev)
{

    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    int ret = 2;

    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL)
    {
        printf("Error allocating memory.\n");
        return 1;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL)
        {
            printf("Error allocating memory.\n");
            return 1;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
    {
        pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            if (!strcmp(pAdapter->AdapterName, dev->dev_guid))
            {

                printf("\ndev name: %s\n", pAdapter->Description);
                printf("\ndev GUID: %s\n", pAdapter->AdapterName);
                printf("IP Address: %s\n", pAdapter->IpAddressList.IpAddress.String);
                printf("Gateway IP: %s\n", pAdapter->GatewayList.IpAddress.String);
                printf("MAC: ");
                print_mac(pAdapter->Address);
                printf("\n");

                dev->ip = inet_addr(pAdapter->IpAddressList.IpAddress.String);
                dev->gateway_ip = inet_addr(pAdapter->GatewayList.IpAddress.String);
                memcpy(dev->dev_mac, pAdapter->Address, ETH_ALEN);

                if (pAdapter->GatewayList.IpAddress.String[0] != '\0')
                {
                    DWORD dwDestIP = inet_addr(pAdapter->GatewayList.IpAddress.String);
                    DWORD dwSrcIP = inet_addr(pAdapter->IpAddressList.IpAddress.String);

                    BYTE macAddr[6] = {0};
                    ULONG macAddrLen = 6;
                    if (SendARP(dwDestIP, dwSrcIP, macAddr, &macAddrLen) == NO_ERROR)
                    {
                        printf("Gateway MAC: ");
                        print_mac(macAddr);
                        printf("\n");
                        memcpy(dev->gateway_mac, macAddr, ETH_ALEN);
                        ret = 0;
                    }
                    else
                    {
                        printf("ARP Failed.\n");
                        printf("\n");
                    }
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    else
    {
        printf("GetAdaptersInfo failed with error: %ld\n", dwRetVal);
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return ret;
}

void dev_thread_rx(u_char *param,
                   const struct pcap_pkthdr *header,
                   const u_char *pkt_data)
{

    output_dev_t *devInfo = (output_dev_t *)param;
    UINT8 *frame_dat = (void *)pkt_data;
    eth_header_t *eth_head = (void *)frame_dat;

    // info("IN src_mac:");
    // print_mac(eth_head->src_mac);
    // info("   dst_mac:");
    // print_mac(eth_head->dst_mac);
    // info("   eth_type:%04X\n", eth_head->eth_type);

    if (htons(eth_head->eth_type) == ETHERTYPE_IP)
    {
        void *ip_head_addr = (void *)&frame_dat[sizeof(eth_header_t)];
        ip_hdr_t *ip_head = ip_head_addr;
        if (ip_head->version == 4)
        {
            // UINT32 chksum = calc_ip_checksum((UINT16 *)ip_head_addr, ip_head->header_len * 4);
            // if (!chksum)
            if (ip_head->dst_ip_u.dst_ip_dw == devInfo->ip)
            {
                void *ip_payload_addr = (void *)(((UINT32 *)ip_head_addr) + ip_head->header_len);
                size_t ip_payload_len = ntohs(ip_head->total_length) - ip_head->header_len * 4;

                if (ip_head->dst_ip_u.dst_ip_dw == devInfo->ip)
                {
                    // printf("IN IP packet: src:");
                    // print_ip(ip_head->src_ip_u.src_ip);
                    // printf("  dst:");
                    // print_ip(ip_head->dst_ip_u.dst_ip);
                    // printf("  len: %d\n", ntohs(ip_head->total_length));

                    switch (ip_head->protocol)
                    {
                    case IPPROTO_ICMP:
                    {
                        
                        InterlockedIncrement64((int64_t *)&tap_net_status.icmp);
                        InterlockedIncrement64((int64_t *)&devInfo->status.icmp);

                        size_t fwd_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                        UINT8 *fwd_packet = malloc(fwd_len);
                        assert(fwd_packet);
                        eth_header_t *fwd_eth_hdr = (void *)fwd_packet;

                        memcpy(fwd_eth_hdr->src_mac, self_mac, ETH_ALEN);
                        memcpy(fwd_eth_hdr->dst_mac, TAP_DEV_MAC, ETH_ALEN);
                        fwd_eth_hdr->eth_type = htons(ETHERTYPE_IP);

                        void *fwd_ip_head = (void *)&fwd_packet[sizeof(eth_header_t)];
                        memcpy(fwd_ip_head, ip_head, ntohs(ip_head->total_length));

                        ip_hdr_t *fwd_ip_h = fwd_ip_head;
                        fwd_ip_h->checksum = 0;
                        // fwd_ip_h->ttl -= 1;
                        void *fwd_ip_payload_addr = (void *)&fwd_packet[sizeof(eth_header_t) + fwd_ip_h->header_len * 4];

                        fwd_ip_h->dst_ip_u.dst_ip_dw = defConf.ip.S_un.S_addr;
                        fwd_ip_h->checksum = calc_ip_checksum((UINT16 *)fwd_ip_head, fwd_ip_h->header_len * 4);

                        memcpy(fwd_ip_payload_addr, ip_payload_addr, ip_payload_len);

                        // frame_tx(fwd_packet, fwd_len);
                        struct frame_tx_info *frame_tx_inf = malloc(sizeof(struct frame_tx_info));
                        frame_tx_inf->dat = fwd_packet;
                        frame_tx_inf->len = fwd_len;
                        enqueue(&tap_tx_queue, frame_tx_inf);
                    }
                    break;

                    case IPPROTO_UDP:
                    {
                        
                        InterlockedIncrement64((int64_t *)&tap_net_status.udp);
                        InterlockedIncrement64((int64_t *)&devInfo->status.udp);
                        // udp_hdr_t *udp_head = ip_payload_addr;
                        if (ip_head->dst_ip_u.dst_ip[0] < 253)
                        {

                            size_t fwd_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                            UINT8 *fwd_packet = malloc(fwd_len);
                            assert(fwd_packet);
                            eth_header_t *fwd_eth_hdr = (void *)fwd_packet;

                            memcpy(fwd_eth_hdr->src_mac, self_mac, ETH_ALEN);
                            memcpy(fwd_eth_hdr->dst_mac, TAP_DEV_MAC, ETH_ALEN);
                            fwd_eth_hdr->eth_type = htons(ETHERTYPE_IP);

                            void *fwd_ip_head = (void *)&fwd_packet[sizeof(eth_header_t)];
                            memcpy(fwd_ip_head, ip_head, ntohs(ip_head->total_length));

                            ip_hdr_t *fwd_ip_h = fwd_ip_head;
                            fwd_ip_h->checksum = 0;
                            // fwd_ip_h->ttl -= 1;
                            void *fwd_ip_payload_addr = (void *)&fwd_packet[sizeof(eth_header_t) + fwd_ip_h->header_len * 4];
                            udp_hdr_t *fwd_udp_head = fwd_ip_payload_addr;

                            fwd_ip_h->dst_ip_u.dst_ip_dw = defConf.ip.S_un.S_addr;

                            fwd_ip_h->checksum = calc_ip_checksum((UINT16 *)fwd_ip_head, fwd_ip_h->header_len * 4);

                            memcpy(fwd_ip_payload_addr, ip_payload_addr, ip_payload_len);

                            fwd_udp_head->checksum = 0;

                            fwd_udp_head->checksum = calc_udp_checksum(fwd_ip_h->src_ip_u.src_ip_dw, fwd_ip_h->dst_ip_u.dst_ip_dw, fwd_ip_payload_addr, ip_payload_len);
                            if (!fwd_udp_head->checksum)
                                fwd_udp_head->checksum = 0xFFFF;

                            // frame_tx(fwd_packet, fwd_len);
                            struct frame_tx_info *frame_tx_inf = malloc(sizeof(struct frame_tx_info));
                            frame_tx_inf->dat = fwd_packet;
                            frame_tx_inf->len = fwd_len;
                            enqueue(&tap_tx_queue, frame_tx_inf);
                        }
                    }
                    break;

                    case IPPROTO_TCP:
                    {
                        
                        InterlockedIncrement64((int64_t *)&tap_net_status.tcp);
                        InterlockedIncrement64((int64_t *)&devInfo->status.tcp);
                        tcp_hdr_t *tcp_head = ip_payload_addr;
                        // chksum = calc_tcp_checksum(ip_head->src_ip_u.src_ip_dw, ip_head->dst_ip_u.dst_ip_dw, ip_payload_addr, ip_payload_len);
                        // if (chksum == 0)
                        {
                            // printf("IN TCP src port:%d, dst port:%d\n", ntohs(tcp_head->source), ntohs(tcp_head->dest));
                            // printf("ack:%d, syn:%d, rst:%d, fin:%d\n", tcp_head->ack, tcp_head->syn, tcp_head->rst, tcp_head->fin);

                            if (tcp_head->syn && tcp_head->ack)
                            {
                                if (tcp_port[ntohs(tcp_head->dest)].tcp_status == TCP_STATUS_SYN_SEND)
                                {
                                    tcp_port[ntohs(tcp_head->dest)].tcp_status = TCP_STATUS_ESTABLISHED;
                                }
                            }
                            else if (tcp_head->rst || tcp_head->fin)
                            {
                                tcp_port[ntohs(tcp_head->dest)].tcp_status = TCP_STATUS_CLOSED;
                            }

                            size_t fwd_len = ntohs(ip_head->total_length) + sizeof(eth_header_t);
                            UINT8 *fwd_packet = malloc(fwd_len);
                            assert(fwd_packet);
                            eth_header_t *fwd_eth_hdr = (void *)fwd_packet;

                            memcpy(fwd_eth_hdr->src_mac, self_mac, ETH_ALEN);
                            memcpy(fwd_eth_hdr->dst_mac, TAP_DEV_MAC, ETH_ALEN);
                            fwd_eth_hdr->eth_type = htons(ETHERTYPE_IP);

                            void *fwd_ip_head = (void *)&fwd_packet[sizeof(eth_header_t)];
                            memcpy(fwd_ip_head, ip_head, ntohs(ip_head->total_length));

                            ip_hdr_t *fwd_ip_h = fwd_ip_head;
                            fwd_ip_h->checksum = 0;
                            // fwd_ip_h->ttl -= 1;
                            void *fwd_ip_payload_addr = (void *)&fwd_packet[sizeof(eth_header_t) + fwd_ip_h->header_len * 4];
                            tcp_hdr_t *fwd_tcp_head = fwd_ip_payload_addr;

                            fwd_ip_h->dst_ip_u.dst_ip_dw = defConf.ip.S_un.S_addr;

                            fwd_ip_h->checksum = calc_ip_checksum((UINT16 *)fwd_ip_head, fwd_ip_h->header_len * 4);

                            memcpy(fwd_ip_payload_addr, ip_payload_addr, ip_payload_len);

                            fwd_tcp_head->checksum = 0;

                            fwd_tcp_head->checksum = calc_tcp_checksum(fwd_ip_h->src_ip_u.src_ip_dw, fwd_ip_h->dst_ip_u.dst_ip_dw, fwd_ip_payload_addr, ip_payload_len);
                            if (!fwd_tcp_head->checksum)
                                fwd_tcp_head->checksum = 0xFFFF;

                            // frame_tx(fwd_packet, fwd_len);
                            struct frame_tx_info *frame_tx_inf = malloc(sizeof(struct frame_tx_info));
                            frame_tx_inf->dat = fwd_packet;
                            frame_tx_inf->len = fwd_len;
                            enqueue(&tap_tx_queue, frame_tx_inf);

                            // free(fwd_packet);
                        }

                        break;
                    }
                    }
                }
            }
        }
    }
    else if (htons(eth_head->eth_type) == ETHERTYPE_ARP)
    {
#if 0 
        arp_header_t *arp_head = (void *)&frame_dat[sizeof(eth_header_t)];
            info("DEV sender mac:");
            print_mac(arp_head->sender_mac);
            info("  sender ip:");
            print_ip(arp_head->sender_ip);

            info("  target mac:");
            print_mac(arp_head->target_mac);
            info("  target ip:");
            print_ip(arp_head->target_ip);
            info("  arp_type:%04X\n", arp_head->opcode);
        if (arp_head->target_ip_4 ==  devInfo->ip )
        {

            int reply_len = sizeof(eth_header_t) + sizeof(arp_header_t);
            UINT8 *reply = malloc(reply_len);
            assert(reply);
            eth_header_t *rep_eth = (void *)reply;
            arp_header_t *rep_arp = (void *)&reply[sizeof(eth_header_t)];

            memcpy(rep_eth->src_mac, devInfo->dev_mac, ETH_ALEN);
            memcpy(rep_eth->dst_mac, arp_head->sender_mac, ETH_ALEN);
            rep_eth->eth_type = htons(ETHERTYPE_ARP);
            rep_arp->hdwr_type = htons(1);          // Ethernet
            rep_arp->protocol_type = htons(0x0800); // ETHERTYPE_IP
            rep_arp->hdwr_sz = ETH_ALEN;
            rep_arp->protocol_sz = 4;
            rep_arp->opcode = htons(ARP_REPLY);

            rep_arp->sender_ip_4 = devInfo->ip;
            memcpy(rep_arp->sender_mac, devInfo->dev_mac, ETH_ALEN);

            rep_arp->target_ip_4 = arp_head->sender_ip_4;
            memcpy(rep_arp->target_mac, arp_head->sender_mac, ETH_ALEN);

            //frame_tx(reply, reply_len);

            dev_pack_send_info_t *inf = malloc(sizeof(dev_pack_send_info_t));
            inf->dev = devInfo->index;
            inf->dat = reply;
            inf->len = reply_len;

            enqueue(&dev_tx_queue, inf);
        }
#endif
    }
}

typedef struct dev_pack_recv_info_t
{
    output_dev_t *devInfo;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
} dev_pack_recv_info_t;

DWORD WINAPI dev_recv_pack_thread(LPVOID arg)
{
    uint32_t dev_idx = (uint64_t)arg;
    while (1)
    {
        dev_pack_recv_info_t *inf = dequeue(&out_dev[dev_idx].dev_rx_queue);
        // printf("dev:%d\n", inf->devInfo->index);
        dev_thread_rx((u_char *)inf->devInfo, inf->header, inf->pkt_data);
        free((void *)inf->pkt_data);
        free(inf);
    }
    return 0;
}

DWORD WINAPI outdev_thread(LPVOID dat)
{
    output_dev_t *devInfo = dat;
    char errbuf[1024] = {0};
    int res;

restart:
    devInfo->ip = 0;
    do
    {
        res = get_adapter_ip(devInfo);
        if (res == 1)
            return 0;
        if (res == 2)
            Sleep(3000);
    } while (res);
    devInfo->connected = TRUE;

    if ((devInfo->fp = pcap_create(devInfo->dev_path, // name of the device
                                   errbuf             // error buffer
                                   )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", " ");
        return 0;
    }

    res = pcap_set_promisc(devInfo->fp, 0);
    printf(pcap_geterr(devInfo->fp));
    printf(" pcap_set_promisc: %d\n", res);

    // res = pcap_set_immediate_mode(devInfo->fp, 1);
    // printf(pcap_geterr(devInfo->fp));
    // printf(" pcap_set_immediate_mode: %d\n", res);

    res = pcap_set_timeout(devInfo->fp, 8);
    printf(pcap_geterr(devInfo->fp));
    printf(" pcap_set_timeout: %d\n", res);

    // res = pcap_set_buffer_size(devInfo->fp, 1024 * 24);
    // printf(pcap_geterr(devInfo->fp));
    // printf(" pcap_set_buffer_size: %d\n", res);


    if (pcap_set_tstamp_type(devInfo->fp, PCAP_TSTAMP_HOST_LOWPREC) != 0)
    {
        printf("setting timestamp not supported\n");
    }

    if (pcap_activate(devInfo->fp) != 0)
    {
        fprintf(stderr, "Could not activate pcap handle: %s\n", pcap_geterr(devInfo->fp));
        return 2;
    }
    
    bpf_u_int32 net = 0;
    struct bpf_program bfp;
    if (pcap_setdirection(devInfo->fp, PCAP_D_IN) != 0) {
        fprintf(stderr, "Couldn't set direction: %s\n", pcap_geterr(devInfo->fp)); 

        char filter_exp[256];
        struct in_addr dev_self_ip;
        dev_self_ip.S_un.S_addr = devInfo->ip;
        sprintf(filter_exp, "not src host %s", inet_ntoa(dev_self_ip));
        if (pcap_compile(devInfo->fp, &bfp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(devInfo->fp));
        }

        if (pcap_setfilter(devInfo->fp, &bfp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(devInfo->fp)); 
        }
    }
    // res = pcap_setdirection(devInfo->fp, PCAP_D_IN);
    // printf(pcap_geterr(devInfo->fp));
    // printf(" pcap_setdirection: %d\n", res);

    res = pcap_setbuff(devInfo->fp, 1024 * 128);
    // res = pcap_setbuff(devInfo->fp, 65536);
    printf(pcap_geterr(devInfo->fp));
    printf(" pcap_set_buffer_size: %d\n", res);

    // res = pcap_setmintocopy(devInfo->fp, 1024 * 4);
    // printf(pcap_geterr(devInfo->fp));
    // printf(" pcap_setmintocopy: %d\n", res);

    for (int i = 0; i < MAX_THREADS; i++)
        devInfo->recv_thread[i] = CreateThread(NULL, 0, dev_recv_pack_thread, (LPVOID)(intptr_t)devInfo->index, 0, NULL);
    for (int i = 0; i < MAX_THREADS; i++)
        devInfo->send_thread[i] = CreateThread(NULL, 0, dev_send_pack_thread, (LPVOID)(intptr_t)devInfo->index, 0, NULL);

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while ((res = pcap_next_ex(devInfo->fp, &header, &pkt_data)) >= 0)
    {
        if (res == 0)
        {
            // Timeout elapsed
            if (devInfo->connected == FALSE)
            {
                printf("outdev_thread fin:%d\n", res);
                goto restart;
            }
            continue;
        }

        dev_pack_recv_info_t *inf = malloc(sizeof(dev_pack_recv_info_t));
        inf->devInfo = devInfo;
        inf->header = header;
        inf->pkt_data = malloc(header->len);
        memcpy((void *)inf->pkt_data, pkt_data, header->len);

        enqueue(&devInfo->dev_rx_queue, inf);
        
        out_dev[devInfo->index].status.rx_packets ++;
        out_dev[devInfo->index].status.rx_bytes += header->len;
        //InterlockedIncrement64((int64_t *)&out_dev[devInfo->index].status.rx_packets);

        // enqueue(&dev_rx_queue, inf);

        // dev_thread_rx((u_char *)devInfo, header, pkt_data);
    }

    // res = pcap_loop(devInfo->fp, 0, dev_thread_rx, (u_char *)devInfo);
    // printf("outdev_thread fin:%d\n", res);
    // goto restart;

    return 0;
}

void print_net_status(net_status_t *st)
{
    printf("TX: %6.2f MBytes/s\t", (st->tx_bytes - st->tx_last_bytes)/(STATUS_UPDATE_TIME/1000)/1e6f);
    printf("Total: %6.2f MB\t", (st->tx_bytes)/1e6f);
    printf("Packets: %9lld\n", st->tx_packets);

    printf("RX: %6.2f MBytes/s\t", (st->rx_bytes - st->rx_last_bytes)/(STATUS_UPDATE_TIME/1000)/1e6f);
    printf("Total: %6.2f MB\t", (st->rx_bytes)/1e6f);
    printf("Packets: %9lld\n", st->rx_packets);

    printf("ARP:%4lld\tICMP:%4lld\tTCP:%9lld\tUDP:%9lld\n\n",st->arp, st->icmp, st->tcp, st->udp);

    st->tx_last_bytes = st->tx_bytes;
    st->rx_last_bytes = st->rx_bytes;

}

DWORD WINAPI status_thread(LPVOID dat)
{
    Sleep(2000);

    while (1)
    {
        printf("\n");
        system("cls");
        SetColor(RED, BLACK);
        printf("---------- Inbound ---------\n");
        SetColor(GREEN, BLACK);
        printf("IP: %s\n", inet_ntoa(defConf.ip));
        printf("Gateway: %s\n\n", inet_ntoa(defConf.gateway));
        print_net_status(&tap_net_status);

        
        SetColor(RED, BLACK);
        printf("---------- Outbound ---------\n");

        for(int i = 0; i < registered_devs; i++)
        {
            SetColor(YELLOW, BLACK);
            printf("[%d]: %s\n", i, out_dev[i].dev_desc);
            if(!out_dev[i].connected)
            {
                SetColor(RED, BLACK);
                printf("[Disconnected]\n");
            }
            SetColor(GREEN, BLACK);
            print_net_status(&out_dev[i].status);

        }


        SetColor(WHITE, BLACK);
        Sleep(STATUS_UPDATE_TIME);
    }
}

int main(int argc, char *argv[])
{
    wchar_t tap_id[255];
    wchar_t tap_path[1024];
    char tap_adapter_name[512];
    char netsh_cmd[512];
    int res = 0;
    BOOL bResult = FALSE;
    OVERLAPPED lc;
    memset(tap_id, 0, sizeof(tap_id));
    memset(tap_path, 0, sizeof(tap_path));
    memset(&lc, 0, sizeof(lc));
    memset(out_dev, 0, sizeof(out_dev));
    memset(tcp_port, 0, sizeof(tcp_port));
    memset(&tap_net_status, 0, sizeof(tap_net_status));

    char errbuf[1024] = {0};
    char tmp_str[1024];

    system("cls");
    SetColor(WHITE, BLACK);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup failed.\n");
        return 1;
    }

    initQueue(&tap_rx_queue);
    initQueue(&tap_tx_queue);

    const char *iniFilePath = "./config.ini";

    if (argc < 2)
    {

        GetPrivateProfileString("inbound", "ip", "none", tmp_str, sizeof(tmp_str), iniFilePath);
        if (strcmp(tmp_str, "none"))
            defConf.ip.S_un.S_addr = inet_addr(tmp_str);
        else
        {
            printf("Error configuration in 'config.ini'!");
            exit(1);
        }
        GetPrivateProfileString("inbound", "gateway", "none", tmp_str, sizeof(tmp_str), iniFilePath);
        if (strcmp(tmp_str, "none"))
            defConf.gateway.S_un.S_addr = inet_addr(tmp_str);
        GetPrivateProfileString("inbound", "mask", "none", tmp_str, sizeof(tmp_str), iniFilePath);
        if (strcmp(tmp_str, "none"))
            defConf.mask.S_un.S_addr = inet_addr(tmp_str);

        printf("Virtual IP: %s\n", inet_ntoa(defConf.ip));
        printf("Virtual Gateway: %s\n", inet_ntoa(defConf.gateway));
        printf("mask: %s\n", inet_ntoa(defConf.mask));

        for (int i = 0; i < MAX_OUTPUT_DEVS; i++)
        {
            char dev_seq[64];
            sprintf(dev_seq, "dev%d", i);
            GetPrivateProfileString("outbound", dev_seq, "none", tmp_str, sizeof(tmp_str), iniFilePath);
            if (strcmp(tmp_str, "none"))
            {
                out_dev[registered_devs].dev_path = calloc(1, 1024);
                out_dev[registered_devs].dev_guid = calloc(1, 1024);
                sprintf(out_dev[registered_devs].dev_path, NPF_PREFIX "%s", tmp_str);
                sprintf(out_dev[registered_devs].dev_guid, "%s", tmp_str);
                out_dev[registered_devs].index = registered_devs;
                registered_devs++;
            }
        }
    }
    // printf("rd:%s\n", username);

    pcap_if_t *ifaces = NULL;
    pcap_if_t *dev = NULL;
    pcap_addr_t *addr = NULL;

    if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
    {
        fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
        return 2;
    }

    if (0 != pcap_findalldevs(&ifaces, errbuf))
    {
        fprintf(stderr, "Failed to get list of devices: %s\n", errbuf);
        return 2;
    }

    for (dev = ifaces; dev != NULL; dev = dev->next)
    {
        printf("%s, (%s):\n", dev->description, dev->name);
        for (int i = 0; i < MAX_OUTPUT_DEVS; i++)
        {
            if (out_dev[i].dev_path && !strcmp(out_dev[i].dev_path, dev->name))
            {
                printf("[selected]");
                out_dev[i].ip = 1;
                out_dev[i].dev_desc = calloc(1, 1024);
                strcpy(out_dev[i].dev_desc, dev->description);
            }
        }
        for (addr = dev->addresses; addr != NULL; addr = addr->next)
        {
            if (((struct sockaddr_in *)(addr->addr))->sin_addr.S_un.S_addr)
            {
                printf("   IP Address: ");
                print_inaddr(((struct sockaddr_in *)(addr->addr))->sin_addr);
                printf("\n\n");
            }
        }
    }

    if (argc == 2)
        exit(0);

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    res = get_tap_instance(tap_id, tap_adapter_name);
    if (res)
        return -1;

    self_ip = defConf.gateway;

    sprintf(
        netsh_cmd,
        "netsh interface ip set address %s static %d.%d.%d.%d %d.%d.%d.%d %d.%d.%d.%d",
        tap_adapter_name,
        defConf.ip.S_un.S_un_b.s_b1,
        defConf.ip.S_un.S_un_b.s_b2,
        defConf.ip.S_un.S_un_b.s_b3,
        defConf.ip.S_un.S_un_b.s_b4,

        defConf.mask.S_un.S_un_b.s_b1,
        defConf.mask.S_un.S_un_b.s_b2,
        defConf.mask.S_un.S_un_b.s_b3,
        defConf.mask.S_un.S_un_b.s_b4,

        self_ip.S_un.S_un_b.s_b1,
        self_ip.S_un.S_un_b.s_b2,
        self_ip.S_un.S_un_b.s_b3,
        self_ip.S_un.S_un_b.s_b4);
    res = system(netsh_cmd);
    if (res)
        return -1;

    // sprintf(netsh_cmd, "netsh interface ipv4 set subinterface %s mtu=%d store=persistent",
    //     tap_adapter_name, 1500);
    // res = system(netsh_cmd);
    // if (res)return -1;

    sprintf(netsh_cmd, "netsh interface ipv4 set interface \"%s\" metric=1",
            tap_adapter_name);
    res = system(netsh_cmd);
    if (res)
        return -1;

    wprintf(L"device id:%S\n", tap_id);
    swprintf_s(tap_path, sizeof(tap_path) / sizeof(wchar_t), L"\\\\.\\Global\\%s.tap", tap_id);
    wprintf(L"tap_path:%S\n", tap_path);

    tuntap = CreateFileW(tap_path,                     // drive to open
                         GENERIC_READ | GENERIC_WRITE, // no access to the drive
                         FILE_SHARE_READ |             // share mode
                             FILE_SHARE_WRITE,
                         NULL,                                         // default security attributes
                         OPEN_EXISTING,                                // disposition
                         FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, // file attributes
                         NULL);                                        // do not copy file attributes

    if (tuntap == INVALID_HANDLE_VALUE) // cannot open the drive
    {
        printf("Failed to open tap device.\n");
        return (-1);
    }

    bResult = DeviceIoControl(tuntap,                // device to be queried
                              TAP_WIN_IOCTL_GET_MTU, // operation to perform
                              NULL, 0,               // input buffer
                              &MTU, sizeof(MTU),     // output buffer
                              0,                     // bytes returned
                              &lc);                  // synchronous I/O
    MAX_FRAME_SZ = MTU + 14;
    printf("mtu: %d\n", MTU);

    bResult = DeviceIoControl(tuntap,                            // device to be queried
                              TAP_WIN_IOCTL_GET_MAC,             // operation to perform
                              NULL, 0,                           // input buffer
                              &TAP_DEV_MAC, sizeof(TAP_DEV_MAC), // output buffer
                              0,                                 // bytes returned
                              &lc);                              // synchronous I/O

    printf("tap dev mac: ");
    print_mac(TAP_DEV_MAC);
    printf("\n");

    UINT32 value = 0x1;
    bResult = DeviceIoControl(tuntap,                         // device to be queried
                              TAP_WIN_IOCTL_SET_MEDIA_STATUS, // operation to perform
                              &value, 4,                      // input buffer
                              NULL, 0,                        // output buffer
                              0,                              // # bytes returned
                              &lc);                           // synchronous I/O

    printf("tap device start:%d\n", bResult);

    for (int i = 0; i < MAX_OUTPUT_DEVS; i++)
    {
        if (out_dev[i].ip)
        {
            // pthread_create(&out_dev[i].thread, NULL, outdev_thread, &out_dev[i]);
            initQueue(&out_dev[i].dev_rx_queue);
            initQueue(&out_dev[i].dev_tx_queue);
            out_dev[i].thread = CreateThread(NULL, 0, outdev_thread, (LPVOID)(intptr_t)&out_dev[i], 0, NULL);
        }
        else
        {
            if (out_dev[i].dev_path)
                free(out_dev[i].dev_path);
            if (out_dev[i].dev_guid)
                free(out_dev[i].dev_guid);
            out_dev[i].dev_path = NULL;
            out_dev[i].dev_guid = NULL;
        }
    }
    // HANDLE threads[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; i++)
        tap_send_thread[i] = CreateThread(NULL, 0, tap_tx_thread, (LPVOID)(intptr_t)i, 0, NULL);
    for (int i = 0; i < MAX_THREADS; i++)
        tap_recv_thread[i] = CreateThread(NULL, 0, tap_rx_thread, (LPVOID)(intptr_t)i, 0, NULL);

    OVERLAPPED rxOverLapped;
    CreateThread(NULL, 0, status_thread, (LPVOID)(intptr_t)0, 0, NULL);

    while (1)
    {
        // Sleep(1000);
        UINT8 *frame = malloc(MAX_FRAME_SZ);
        assert(frame);
        DWORD size;
        // pthread_t thread;
    
        rxOverLapped.hEvent = CreateEvent(0, 0, 0, "");
        ReadFile(tuntap, frame, MAX_FRAME_SZ, &size, &rxOverLapped);
        WaitForSingleObject(rxOverLapped.hEvent, INFINITE);
        // rxOverLapped.OffsetHigh += size;
        // tap_net_status.rx_bytes += size;
        tap_net_status.rx_packets += 1;

        enqueue(&tap_rx_queue, frame);
    }
}
