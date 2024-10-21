#ifndef DPI_HEADERS_H_
#define DPI_HEADERS_H_

#include <stdint.h>
#include <features.h>

typedef uint8_t         IPv4[4];
typedef uint8_t         MAC[6];

typedef struct __attribute__((packed)){
    MAC         dmac;               // destination mac address
    MAC         smac;               // source mac address
    uint16_t    ethrType;           // ethernet type
} EthrHeader;

typedef struct __attribute__((packed)){
    uint16_t    tpid;               // protocol
    uint16_t    tci;
} VlanHeader;

typedef struct __attribute__((packed)){
    MAC         dmac;               // destination mac address
    MAC         smac;               // source mac address
    VlanHeader  vlanTag;            // vlan tag
    uint16_t    ethrType;           // ethernet type
} EthrVlanHeader;

typedef struct __attribute__((packed)){
    uint16_t htype;     // Hardware type (e.g., Ethernet is 1)
    uint16_t ptype;     // Protocol type (e.g., IPv4 is 0x0800)
    uint8_t hlen;       // Hardware address length (e.g., Ethernet MAC is 6)
    uint8_t plen;       // Protocol address length (e.g., IPv4 address is 4)
    uint16_t oper;      // Operation (e.g., request is 1, reply is 2)
    MAC sha;            // Sender hardware address (e.g., MAC address)
    IPv4 spa;           // Sender protocol address (e.g., IPv4 address)
    MAC tha;            // Target hardware address (e.g., MAC address)
    IPv4 tpa;           // Target protocol address (e.g., IPv4 address)
} ARPHeader;

typedef struct __attribute__((packed)){
    uint8_t type;        // ICMP message type
    uint8_t code;        // ICMP message code
    uint16_t checksum;   // ICMP checksum
    // content based on type and code
} ICMPHeader;

typedef struct  __attribute__((packed)) {
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
    uint8_t     ihl : 4;
    uint8_t     version : 4;
#elif (__BYTE_ORDER == __BIG_ENDIAN)
    uint8_t     version : 4;
    uint8_t     ihl : 4;
#endif
    uint8_t     tos;
    uint16_t    totalLen;
    uint16_t    id;
    uint16_t    flags;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    checkSum;
    IPv4        saddr;
    IPv4        daddr;
} IPv4Header;

typedef struct __attribute__((packed)) {
    uint16_t source;      /* Source port */
    uint16_t dest;        /* Destination port */
    uint32_t seq;         /* Sequence number */
    uint32_t ack_seq;     /* Acknowledgment number */
    
    uint8_t res:4;      /* Reserved */
    uint8_t headerLength: 4;      /* Data offset */
    // uint8_t dataOffset;

    uint16_t flags:8;     /* Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN) */
    uint16_t window;      /* Window size */
    uint16_t check;       /* Checksum */
    uint16_t urg_ptr;     /* Urgent pointer */
} TCPHeader;

typedef struct __attribute__((packed)){
    uint16_t id;         // Identification number

    // Flags
    // uint16_t rd : 1;     // Recursion Desired
    // uint16_t tc : 1;     // Truncated Message
    // uint16_t aa : 1;     // Authoritative Answer
    // uint16_t opcode : 4; // Purpose of the message
    // uint16_t qr : 1;     // Query/Response Flag

    // uint16_t rcode : 4;  // Response code
    // uint16_t cd : 1;     // Checking Disabled
    // uint16_t ad : 1;     // Authenticated Data
    // uint16_t z : 1;      // Reserved for future use
    // uint16_t ra : 1;     // Recursion Available

    uint16_t flags;

    uint16_t qdcount;    // Number of question entries
    uint16_t ancount;    // Number of answer entries
    uint16_t nscount;    // Number of authority entries
    uint16_t arcount;    // Number of resource entries
} DNSHeader;


typedef struct __attribute__((packed)){
    uint16_t    sport;          // source port
    uint16_t    dport;          // destination port
    uint16_t    length;         // header length
    uint16_t    checkSum;       
} UDPHeader;

typedef struct __attribute__((packet)){
    uint16_t    sport;
    uint16_t    dport;
    uint32_t    verfTag;
    uint32_t    checksum;
} SCTPHeader;

typedef struct __attribute__((packed)) {
    uint8_t content_type;      // Content Type (1 byte)
    uint16_t version;          // Version (2 bytes)
    uint16_t length;           // Length (2 bytes)
} TLSHeader;

typedef struct __attribute__((packed)) {
    uint8_t PN : 1;
    uint8_t S : 1;
    uint8_t E : 1;
    uint8_t empty : 1;
    uint8_t payloadType : 1;
    uint8_t version : 3;
    uint8_t messageType;
    uint16_t length;
    uint32_t TEID;
    // optional headers
    // uint16_t seg_num;
    // uint8_t N_PDU;
    // uint8_t next_ext_hdr_typ;
} GTPHeader;

typedef struct __attribute__((packed)) {
    unsigned int cc:4;        // CSRC count (4 bits)
    unsigned int x:1;         // Extension (1 bit)
    unsigned int p:1;         // Padding (1 bit)
    unsigned int version:2;   // Version (2 bits)
    unsigned int pt:7;        // Payload type (7 bits)
    unsigned int marker:1;    // Marker bit (1 bit)

    uint16_t seq;             // Sequence number (16 bits)

    uint32_t timestamp;       // Timestamp (32 bits)

    uint32_t ssrc;            // Synchronization source (SSRC) identifier (32 bits)

    // Optional: CSRC list
    uint32_t csrc[1];         // CSRC list (0 to 15 items, each 32 bits)
} RTPHeader;

#endif // DPI_HEADERS_H_