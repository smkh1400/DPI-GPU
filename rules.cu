#include <cuda_runtime.h>
#include "rulesGraph.cuh"
#include "rules.cuh"
#include "header.h"
#include <stdio.h>

#define swapEndian16(x) ((uint16_t)(((x) >> 8) | ((x) << 8)))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htons(x) swapEndian16(x)
#define ntohs(x) swapEndian16(x)
#else
#define htons(x) x
#define ntohs(x) x
#endif

#define LOAD_UINT8(p) (*((uint8_t *)(p)))
#define LOAD_UINT16(p) (uint16_t)(LOAD_UINT8(p) | (LOAD_UINT8(p + 1) << 8))
#define LOAD_UINT32(p) (uint32_t)((LOAD_UINT16(p)) | ((LOAD_UINT16(p + 2)) << 16))

__device__ __forceinline__ static bool d_strcmp(const uint8_t *a, const uint8_t *b, size_t n)                           // TODO
{
    size_t counter = 0;
    for (size_t i = 0; i < n; i++)
        counter += (a[i] == b[i]);

    return (counter == n);
}

__device__ static bool isFieldInHeader(HeaderBuffer *h, const uint8_t *field, size_t fieldLen)                          // TODO : using trie
{
    bool result = false;
    size_t len = (h->packetLen < HEADER_BUFFER_DATA_MAX_SIZE) * (h->packetLen) + (h->packetLen >= HEADER_BUFFER_DATA_MAX_SIZE) * (HEADER_BUFFER_DATA_MAX_SIZE);
    for (size_t i = h->headerOffset; i < len - fieldLen; i++)
        result |= d_strcmp(h->headerData + i, field, fieldLen);

    return result;
}

__device__ static void ethr_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    out->checkConditionResult = true;

    EthrHeader *hdr = (EthrHeader *)(p->getHeaderData());
    out->extractedCondition = &(hdr->ethrType);
    out->calculatedOffset = sizeof(EthrHeader);
}

__device__ static void vlanEthr_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    EthrVlanHeader *hdr = (EthrVlanHeader *)p->getHeaderData();
    out->checkConditionResult = (hdr->vlanTag.tpid == ntohs(0x8100));

    out->extractedCondition = &(hdr->ethrType);

    out->calculatedOffset = sizeof(EthrVlanHeader);
}
__device__ static void ethrArp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint16_t ethrType = *((uint16_t *)cond);
    out->checkConditionResult = (ethrType == htons(0x0806));

    out->extractedCondition = NULL;

    out->calculatedOffset = 0;
}

__device__ static void ethrIpv4_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint16_t ethrType = *((uint16_t *)cond);
    out->checkConditionResult = (ethrType == htons(0x0800));

    IPv4Header *hdr = (IPv4Header *)(p->getHeaderData());
    out->extractedCondition = &(hdr->protocol);

    size_t optionSize = (hdr->ihl * 4) - 20;
    out->calculatedOffset = sizeof(IPv4Header) + optionSize;
}

__device__ static void ipv4Icmp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint8_t protocol = *((uint8_t *)cond);
    out->checkConditionResult = (protocol == 0x01);

    out->extractedCondition = NULL;

    out->calculatedOffset = sizeof(ICMPHeader);
}

__device__ static void ipv4Udp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint8_t protocol = *((uint8_t *)cond);
    out->checkConditionResult = (protocol == 0x11);

    UDPHeader *hdr = (UDPHeader *)(p->getHeaderData());
    out->extractedCondition = &(hdr->sport);

    out->calculatedOffset = sizeof(UDPHeader);
}

__device__ static void udpDns_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint16_t sport = *((uint16_t *)cond);
    uint16_t dport = *((uint16_t *)(cond + 2));
    out->checkConditionResult = ((sport == htons(0x0035)) || (dport == htons(0x0035)));

    out->extractedCondition = NULL;

    out->calculatedOffset = sizeof(DNSHeader);
}

__device__ static void udpRtp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    int16_t rtp_len = p->packetLen - p->headerOffset;
    RTPHeader *hdr = (RTPHeader *)p->getHeaderData();
    out->checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >= 96);

    out->calculatedOffset = 0;

    out->extractedCondition = NULL;
}

__device__ static void udpSip_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint16_t sport = LOAD_UINT16(cond);
    uint16_t dport = LOAD_UINT16(cond + 2);

    const uint8_t field[] = "CSeq:";
    out->checkConditionResult = ((sport == htons(5060) || dport == htons(5060)) && (isFieldInHeader(p, field, sizeof(field) - 1)));

    

    out->calculatedOffset = 0;

    out->extractedCondition = NULL;
}

__device__ static void udpGtp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    GTPHeader *hdr = (GTPHeader *)p->getHeaderData();

    uint8_t version = hdr->version;
    uint8_t msgType = hdr->messageType;
    out->checkConditionResult = (((version) == 0b010 || (version) == 0b001) && (msgType) == 0xFF);

    int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
    out->calculatedOffset = (hdr->E) * (*((uint8_t *)(p->getHeaderData() + normalSize)) * 4 + 1) + normalSize; // 1 : 'extension header length' size

    out->extractedCondition = NULL;
}

__device__ static void gtpIpv4_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    IPv4Header *hdr = (IPv4Header *)p->getHeaderData();
    uint8_t version = hdr->version;

    out->checkConditionResult = version;

    out->extractedCondition = &(hdr->protocol);

    out->calculatedOffset = hdr->ihl * 4;
}

__device__ static void ipv4Tcp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint8_t protocol = *((uint8_t *)cond);
    out->checkConditionResult = (protocol == 0x06);

    TCPHeader *hdr = (TCPHeader *)(p->getHeaderData());
    int headerLength = hdr->headerLength * 4;
    out->extractedCondition = (&hdr->source);

    out->calculatedOffset = headerLength;
}

__device__ static void tcpHttp_inspector(HeaderBuffer *p, void *cond, InspectorFuncOutput *out)
{
    uint16_t sport = *((uint16_t *)cond);
    uint16_t dport = *((uint16_t *)cond + 2);

    const uint8_t *fields[] = {"HTTP"};                                                 // TODO : Adding other fields
    out->checkConditionResult = (isFieldInHeader(p, fields[0], 4) && (sport == htons(0x0050) || dport == htons(0x0050)));

    out->extractedCondition = NULL;

    out->calculatedOffset = 0;
}

__global__ void registerRules(RuleTrie *trie)
{
    trie->initTrie();

    Rule_t rules[] = {
        REGISTER_RULE(Rule_EthrArp, {ethr_inspector, ethrArp_inspector}),
        REGISTER_RULE(Rule_VlanEthrArp, {vlanEthr_inspector, ethrArp_inspector}),

        REGISTER_RULE(Rule_EthrIPv4Icmp, {ethr_inspector, ethrIpv4_inspector, ipv4Icmp_inspector}),
        REGISTER_RULE(Rule_VlanEthrIPv4Icmp, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Icmp_inspector}),

        REGISTER_RULE(Rule_EthrIpv4UdpDns, {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpDns_inspector}),          // note: DNS should be registered before UDP-RTP
        REGISTER_RULE(Rule_VlanEthrIpv4UdpDns, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpDns_inspector}),

        REGISTER_RULE(Rule_EthrIpv4UdpRtp, {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector}),
        REGISTER_RULE(Rule_VlanEthrIpv4UdpRtp, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector}),

        REGISTER_RULE(Rule_EthrIpv4UdpSip, {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpSip_inspector}),
        REGISTER_RULE(Rule_VlanEthrIpv4UdpSip, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpSip_inspector}),

        REGISTER_RULE(Rule_EthrIpv4UdpGtpIpv4UdpRtp, {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector}),
        REGISTER_RULE(Rule_VlanEthrIpv4UdpGtpIpv4UdpRtp, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector}),

        REGISTER_RULE(Rule_EthrIpv4UdpGtpIpv4UdpSip, {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpSip_inspector}),
        REGISTER_RULE(Rule_VlanEthrIpv4UdpGtpIpv4UdpSip, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpSip_inspector}),

        REGISTER_RULE(Rule_EthrIpv4TcpHttp, {ethr_inspector, ethrIpv4_inspector, ipv4Tcp_inspector, tcpHttp_inspector}),
        REGISTER_RULE(Rule_VlanEthrIpv4TcpHttp, {vlanEthr_inspector, ethrIpv4_inspector, ipv4Tcp_inspector, tcpHttp_inspector}),
    };

    trie->insertRules(rules, sizeof(rules) / sizeof(rules[0]));
}