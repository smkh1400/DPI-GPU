#include <cuda_runtime.h>
#include "rulesGraph.cuh"
#include "rules.cuh"
#include "header.h"
#include <stdio.h>

#define swapEndian16(x)     ((uint16_t) (((x) >> 8) | ((x) << 8)))

#if __BYTE_ORDER == __LITTLE_ENDIAN
    #define htons(x) swapEndian16(x)
    #define ntohs(x) swapEndian16(x)
#else 
    #define htons(x) x
    #define ntohs(x) x
#endif

#define LOAD_UINT8(p)               (*((uint8_t*) (p)))
#define LOAD_UINT16(p)              (uint16_t) (LOAD_UINT8(p)    | (LOAD_UINT8(p+1)    << 8))
#define LOAD_UINT32(p)              (uint32_t) ((LOAD_UINT16(p)) | ((LOAD_UINT16(p+2)) << 16))

__device__ __forceinline__ static bool d_strcmp(const uint8_t* a, const uint8_t* b, size_t n) {
    size_t counter = 0;
    for(size_t i = 0 ; i < n ; i++) {
        counter += (a[i] == b[i]);
    }

    return (counter==n);
}

__device__ static bool isFieldInHeader(HeaderBuffer* h, const uint8_t* field, size_t fieldLen) {
    bool result = false;
    for(size_t i = 0 ; i < HEADER_BUFFER_DATA_MAX_SIZE-fieldLen ; i++) {
        result = (result) | d_strcmp(h->headerData + i, field, fieldLen);
    } 

    return result;
}

__managed__ int counter_ = 0;


__device__ static void ethr_inspector (HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    out->checkConditionResult = true;

    EthrHeader* hdr = (EthrHeader*) (p->getHeaderData());
    out->extractedCondition = &(hdr->ethrType);
    out->calculatedOffset = sizeof(EthrHeader);
}

__device__ static void vlanEthr_inspector (HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    EthrVlanHeader* hdr = (EthrVlanHeader*) p->getHeaderData();
    out->checkConditionResult = (hdr->vlanTag.tpid == ntohs(0x8100));

    out->extractedCondition = &(hdr->ethrType);

    out->calculatedOffset = sizeof(EthrVlanHeader);
}
__device__ static void ethrArp_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    uint16_t ethrType = *((uint16_t*) cond);
    out->checkConditionResult = (ethrType == htons(0x0806));

    out->extractedCondition = NULL;

    if(out->checkConditionResult) atomicAdd(&counter_, 1);

    // printf("%d\n", counter_);

    out->calculatedOffset = 0;
}

__device__ static void ethrIpv4_inspector (HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    uint16_t ethrType = *((uint16_t*) cond);
    out->checkConditionResult = (ethrType == htons(0x0800));


    IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
    out->extractedCondition = &(hdr->protocol);

    size_t optionSize = (hdr->ihl*4)-20;
    out->calculatedOffset = sizeof(IPv4Header) + optionSize;
}

__device__ static void ipv4Icmp_inspector (HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {

    uint8_t protocol = *((uint8_t*) cond);
    out->checkConditionResult = (protocol == 0x01);

    

    out->extractedCondition = NULL;

    out->calculatedOffset = sizeof(ICMPHeader);
}

__device__ static void ipv4Udp_inspector (HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    
    uint8_t protocol = *((uint8_t*) cond);
    out->checkConditionResult = (protocol == 0x11);

    UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
    out->extractedCondition = &(hdr->sport);

    out->calculatedOffset = sizeof(UDPHeader);

}

__device__ static void udpDns_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {

    uint16_t sport = *((uint16_t*) cond);
    uint16_t dport = *((uint16_t*) (cond+2));
    out->checkConditionResult = ((sport == htons(0x0035)) || (dport == htons(0x0035)));

    out->extractedCondition = NULL;

    out->calculatedOffset = sizeof(DNSHeader);

}


__device__ static void udpRtp_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out){

    int16_t rtp_len = p->packetLen - p->headerOffset; 
    RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
    out->checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

    out->calculatedOffset = 0;

    out->extractedCondition = NULL;

}

__device__ static void udpSip_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {

    uint16_t sport = LOAD_UINT16(cond);
    uint16_t dport = LOAD_UINT16(cond + 2);

    const uint8_t field[] = "CSeq:";
    out->checkConditionResult = ((sport==htons(5060) || dport==htons(5060)) && (isFieldInHeader(p, field, sizeof(field)-1)));

    out->calculatedOffset = 0;

    out->extractedCondition = NULL;

}

__device__ static void udpGtp_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    
    GTPHeader* hdr = (GTPHeader*) p->getHeaderData();

    uint8_t version = hdr->version;
    uint8_t msgType = hdr->messageType;
    out->checkConditionResult = (((version) == 0b010 || (version) == 0b001) && (msgType) == 0xFF);

    int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
    out->calculatedOffset = (hdr->E) * (*((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + 1) + normalSize; // 1 : 'extension header length' size 

    out->extractedCondition = NULL;

}

__device__ static void gtpIpv4_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    
    IPv4Header* hdr = (IPv4Header*) p->getHeaderData();
    uint8_t version = hdr->version;


    out->checkConditionResult = version;

    out->extractedCondition = &(hdr->protocol);

    out->calculatedOffset = hdr->ihl*4;

}

__device__ static void ipv4Tcp_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {

    uint8_t protocol = *((uint8_t*) cond);
    out->checkConditionResult = (protocol == 0x06);

    TCPHeader* hdr = (TCPHeader*) (p->getHeaderData());
    int headerLength = hdr->headerLength*4;
    // out->extractedCondition = (p->getHeaderData() + headerLength);
    out->extractedCondition = (&hdr->source);

    out->calculatedOffset = headerLength;

}

__device__ static void tcpHttp_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {

    // uint8_t* method = (uint8_t*) cond;
    
    uint16_t sport = *((uint16_t*) cond);
    uint16_t dport = *((uint16_t*) cond + 2);

    // printf("sport is %d and dport is %d\n", sport, dport);

    const uint8_t* fields[] = {"HTTP"};
    out->checkConditionResult = (isFieldInHeader(p, fields[0], 4) && (sport == htons(0x0050) || dport == htons(0x0050))) ;

    out->extractedCondition = NULL;

    out->calculatedOffset = 0;
}

__global__ void registerRules(RuleTrie* trie) {
    Inspector_t rule_vlanEthrArp[] = {vlanEthr_inspector, ethrArp_inspector};
    Inspector_t rule_vlanEthrIpv4Icmp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Icmp_inspector};
    Inspector_t rule_ethrIpv4UdpRtp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    Inspector_t rule_ethrIpv4TcpHttp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Tcp_inspector, tcpHttp_inspector};
    Inspector_t rule_vlanEthrIpv4UdpGtpIpv4UdpRtp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    Inspector_t rule_vlanEthrIpv4UdpGtpIpv4UdpSip[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    Inspector_t rule_vlanEthrIpv4UdpDns[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpDns_inspector};
    Inspector_t rule_vlanEthrIpv4UdpRtp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    Inspector_t rule_vlanEthrIpv4TcpHttp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Tcp_inspector, tcpHttp_inspector};
    Inspector_t rule_ethrIpv4UdpGtpIpv4UdpRtp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    Inspector_t rule_ethrIpv4UdpGtpIpv4UdpSip[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    Inspector_t rule_vlanEthrIpv4UdpSip[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    Inspector_t rule_ethrIpv4UdpDns[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpDns_inspector};
    Inspector_t rule_ethrIpv4UdpSip[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    Inspector_t rule_ethrIpv4Icmp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Icmp_inspector};
    Inspector_t rule_ethrArp[] = {ethr_inspector, ethrArp_inspector};
// #define MAX         10

// #define REG_INSP(ID ,...)      {.rules = __VA_ARGS__,  .ruleId = ID, .name = #ID},

//     Inspector_t rules[MAX][MAX] = {
//         REG_INSP(Rule_EthrArp, {vlanEthr_inspector, ethrArp_inspector}),
//         {vlanEthr_inspector, ethrIpv4_inspector, ipv4Icmp_inspector}
//     };

//     trie->isertRules(rules);

//     for(int i = 0 ; i < MAX ; i++) 
//         trie->insertRule(rules[i].rules, MAX, rules[i].ruleId);

    // Inspector_t rule_ethrIpv4UdpRtp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    // Inspector_t rule_ethrIpv4TcpHttp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Tcp_inspector, tcpHttp_inspector};
    // Inspector_t rule_vlanEthrIpv4UdpGtpIpv4UdpRtp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    // Inspector_t rule_vlanEthrIpv4UdpGtpIpv4UdpSip[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    // Inspector_t rule_vlanEthrIpv4UdpDns[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpDns_inspector};
    // Inspector_t rule_vlanEthrIpv4UdpRtp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    // Inspector_t rule_vlanEthrIpv4TcpHttp[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Tcp_inspector, tcpHttp_inspector};
    // Inspector_t rule_ethrIpv4UdpGtpIpv4UdpRtp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpRtp_inspector};
    // Inspector_t rule_ethrIpv4UdpGtpIpv4UdpSip[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpGtp_inspector, gtpIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    // Inspector_t rule_vlanEthrIpv4UdpSip[] = {vlanEthr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    // Inspector_t rule_ethrIpv4UdpDns[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpDns_inspector};
    // Inspector_t rule_ethrIpv4UdpSip[] = {ethr_inspector, ethrIpv4_inspector, ipv4Udp_inspector, udpSip_inspector};
    // Inspector_t rule_ethrIpv4Icmp[] = {ethr_inspector, ethrIpv4_inspector, ipv4Icmp_inspector};
    // Inspector_t rule_ethrArp[] = {ethr_inspector, ethrArp_inspector};


    trie->initTrie();

    trie->insertRule(rule_vlanEthrArp, RULE_SIZE(rule_vlanEthrArp), Rule_VlanEthrArp);

    trie->insertRule(rule_ethrIpv4Icmp, RULE_SIZE(rule_ethrIpv4Icmp), Rule_EthrIPv4Icmp);
    trie->insertRule(rule_vlanEthrIpv4Icmp, RULE_SIZE(rule_vlanEthrIpv4Icmp), Rule_VlanEthrIPv4Icmp);

    trie->insertRule(rule_ethrIpv4UdpDns, RULE_SIZE(rule_ethrIpv4UdpDns), Rule_EthrIpv4UdpDns);
    trie->insertRule(rule_vlanEthrIpv4UdpDns, RULE_SIZE(rule_vlanEthrIpv4UdpDns), Rule_VlanEthrIpv4UdpDns);

    trie->insertRule(rule_ethrIpv4UdpGtpIpv4UdpRtp, RULE_SIZE(rule_ethrIpv4UdpGtpIpv4UdpRtp), Rule_EthrIpv4UdpGtpIpv4UdpRtp);
    trie->insertRule(rule_vlanEthrIpv4UdpGtpIpv4UdpRtp, RULE_SIZE(rule_vlanEthrIpv4UdpGtpIpv4UdpRtp), Rule_VlanEthrIpv4UdpGtpIpv4UdpRtp);

    trie->insertRule(rule_ethrIpv4UdpRtp, RULE_SIZE(rule_ethrIpv4UdpRtp), Rule_EthrIpv4UdpRtp);
    trie->insertRule(rule_vlanEthrIpv4UdpRtp, RULE_SIZE(rule_vlanEthrIpv4UdpRtp), Rule_VlanEthrIpv4UdpRtp);
    trie->insertRule(rule_ethrArp, RULE_SIZE(rule_ethrArp), Rule_EthrArp);

    trie->insertRule(rule_ethrIpv4UdpGtpIpv4UdpSip, RULE_SIZE(rule_ethrIpv4UdpGtpIpv4UdpSip), Rule_EthrIpv4UdpGtpIpv4UdpSip);
    trie->insertRule(rule_vlanEthrIpv4UdpGtpIpv4UdpSip, RULE_SIZE(rule_vlanEthrIpv4UdpGtpIpv4UdpSip), Rule_VlanEthrIpv4UdpGtpIpv4UdpSip);

    trie->insertRule(rule_ethrIpv4TcpHttp, RULE_SIZE(rule_ethrIpv4TcpHttp), Rule_EthrIpv4TcpHttp);
    trie->insertRule(rule_vlanEthrIpv4TcpHttp, RULE_SIZE(rule_vlanEthrIpv4TcpHttp), Rule_VlanEthrIpv4TcpHttp);

    trie->insertRule(rule_ethrIpv4UdpSip, RULE_SIZE(rule_ethrIpv4UdpSip), Rule_EthrIpv4UdpSip);
    trie->insertRule(rule_vlanEthrIpv4UdpSip, RULE_SIZE(rule_vlanEthrIpv4UdpSip), Rule_VlanEthrIpv4UdpSip);


    // printf("ethr_inspector:%ld\n", (uintptr_t) ethr_inspector);
    // printf("vlanEthr_inspector:%ld\n", (uintptr_t) vlanEthr_inspector);
    // printf("ethrArp_inspector:%ld\n", (uintptr_t) ethrArp_inspector);
    // printf("ethrIpv4_inspector:%ld\n", (uintptr_t) ethrIpv4_inspector);
    // printf("ipv4Icmp_inspector:%ld\n", (uintptr_t) ipv4Icmp_inspector);
    // printf("ipc4Udp_inspector:%ld\n", (uintptr_t) ipv4Udp_inspector);
    // printf("udpRtp_inspector:%ld\n", (uintptr_t) udpRtp_inspector);
    // printf("udpGtp_inspector:%ld\n", (uintptr_t) udpGtp_inspector);
    // printf("gtpIpv4_inspector:%ld\n", (uintptr_t) gtpIpv4_inspector);
    // printf("udpDns_inspector:%ld\n", (uintptr_t) udpDns_inspector);
    // printf("udpSip_inspector:%ld\n", (uintptr_t) udpSip_inspector);

    // trie->printTrie(&(trie->root), 0);
}   