#include <cuda_runtime.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <endian.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#include "rulesGraph.cuh"
#include "header.h"
#include "gputimer.cuh"

#define CHECK_CUDA_ERROR(fun)                                                   \
{                                                                               \
    cudaError_t err = fun;                                                      \
    if(err != cudaSuccess) {                                                    \
        printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
        return -1;                                                               \
    }                                                                           \
}

#define __DEBUG_ENABLE      (1)
#define __DEBUG_LOG(...)         {if(__DEBUG_ENABLE) {printf(__VA_ARGS__);}}

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

__global__ static void registerRuleGraph(InspectorNode* nodes, InspectorNode* root) {
    InspectorNode* ethr_insp = &nodes[0];
    ethr_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        out->checkConditionResult = true;

        EthrHeader* hdr = (EthrHeader*) (p->getHeaderData());
        out->extractedCondition = &(hdr->ethrType);

        out->calculatedOffset = sizeof(EthrHeader);
    });

    InspectorNode* ethrArp_insp = &nodes[1];
    ethrArp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        uint16_t ethrType = *((uint16_t*) cond);
        out->checkConditionResult = (ethrType == htons(0x0806));

        out->extractedCondition = NULL;

        out->calculatedOffset = 0;

        
    }, Rule_EthrArp);


    InspectorNode* ethrIpv4_insp = &nodes[2];
    ethrIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint16_t ethrType = *((uint16_t*) cond);
        out->checkConditionResult = (ethrType == htons(0x0800));

        IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
        out->extractedCondition = &(hdr->protocol);

        size_t optionSize = (hdr->ihl*4)-20;
        out->calculatedOffset = sizeof(IPv4Header) + optionSize;

        
    });

    InspectorNode* ethrIpv4Icmp_insp = &nodes[3];
    ethrIpv4Icmp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint8_t protocol = *((uint8_t*) cond);
        out->checkConditionResult = (protocol == 0x01);

        out->extractedCondition = NULL;

        out->calculatedOffset = sizeof(ICMPHeader);


        
    }, Rule_EthrIPv4ICMP);

    InspectorNode* ethrIpv4Udp_insp = &nodes[4];
    ethrIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {


        uint8_t protocol = *((uint8_t*) cond);
        out->checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out->extractedCondition = &(hdr->sport);

        out->calculatedOffset = sizeof(UDPHeader);

        
    });

    InspectorNode* ethrIpv4UdpDns_insp = &nodes[5];
    ethrIpv4UdpDns_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint16_t sport = *((uint16_t*) cond);
        uint16_t dport = *((uint16_t*) (cond+2));
        out->checkConditionResult = ((sport == htons(0x0035)) || (dport == htons(0x0035)));

        out->extractedCondition = NULL;

        out->calculatedOffset = sizeof(DNSHeader);

        
    }, Rule_EthrIpv4UdpDns);

    InspectorNode* ethrIpv4Tcp_insp = &nodes[6];
    ethrIpv4Tcp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint8_t protocol = *((uint8_t*) cond);
        out->checkConditionResult = (protocol == 0x06);

        TCPHeader* hdr = (TCPHeader*) (p->getHeaderData());
        int headerLength = hdr->headerLength * 4;
        out->extractedCondition = (p->getHeaderData() + headerLength);

        out->calculatedOffset = headerLength;

        
    }, Rule_EthrIpv4Tcp);

    InspectorNode* ethrIpv4TcpHttp_insp = &nodes[7];
    ethrIpv4TcpHttp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint8_t* method = (uint8_t*) cond;
        out->checkConditionResult = 
            (method[0]=='G' && method[1]=='E' && method[2]=='T') ||
            (method[0]=='P' && method[1]=='O' && method[2]=='S' && method[3]=='T') ||
            (method[0]=='P' && method[1]=='U' && method[2]=='T') ||
            (method[0]=='D' && method[1]=='E' && method[2]=='L' && method[3]=='E' && method[4]=='T' && method[5]=='E') ||
            (method[0]=='H' && method[1]=='E' && method[2]=='A' && method[3]=='D') ||
            (method[0]=='O' && method[1]=='P' && method[2]=='T' && method[3]=='I' && method[4]=='O' && method[5]=='N' && method[6]=='S') ||
            (method[0]=='P' && method[1]=='A' && method[2]=='T' && method[3]=='C' && method[4]=='H') ||
            (method[0]=='T' && method[1]=='R' && method[2]=='A' && method[3]=='C' && method[4]=='E') ||
            (method[0]=='C' && method[1]=='O' && method[2]=='N' && method[3]=='N' && method[4]=='E' && method[5]=='C' && method[6]=='T');

        out->extractedCondition = NULL;

        out->calculatedOffset = 0;

        
    }, Rule_EthrIpv4TcpHttp);    

    InspectorNode* ethrIpv4UdpRtp_insp = &nodes[8];
    ethrIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out->checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;
    }, Rule_EthrIpv4UdpRtp);

    InspectorNode* ethrIpv4UdpSip_insp = &nodes[21];
    ethrIpv4UdpSip_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        uint16_t sport = *((uint16_t*) cond);
        uint16_t dport = *((uint16_t*) (cond+2));

        const uint8_t field[] = "CSeq:";
        out->checkConditionResult = ((sport==htons(5060) || dport==htons(5060)) && (isFieldInHeader(p, field, sizeof(field)-1)));

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;
    }, Rule_EthrIpv4UdpSip);
    

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    InspectorNode* ethrVlan_insp = &nodes[9];
    ethrVlan_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        EthrVlanHeader* hdr = (EthrVlanHeader*) p->getHeaderData();
        out->checkConditionResult = (hdr->vlanTag.tpid == ntohs(0x8100));

        out->extractedCondition = &(hdr->ethrType);

        out->calculatedOffset = sizeof(EthrVlanHeader);

        
    });

    InspectorNode* ethrVlanIpv4_insp = &nodes[10];
    ethrVlanIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint16_t ethrType = *((uint16_t*) cond);
        out->checkConditionResult = (ethrType == htons(0x0800));

        IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
        out->extractedCondition = &(hdr->protocol);

        size_t optionSize = (hdr->ihl*4)-20;
        out->calculatedOffset = sizeof(IPv4Header) + optionSize;

        
    });

    InspectorNode* ethrVlanIpv4Udp_insp = &nodes[11];
    ethrVlanIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint8_t protocol = *((uint8_t*) cond);
        out->checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out->extractedCondition = &(hdr->sport);

        out->calculatedOffset = sizeof(UDPHeader);

        
    });

    InspectorNode* ethrVlanIpv4UdpRtp_insp = &nodes[12];
    ethrVlanIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out->checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;

        
    }, Rule_EthrVlanIpv4UdpRtp);


    InspectorNode* ethrVlanIpv4UdpSip_insp = &nodes[23];
    ethrVlanIpv4UdpSip_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint16_t sport = *((uint16_t*) cond);
        uint16_t dport = *((uint16_t*) (cond+2));
        const uint8_t field[] = "CSeq:";
        out->checkConditionResult = ((sport == htons(5060)) && (dport == htons(5060)) && (isFieldInHeader(p, "CSeq:", sizeof(field)-1)));

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;

        
    }, Rule_EthrVlanIpv4UdpSip);

    InspectorNode* ethrVlanIpv4UdpGtp_insp = &nodes[13];
    ethrVlanIpv4UdpGtp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        GTPHeader* hdr = (GTPHeader*) p->getHeaderData();

        out->checkConditionResult = (((hdr->version) == 0b010 || (hdr->version) == 0b001) && (hdr->payloadType == 1) && (hdr->messageType) == 0xFF);

        int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
        out->calculatedOffset = (hdr->E) * (*((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + 1) + normalSize; // 1 : 'extension header length' size 

        out->extractedCondition = NULL;

        
    });

    InspectorNode* ethrVlanIpv4UdpGtpIpv4_insp = &nodes[14];
    ethrVlanIpv4UdpGtpIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        IPv4Header* hdr = (IPv4Header*) p->getHeaderData();

        out->checkConditionResult = (hdr->version == 4);

        out->extractedCondition = &(hdr->protocol);

        out->calculatedOffset = hdr->ihl*4;

        
    });


    InspectorNode* ethrVlanIpv4UdpGtpIpv4Udp_insp = &nodes[15];
    ethrVlanIpv4UdpGtpIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint8_t protocol = *((uint8_t*) cond);
        out->checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out->extractedCondition = &(hdr->sport);

        out->calculatedOffset = sizeof(UDPHeader);

        
    });

    InspectorNode* ethrVlanIpv4UdpGtpIpv4UdpRtp_insp = &nodes[16];
    ethrVlanIpv4UdpGtpIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out->checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;

        
    }, Rule_EthrVlanIpv4UdpGtpIpv4UdpRtp);

    InspectorNode* ethrVlanIpv4UdpGtpIpv4UdpSip_insp = &nodes[24];
    ethrVlanIpv4UdpGtpIpv4UdpSip_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        uint16_t sport = LOAD_UINT16(cond);
        uint16_t dport = LOAD_UINT16(cond+2);
        const uint8_t field[] = "CSeq:";
        out->checkConditionResult = ((sport == htons(5060)) && (dport == htons(5060)) && (isFieldInHeader(p, "CSeq:", sizeof(field)-1)));

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;
    }, Rule_EthrVlanIpv4UdpGtpIpv4UdpSip);

//////////////////////////////////////////////////////////////

    InspectorNode* ethrIpv4UdpGtp_insp = &nodes[17];
    ethrIpv4UdpGtp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        GTPHeader* hdr = (GTPHeader*) p->getHeaderData();

        uint8_t version = hdr->version;
        uint8_t msgType = hdr->messageType;
        out->checkConditionResult = (((version) == 0b010 || (version) == 0b001) && (msgType) == 0xFF);

        int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
        out->calculatedOffset = (hdr->E) * (*((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + 1) + normalSize; // 1 : 'extension header length' size 

        out->extractedCondition = NULL;

        
    });


    InspectorNode* ethrIpv4UdpGtpIpv4_insp = &nodes[18];
    ethrIpv4UdpGtpIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        IPv4Header* hdr = (IPv4Header*) p->getHeaderData();
        uint8_t version = hdr->version;


        out->checkConditionResult = version;

        out->extractedCondition = &(hdr->protocol);

        out->calculatedOffset = hdr->ihl*4;

        
    });

    InspectorNode* ethrIpv4UdpGtpIpv4Udp_insp = &nodes[19];
    ethrIpv4UdpGtpIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        uint8_t protocol = *((uint8_t*) cond);
        out->checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out->extractedCondition = &(hdr->sport);

        out->calculatedOffset = sizeof(UDPHeader);

        
    });

    InspectorNode* ethrIpv4UdpGtpIpv4UdpRtp_insp = &nodes[20];
    ethrIpv4UdpGtpIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {


        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out->checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;

        
    }, Rule_EthrIpv4UdpGtpIpv4UdpRtp);

    InspectorNode* ethrIpv4UdpGtpIpv4UdpSip_insp = &nodes[22];
    ethrIpv4UdpGtpIpv4UdpSip_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        uint16_t sport = LOAD_UINT16(cond);
        uint16_t dport = LOAD_UINT16(cond+2);

        const uint8_t field[] = "CSeq:";
        out->checkConditionResult = ((sport == htons(5060)) && (dport == htons(5060)) && (isFieldInHeader(p, "CSeq:", sizeof(field)-1)));

        out->calculatedOffset = 0;

        out->extractedCondition = NULL;
    }, Rule_EthrIpv4UdpGtpIpv4UdpSip);
    
    root->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond, InspectorFuncOutput* out)  {
        out->checkConditionResult = true;
        out->extractedCondition = NULL;
        out->calculatedOffset = 0;
        
    });

    root->addChild(ethr_insp);
    root->addChild(ethrVlan_insp);

    ethrVlan_insp->addChild(ethrVlanIpv4_insp);
    ethrVlanIpv4_insp->addChild(ethrVlanIpv4Udp_insp);
    ethrVlanIpv4Udp_insp->addChild(ethrVlanIpv4UdpRtp_insp);
    ethrVlanIpv4Udp_insp->addChild(ethrVlanIpv4UdpGtp_insp);
    ethrVlanIpv4Udp_insp->addChild(ethrVlanIpv4UdpSip_insp);
    ethrVlanIpv4UdpGtp_insp->addChild(ethrVlanIpv4UdpGtpIpv4_insp);
    ethrVlanIpv4UdpGtpIpv4_insp->addChild(ethrVlanIpv4UdpGtpIpv4Udp_insp);
    ethrVlanIpv4UdpGtpIpv4Udp_insp->addChild(ethrVlanIpv4UdpGtpIpv4UdpRtp_insp);
    ethrVlanIpv4UdpGtpIpv4Udp_insp->addChild(ethrVlanIpv4UdpGtpIpv4UdpSip_insp);

    ethr_insp->addChild(ethrIpv4_insp);
    ethrIpv4_insp->addChild(ethrIpv4Udp_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpDns_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpRtp_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpGtp_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpSip_insp);
    ethrIpv4UdpGtp_insp->addChild(ethrIpv4UdpGtpIpv4_insp);
    ethrIpv4UdpGtpIpv4_insp->addChild(ethrIpv4UdpGtpIpv4Udp_insp);
    ethrIpv4UdpGtpIpv4Udp_insp->addChild(ethrIpv4UdpGtpIpv4UdpRtp_insp);
    ethrIpv4UdpGtpIpv4Udp_insp->addChild(ethrIpv4UdpGtpIpv4UdpSip_insp);
}

__global__ void performProcess(PacketBuffer* packets, size_t packetCount, InspectorNode* rootNode) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    HeaderBuffer h;
    InspectorFuncOutput out;

    if(idx < packetCount) {
        for(size_t i = 0 ; i < HEADER_BUFFER_DATA_MAX_SIZE ; i++)
            h.headerData[i] = packets[idx].packetData[i];
        
        h.packetLen = packets[idx].packetLen;

        rootNode->processNode(&h, NULL, &out);
        packets[idx].ruleId = h.ruleId;
    }       
}

#define _GB_                (1024.0*1024.0*1024.0)             
#define _MB_                (1024.0*1024.0)             
#define _KB_                (1024.0)             

#define HOST_RAM_SIZE       (60 * _GB_)    
#define DEVICE_RAM_SIZE     (20 * _GB_)

#define MIN(x, y)           ((x) < (y) ? (x) : (y))

#define MAX_PACKET_IN_RAM            ((long long) ((long long) MIN(HOST_RAM_SIZE, DEVICE_RAM_SIZE)) / (sizeof(PacketBuffer)))
#define DEVICE_TOTAL_THREADS                (196608)

#define PACKET_BUFFER_CHUNK_SIZE         (MIN(DEVICE_TOTAL_THREADS, MAX_PACKET_IN_RAM))
// #define PACKET_BUFFER_CHUNK_SIZE         (196608)


static int readPacketChunk(PacketBuffer* h_packets, pcap_t* handle, size_t* counter, size_t* packetSize) {
    *counter = 0;
    *packetSize = 0;
    int result;
    const u_char *packet;
    struct pcap_pkthdr *header;

    while((*counter < PACKET_BUFFER_CHUNK_SIZE)) {

        if(!((result = (pcap_next_ex(handle, &header, &packet))) >= 0)) break;

        PacketBuffer p(packet, header->caplen);

        h_packets[(*counter)] = p;
        *counter += 1;
        *packetSize += p.packetLen;
        // if(counter*sizeof(PacketBuffer) >= DEVICE_RAM_SIZE) break;     
    }

    return result;
}   

static bool hasPcapExtension(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if(ext != NULL && strcmp(ext, ".pcap") == 0) 
        return true;
    return false;
}

static pcap_t* openPcapFile(const char* pcapFilePath) {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = (pcap_t*) malloc(sizeof(pcap_t*));
    
    handle = pcap_open_offline(pcapFilePath, errBuf);

    return handle;
} 

static int processPcapFile(const char* pcapFilePath, bool verbose) {
    pcap_t* handle;

    if(!hasPcapExtension(pcapFilePath)) 
    {
        printf("Invalid Extension, Excepted .pcap\n");
        return -1;
    }

    handle = openPcapFile(pcapFilePath);
    if(handle == NULL)
    {
        printf("Unable To Open Pcap File : %s\n", pcapFilePath);
        return -1;
    } 

    FILE* fd = fopen("rtp_packets.txt", "w");
    
    size_t pcapFileSize;

    {
        FILE* fd = fopen(pcapFilePath, "r");


        fseek(fd, 0, SEEK_END);
        pcapFileSize = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        fclose(fd);
    }


    PacketBuffer* h_packets = (PacketBuffer*) calloc(PACKET_BUFFER_CHUNK_SIZE, sizeof(PacketBuffer));
    if(h_packets == NULL)   
    {
        printf("Unable to allocate Packets\n");
        return -1;
    }

    if(verbose) printf("Pcap File %s Opened\n", pcapFilePath);

    PacketBuffer* d_packets;
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packets, PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketBuffer)));

    float duration;
    GPUTimer timer;

    InspectorNode* d_root;
    InspectorNode* d_nodes;

    size_t stackSize;
    CHECK_CUDA_ERROR(cudaThreadGetLimit(&stackSize, cudaLimitStackSize));

    // if(stackSize < (HEADER_BUFFER_DATA_MAX_SIZE*))
        CHECK_CUDA_ERROR(cudaThreadSetLimit(cudaLimitStackSize, 1024*20));

    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_nodes, 30*sizeof(InspectorNode)));
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_root, sizeof(InspectorNode)));

    registerRuleGraph<<<1,1>>>(d_nodes, d_root);
    CHECK_CUDA_ERROR(cudaDeviceSynchronize());
    if(verbose) printf("RuleGraph Was Registered On Device\n");

    size_t counter;
    size_t packetSize;
    size_t HDPacketSize;
    size_t DHPacketSize;
    size_t chunkCounter = 0;

    size_t totalCounter = 0;
    size_t totalPacketSize = 0;
    size_t totalHDPacketSize = 0;
    size_t totalDHPacketSize = 0;

    double totalHDDuration = 0;
    double totalDHDuration = 0;
    double totalKernelDuration = 0;

    int ruleCount[Rule_Count] = {0};
    int result;

    while (1) {
        if(verbose) printf(">> Chunk %d Started\n", chunkCounter+1);

        int result = readPacketChunk(h_packets, handle, &counter, &packetSize);
        if(result < 0 && result != -2 && verbose) {
            printf("Something went wrong in reading packets(%d)\n", result);
            printf("The Error was : %s\n", pcap_geterr(handle));
            printf("The counter was %d\n", counter);
        }

        totalCounter += counter;
        totalPacketSize += packetSize;

        if(verbose) printf("%ld Packets Was Read From Pcap File\n", counter);
        
        HDPacketSize = counter*sizeof(PacketBuffer);
        timer.start();
        CHECK_CUDA_ERROR(cudaMemcpy((void*) d_packets, (void*) h_packets, HDPacketSize, cudaMemcpyHostToDevice));
        timer.end();
        duration = timer.elapsed();
        totalHDDuration += duration;
        totalHDPacketSize += HDPacketSize;

        if(verbose) printf(">> %ld Packets (%lf GB) Transfered From Host To Device \n", counter, (counter*sizeof(PacketBuffer))/(_GB_));
        if(verbose) printf("\t| Duration : %lf ms\n", duration);
        if(verbose) printf("\t| Bandwidth : %lf Gb/s\n", (counter*sizeof(PacketBuffer)*1000.0*8.0)/(_GB_*duration));
        
        int threadPerBlock = 256;
        
        timer.start();
        performProcess<<<(counter+threadPerBlock-1)/threadPerBlock,threadPerBlock>>>(d_packets, counter, d_root);
        timer.end();
        duration = timer.elapsed();
        totalKernelDuration += duration;

        if(verbose) printf(">> RuleGraph Was Processed For %d Threads Per Block \n", threadPerBlock);
        if(verbose) printf(">> %ld Packets (%.3lf GB) Processed On GPU \n", counter, (sizeof(HeaderBuffer)*counter*1.0)/(_GB_));
        if(verbose) printf("\t| Duration : %lf ms\n", duration);
        if(verbose) printf("\t| Bandwidth : %lf Gb/s\n", (sizeof(HeaderBuffer)*counter*1000.0*8.0)/(_GB_*duration));

        DHPacketSize = counter*sizeof(PacketBuffer);
        timer.start();
        CHECK_CUDA_ERROR(cudaMemcpy((void*) h_packets, (void*) d_packets, DHPacketSize, cudaMemcpyDeviceToHost));
        timer.end();
        duration = timer.elapsed();
        totalDHDuration += duration;
        totalDHPacketSize += DHPacketSize;

        if(verbose) printf(">> %ld Packets (%lf GB) Transfered From Device to Host\n", counter, (counter*sizeof(PacketBuffer))/(_GB_));
        if(verbose) printf("\t| Duration : %lf ms\n", duration);
        if(verbose) printf("\t| Bandwidth : %lf Gb/s\n", (counter*sizeof(PacketBuffer)*1000.0*8.0)/(_GB_*duration));

        for(size_t i = 0 ; i < counter ; i++) {  
            ruleCount[h_packets[i].ruleId]++;
            if(h_packets[i].ruleId == Rule_EthrIpv4UdpRtp) fprintf(fd ,"%d\n", i+1);
        }

        if(!verbose){
            printf("\033[2K\r");
            fflush(stdout);

            printf("# %0.3lf% Of %s Is Procesed", ((totalPacketSize*1.0)/(pcapFileSize*1.0))*100, pcapFilePath);
            fflush(stdout);
        }

        if (result == -2) {
            break;
        }

        chunkCounter++;
        if(verbose) printf("---------------------------------------------------------------\n\n");
    }

    if(!verbose){
        printf("\033[2K\r");
        fflush(stdout);

        printf("# 100%% Of %s Is Procesed\n", pcapFilePath);
        fflush(stdout);
    }

    pcap_close(handle);
    fclose(fd);

    printf("\t| Total Packets: %ld\n", totalCounter);

    for(size_t i = 0 ; i < Rule_Count ; i++)
        if(ruleCount[i] != 0) printf("\t| %s : %d\n", getRuleName(i), ruleCount[i]);

    printf(">> Host To Device:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n", totalHDDuration, (sizeof(HeaderBuffer)*totalCounter*8*1000.0)/(totalHDDuration*_GB_));
    printf(">> Kernel:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n", totalKernelDuration, (sizeof(HeaderBuffer)*totalCounter*8*1000.0)/(totalKernelDuration*_GB_));
    printf(">> Device To Host:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\n", totalDHDuration, (sizeof(HeaderBuffer)*totalCounter*8*1000.0)/(totalDHDuration*_GB_));
    printf("**********************************************************************************************\n\n");
    
    return 0;
}


static int processDirectory(const char* directoryPath, bool verbose) {
    struct dirent* entry;
    DIR* dp;

    dp = opendir(directoryPath);
    if(dp == NULL) {
        printf("Unable To Open Directory %s\n", directoryPath);
        return -1;
    }

    while((entry = readdir(dp)) != NULL) {
        if(entry->d_type == DT_REG && hasPcapExtension(entry->d_name)) {
            char fullPath[1024];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, entry->d_name);            
            processPcapFile(fullPath, verbose);
        }
    }

    closedir(dp);
}

#define HLEP_COMMAND_LINE       "Usage: ./ruleGraph [options] <arguments>\nAvailable Options:\n\t-f\t\t: Select The Pcap File\n\t-d\t\t: Select The Directory Containing Multiple Pcap Files\n\t-v\t\t: Make The Operation More Talkative\n\t-h\t\t: Print Help And Exit\n" 

int main(int argc, char* argv[]) {
    if(argc == 1)
    {
        printf(HLEP_COMMAND_LINE);
        return -1;
    }

    int opt, xfnd;
    xfnd = 0;
    bool processDir = false;
    bool processFile = false;
    bool verbose = false;
    char* pstr = NULL;

    while((opt = getopt(argc, argv, "d:f:hv")) != -1) {
        switch (opt)
        {
        case 'd':
            processDir = true;
            pstr = optarg;
            break;

        case 'f':
            processFile = true;
            pstr = optarg;
            break;

        case 'h':   
            printf(HLEP_COMMAND_LINE);
            return 0;

        case 'v':
            verbose = true;
            break;

        case ':':
            printf("Option -$c requires an argument\n", optopt);
            return -1;

        case '?':
            printf("Unknown Option: -%c\n", optopt);
            return -1;
        }
    }

    if(processDir) 
        return processDirectory(pstr, verbose);

    if(processFile)
        return processPcapFile(pstr, verbose);

    return -1;
}