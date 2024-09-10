#include <cuda_runtime.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <endian.h>
#include <time.h>

#include "rulesGraph.cuh"
#include "header.h"

#define CHECK_CUDA_ERROR(fun)                                                   \
{                                                                               \
    cudaError_t err = fun;                                                      \
    if(err != cudaSuccess) {                                                    \
        printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
        return -1;                                                               \
    }                                                                           \
}

#define swapEndian16(x)     ((uint16_t) (((x) >> 8) | ((x) << 8)))

#if __BYTE_ORDER == __LITTLE_ENDIAN
    #define htons(x) swapEndian16(x)
    #define ntohs(x) swapEndian16(x)
#else 
    #define htons(x) x
    #define ntohs(x) x
#endif

__global__ static void registerRuleGraph(InspectorNode* nodes, InspectorNode* root) {
    InspectorNode* ethr_insp = &nodes[0];
    ethr_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;
        out.checkConditionResult = true;

        EthrHeader* hdr = (EthrHeader*) (p->getHeaderData());
        out.extractedCondition = &(hdr->ethrType);

        out.calculatedOffset = sizeof(EthrHeader);

        return out;
    });

    InspectorNode* ethrArp_insp = &nodes[1];
    ethrArp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint16_t ethrType = *((uint16_t*) cond);
        out.checkConditionResult = (ethrType == htons(0x0806));

        out.extractedCondition = NULL;

        out.calculatedOffset = 0;

        return out;
    }, Rule_EthrArp);


    InspectorNode* ethrIpv4_insp = &nodes[2];
    ethrIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint16_t ethrType = *((uint16_t*) cond);
        out.checkConditionResult = (ethrType == htons(0x0800));

        IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
        out.extractedCondition = &(hdr->protocol);

        size_t optionSize = (hdr->ihl*4)-20;
        out.calculatedOffset = sizeof(IPv4Header) + optionSize;

        return out;
    });

    InspectorNode* ethrIpv4Icmp_insp = &nodes[3];
    ethrIpv4Icmp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t protocol = *((uint8_t*) cond);
        out.checkConditionResult = (protocol == 0x01);

        out.extractedCondition = NULL;

        out.calculatedOffset = sizeof(ICMPHeader);

        return out;
    }, Rule_EthrIPv4ICMP);

    InspectorNode* ethrIpv4Udp_insp = &nodes[4];
    ethrIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t protocol = *((uint8_t*) cond);
        out.checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out.extractedCondition = &(hdr->sport);

        out.calculatedOffset = sizeof(UDPHeader);

        return out;
    });

    InspectorNode* ethrIpv4UdpDns_insp = &nodes[5];
    ethrIpv4UdpDns_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint16_t sport = *((uint16_t*) cond);
        uint16_t dport = *((uint16_t*) (cond+2));
        out.checkConditionResult = ((sport == htons(0x0035)) || (dport == htons(0x0035)));

        out.extractedCondition = NULL;

        out.calculatedOffset = sizeof(DNSHeader);

        return out;
    }, Rule_EthrIpv4UdpDns);

    InspectorNode* ethrIpv4Tcp_insp = &nodes[6];
    ethrIpv4Tcp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t protocol = *((uint8_t*) cond);
        out.checkConditionResult = (protocol == 0x06);

        TCPHeader* hdr = (TCPHeader*) (p->getHeaderData());
        int headerLength = hdr->headerLength * 4;
        out.extractedCondition = (p->getHeaderData() + headerLength);

        out.calculatedOffset = headerLength;

        return out;
    }, Rule_EthrIpv4Tcp);

    InspectorNode* ethrIpv4TcpHttp_insp = &nodes[7];
    ethrIpv4TcpHttp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t* method = (uint8_t*) cond;
        out.checkConditionResult = 
            (method[0]=='G' && method[1]=='E' && method[2]=='T') ||
            (method[0]=='P' && method[1]=='O' && method[2]=='S' && method[3]=='T') ||
            (method[0]=='P' && method[1]=='U' && method[2]=='T') ||
            (method[0]=='D' && method[1]=='E' && method[2]=='L' && method[3]=='E' && method[4]=='T' && method[5]=='E') ||
            (method[0]=='H' && method[1]=='E' && method[2]=='A' && method[3]=='D') ||
            (method[0]=='O' && method[1]=='P' && method[2]=='T' && method[3]=='I' && method[4]=='O' && method[5]=='N' && method[6]=='S') ||
            (method[0]=='P' && method[1]=='A' && method[2]=='T' && method[3]=='C' && method[4]=='H') ||
            (method[0]=='T' && method[1]=='R' && method[2]=='A' && method[3]=='C' && method[4]=='E') ||
            (method[0]=='C' && method[1]=='O' && method[2]=='N' && method[3]=='N' && method[4]=='E' && method[5]=='C' && method[6]=='T');

        out.extractedCondition = NULL;

        out.calculatedOffset = 0;

        return out;
    }, Rule_EthrIpv4TcpHttp);    

    InspectorNode* ethrIpv4UdpRtp_insp = &nodes[8];
    ethrIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out.checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out.calculatedOffset = 0;

        out.extractedCondition = NULL;

        return out;
    }, Rule_EthrIpv4UdpRtp);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    InspectorNode* ethrVlan_insp = &nodes[9];
    ethrVlan_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        EthrVlanHeader* hdr = (EthrVlanHeader*) p->getHeaderData();
        out.checkConditionResult = (hdr->vlanTag.tpid == ntohs(0x8100));

        out.extractedCondition = &(hdr->ethrType);

        out.calculatedOffset = sizeof(EthrVlanHeader);

        return out;
    });

    InspectorNode* ethrVlanIpv4_insp = &nodes[10];
    ethrVlanIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint16_t ethrType = *((uint16_t*) cond);
        out.checkConditionResult = (ethrType == htons(0x0800));

        IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
        out.extractedCondition = &(hdr->protocol);

        size_t optionSize = (hdr->ihl*4)-20;
        out.calculatedOffset = sizeof(IPv4Header) + optionSize;

        return out;
    });

    InspectorNode* ethrVlanIpv4Udp_insp = &nodes[11];
    ethrVlanIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t protocol = *((uint8_t*) cond);
        out.checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out.extractedCondition = &(hdr->sport);

        out.calculatedOffset = sizeof(UDPHeader);

        return out;
    });

    InspectorNode* ethrVlanIpv4UdpRtp_insp = &nodes[12];
    ethrVlanIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out.checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out.calculatedOffset = 0;

        out.extractedCondition = NULL;

        return out;
    }, Rule_EthrVlanIpv4UdpRtp);

    InspectorNode* ethrVlanIpv4UdpGtp_insp = &nodes[13];
    ethrVlanIpv4UdpGtp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        GTPHeader* hdr = (GTPHeader*) p->getHeaderData();

        out.checkConditionResult = (((hdr->version) == 0b010 || (hdr->version) == 0b001) && (hdr->payloadType == 1) && (hdr->messageType) == 0xFF);

        int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
        out.calculatedOffset = (hdr->E) * (*((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + 1) + normalSize; // 1 : 'extension header length' size 

        out.extractedCondition = NULL;

        return out;
    });

    InspectorNode* ethrVlanIpv4UdpGtpIpv4_insp = &nodes[14];
    ethrVlanIpv4UdpGtpIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        IPv4Header* hdr = (IPv4Header*) p->getHeaderData();
        uint8_t version = hdr->version;

        out.checkConditionResult = version == 4;

        out.extractedCondition = &(hdr->protocol);

        out.calculatedOffset = hdr->ihl*4;

        return out;
    });


    InspectorNode* ethrVlanIpv4UdpGtpIpv4Udp_insp = &nodes[15];
    ethrVlanIpv4UdpGtpIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t protocol = *((uint8_t*) cond);
        out.checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out.extractedCondition = &(hdr->sport);

        out.calculatedOffset = sizeof(UDPHeader);

        return out;
    });

    InspectorNode* ethrVlanIpv4UdpGtpIpv4UdpRtp_insp = &nodes[16];
    ethrVlanIpv4UdpGtpIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out.checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out.calculatedOffset = 0;

        out.extractedCondition = NULL;

        return out;
    }, Rule_EthrVlanIpv4UdpGtpIpv4UdpRtp);

//////////////////////////////////////////////////////////////

    InspectorNode* ethrIpv4UdpGtp_insp = &nodes[17];
    ethrIpv4UdpGtp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        GTPHeader* hdr = (GTPHeader*) p->getHeaderData();

        uint8_t version = hdr->version;
        uint8_t msgType = hdr->messageType;
        out.checkConditionResult = (((version) == 0b010 || (version) == 0b001) && (msgType) == 0xFF);

        printf("%d\n", out.checkConditionResult);

        int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
        out.calculatedOffset = (hdr->E) * (*((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + 1) + normalSize; // 1 : 'extension header length' size 

        out.extractedCondition = NULL;

        return out;
    });


    InspectorNode* ethrIpv4UdpGtpIpv4_insp = &nodes[18];
    ethrIpv4UdpGtpIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        IPv4Header* hdr = (IPv4Header*) p->getHeaderData();
        uint8_t version = hdr->version;


        out.checkConditionResult = version;

        out.extractedCondition = &(hdr->protocol);

        out.calculatedOffset = hdr->ihl*4;

        return out;
    });

    InspectorNode* ethrIpv4UdpGtpIpv4Udp_insp = &nodes[19];
    ethrIpv4UdpGtpIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        uint8_t protocol = *((uint8_t*) cond);
        out.checkConditionResult = (protocol == 0x11);

        UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
        out.extractedCondition = &(hdr->sport);

        out.calculatedOffset = sizeof(UDPHeader);

        return out;
    });

    InspectorNode* ethrIpv4UdpGtpIpv4UdpRtp_insp = &nodes[20];
    ethrIpv4UdpGtpIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;

        int16_t rtp_len = p->packetLen - p->headerOffset; 
        RTPHeader* hdr = (RTPHeader*) p->getHeaderData();
        out.checkConditionResult = (rtp_len >= 12) && (hdr->version == 0b10) && (hdr->pt <= 64 || hdr->pt >=96);

        out.calculatedOffset = 0;

        out.extractedCondition = NULL;

        return out;
    }, Rule_EthrIpv4UdpGtpIpv4UdpRtp);


    root->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
        InspectorFuncOutput out;
        out.checkConditionResult = true;
        out.extractedCondition = NULL;
        out.calculatedOffset = 0;
        return out;
    });

    root->addChild(ethr_insp);
    root->addChild(ethrVlan_insp);

    ethrVlan_insp->addChild(ethrVlanIpv4_insp);
    ethrVlanIpv4_insp->addChild(ethrVlanIpv4Udp_insp);
    ethrVlanIpv4Udp_insp->addChild(ethrVlanIpv4UdpRtp_insp);
    ethrVlanIpv4Udp_insp->addChild(ethrVlanIpv4UdpGtp_insp);
    ethrVlanIpv4UdpGtp_insp->addChild(ethrVlanIpv4UdpGtpIpv4_insp);
    ethrVlanIpv4UdpGtpIpv4_insp->addChild(ethrVlanIpv4UdpGtpIpv4Udp_insp);
    ethrVlanIpv4UdpGtpIpv4Udp_insp->addChild(ethrVlanIpv4UdpGtpIpv4UdpRtp_insp);

    ethr_insp->addChild(ethrIpv4_insp);
    ethrIpv4_insp->addChild(ethrIpv4Udp_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpDns_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpRtp_insp);
    ethrIpv4Udp_insp->addChild(ethrIpv4UdpGtp_insp);
    ethrIpv4UdpGtp_insp->addChild(ethrIpv4UdpGtpIpv4_insp);
    ethrIpv4UdpGtpIpv4_insp->addChild(ethrIpv4UdpGtpIpv4Udp_insp);
    ethrIpv4UdpGtpIpv4Udp_insp->addChild(ethrIpv4UdpGtpIpv4UdpRtp_insp);
}

__global__ void performProcess(PacketBuffer* packets, size_t packetCount, InspectorNode* rootNode) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    HeaderBuffer h;

    if(idx < packetCount) {
        for(size_t i = 0 ; i < HEADER_BUFFER_DATA_MAX_SIZE ; i++)
            h.headerData[i] = packets[idx].packetData[i];
        
        h.packetLen = packets[idx].packetLen;

        rootNode->processNode(&h, NULL);
        packets[idx].ruleId = h.ruleId;
    }       
}


int main() {
    size_t packetCount = 20000000;
    unsigned long long packetSize = 0L;
    PacketBuffer* packets = (PacketBuffer*) calloc(packetCount, sizeof(PacketBuffer));
    if(packets == NULL) 
        printf("Unable to allocate Packets\n");
    long long counter = 0L;

    {
        char errBuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle;
        const u_char *packet;
        struct pcap_pkthdr* header = (struct pcap_pkthdr*) malloc(sizeof(*header));

        handle = pcap_open_offline("../pcap/gtp2.pcap", errBuf);
        if(handle == NULL) {
            printf("Unable To Open Pcap File\n");
            return 1;
        }

        int result;
        while((result = (pcap_next_ex(handle, &header, &packet))) >= 0) {
            PacketBuffer p(packet, header->caplen);
            packets[counter++] = p;
            packetCount++;
            packetSize += header->caplen;
            if ((counter*sizeof(PacketBuffer)) >= (24696061952L)) break;        // GPU RAM Limit
        } 

        pcap_close(handle);
    }

    packetCount = counter;

    size_t stackSize;
    CHECK_CUDA_ERROR(cudaDeviceGetLimit(&stackSize, cudaLimitStackSize));
    CHECK_CUDA_ERROR(cudaDeviceSetLimit(cudaLimitStackSize, 1024*2));
    

    float duration = 0;
    cudaEvent_t start, stop;
    CHECK_CUDA_ERROR(cudaEventCreate(&start));
    CHECK_CUDA_ERROR(cudaEventCreate(&stop));

    printf("Packets Was Read From Pcap File (%lf GB)\n", (packetSize*1.0)/(1024.0 * 1024.0 * 1024.0));

    PacketBuffer* d_packets;
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packets, packetCount*sizeof(PacketBuffer)));

    CHECK_CUDA_ERROR(cudaEventRecord(start));
    CHECK_CUDA_ERROR(cudaMemcpy((void*) d_packets, (void*) packets, packetCount*sizeof(PacketBuffer), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaEventRecord(stop));

    CHECK_CUDA_ERROR(cudaEventSynchronize(stop));
    CHECK_CUDA_ERROR(cudaEventElapsedTime(&duration, start, stop));

    printf("*** Packets (%lf GB) Transfered From Host To Device ***\n", (packetCount*sizeof(PacketBuffer))/(1024.0*1024.0*1024.0));
    printf("\t Duration : %lf ms\n", duration);
    printf("\t Bandwidth : %lf Gb/s\n", (packetCount*sizeof(PacketBuffer)*1000.0*8.0)/(1024.0*1024.0*1024.0*duration));
    printf("\t Bandwidth : %lf GPacket/s\n\n", (packetCount*1000.0)/(1024.0*1024.0*1024.0*duration));


    InspectorNode* d_nodes;
    InspectorNode* d_root;
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_nodes, 30*sizeof(InspectorNode)));
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_root, sizeof(InspectorNode)));

    registerRuleGraph<<<1,1>>>(d_nodes, d_root);
    CHECK_CUDA_ERROR(cudaDeviceSynchronize());
    printf("RuleGraph Was Registered On Device\n");

    int threadPerBlock = 512;

    CHECK_CUDA_ERROR(cudaEventRecord(start));
    performProcess<<<(packetCount+threadPerBlock-1)/threadPerBlock,threadPerBlock>>>(d_packets, packetCount, d_root);
    CHECK_CUDA_ERROR(cudaEventRecord(stop));

    CHECK_CUDA_ERROR(cudaEventSynchronize(stop));
    CHECK_CUDA_ERROR(cudaEventElapsedTime(&duration, start, stop));

    printf("*** RuleGraph Was Processed For %d Threads Per Block ***\n", threadPerBlock);
    printf("**** %ld Packets (%.3lf GB) Process On GPU ***\n", packetCount, (packetSize*1.0)/(1024.0*1024.0*1024.0));
    printf("\t Duration : %lf ms\n", duration);
    printf("\t Bandwidth : %lf Gb/s\n", (packetSize*1000.0*8.0)/(1024.0*1024.0*1024.0*duration));
    printf("\t Bandwidth : %lf GPacket/s\n\n", (packetCount*1000.0)/(1024.0*1024.0*1024.0*duration));

    CHECK_CUDA_ERROR(cudaMemcpy((void*) packets, (void*) d_packets, packetCount*sizeof(PacketBuffer), cudaMemcpyDeviceToHost));


    int ruleCount[Rule_Count] = {0};
    for(size_t i = 0 ; i < packetCount ; i++) {  
        ruleCount[packets[i].ruleId]++;
    }

    for(size_t i = 0 ; i < Rule_Count ; i++)
        printf("#%s : %d\n", getRuleName(i), ruleCount[i]);
    
    return 0;
}