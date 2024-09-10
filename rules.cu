// #include <cuda_runtime.h>
// #include "ruleTrie.cuh"
// #include "header.h"

// #define swapEndian16(x)     ((uint16_t) (((x) >> 8) | ((x) << 8)))

// #if __BYTE_ORDER == __LITTLE_ENDIAN
//     #define htons(x) swapEndian16(x)
//     #define ntohs(x) swapEndian16(x)
// #else 
//     #define htons(x) x
//     #define ntohs(x) x
// #endif


// __device__ InspectorFuncOutput root_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;
    
//     out.checkConditionResult = true;

//     EthrVlanHeader* hdr = (EthrVlanHeader*) (p->getHeaderData());
//     out.extractedCondition = &(hdr->vlanTag.tpid);

//     out.calculatedOffset = 0;

//     return out;
// }

// __device__ InspectorFuncOutput vlan_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;
    
//     uint16_t tpid = *((uint16_t*) cond);
//     out.checkConditionResult = (tpid == ntohs(0x8100));

//     EthrVlanHeader* hdr = (EthrVlanHeader*) (p->getHeaderData());
//     out.extractedCondition = &(hdr->ethrType);

//     out.calculatedOffset = sizeof(EthrVlanHeader);

//     return out;
// }

// __device__ InspectorFuncOutput ethr_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     uint16_t tpid = *((uint16_t*) cond);
//     out.checkConditionResult = (tpid != ntohs(0x8100));

//     out.extractedCondition = cond;

//     out.calculatedOffset = sizeof(EthrHeader);

//     return out;
// }

// __device__ InspectorFuncOutput ipv4_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     uint16_t ethrType = *((uint16_t*) cond);
//     out.checkConditionResult = (ethrType == htons(0x0800));

//     IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
//     out.extractedCondition = &(hdr->protocol);

//     size_t headerSize = (hdr->ihl*4);
//     out.calculatedOffset = headerSize;

//     return out;
// }

// __device__ InspectorFuncOutput ipv4Udp_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     uint8_t protocol = *((uint8_t*) cond);
//     out.checkConditionResult = (protocol == 0x11);

//     UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
//     out.extractedCondition = &(hdr->sport);

//     out.calculatedOffset = sizeof(UDPHeader);

//     return out;
// }

// __device__ InspectorFuncOutput ipv4UdpRtp_inspector (HeaderBuffer* p, void* cond){
//     InspectorFuncOutput out;

//     uint8_t version = *((uint8_t*) p->getHeaderData());
//     out.checkConditionResult = (version >> 6 == 0b10);

//     out.calculatedOffset = 0;

//     out.extractedCondition = NULL;

//     return out;
// }

// __device__ InspectorFuncOutput ipv4UdpGtp_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     GTPHeader* hdr = (GTPHeader*) (p->getHeaderData());

//     uint8_t version = hdr->version;
//     uint8_t msgType = hdr->messageType;
//     out.checkConditionResult = (((version) == 0b010 || (version) == 0b001) && (msgType) == 0xFF);


//     int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
//     out.calculatedOffset = *((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + normalSize + 1; // 1 : 'extension header length' size 

//     out.extractedCondition = NULL;

//     return out;
// }

// __device__ InspectorFuncOutput gtpIpv4_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());

//     uint8_t version = hdr->version;
//     out.checkConditionResult = (((version) == 0b0100));


//     int headerSize = (hdr->ihl*4);
//     out.calculatedOffset = headerSize;

//     out.extractedCondition = &(hdr->protocol);

//     return out;
// }

// __device__ InspectorFuncOutput gtpIpv4Udp_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     uint8_t protocol = *((uint8_t*) cond);
//     out.checkConditionResult = (protocol == 0x11);

//     UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
//     out.extractedCondition = &(hdr->sport);

//     out.calculatedOffset = sizeof(UDPHeader);

//     return out;
// }

// __device__ InspectorFuncOutput gtpIpv4UdpRtp_inspector (HeaderBuffer* p, void* cond) {
//     InspectorFuncOutput out;

//     uint8_t version = *((uint8_t*) p->getHeaderData());
//     out.checkConditionResult = (version >> 6 == 0b10);

//     out.calculatedOffset = 0;

//     out.extractedCondition = NULL;

//     return out;
// }

// void* ethrIpv4UdpRtp_rule[5] = {root_inspector, ethr_inspector, ipv4_inspector, ipv4Udp_inspector, ipv4UdpRtp_inspector};
// void* ethrIpv4UdpGtpIpv4UdpRtp_rule[8]= {root_inspector, ethr_inspector, ipv4_inspector, ipv4Udp_inspector, ipv4UdpGtp_inspector, gtpIpv4_inspector, gtpIpv4Udp_inspector, gtpIpv4UdpRtp_inspector};
// void* vlanIpv4UdpRtp_rule[5] = {root_inspector, vlan_inspector, ipv4_inspector, ipv4Udp_inspector, ipv4UdpRtp_inspector};
// void* vlanIpv4UdpGtpIpv4UdpRtp_rule[8] = {root_inspector, vlan_inspector, ipv4_inspector, ipv4Udp_inspector, ipv4UdpRtp_inspector, gtpIpv4_inspector, gtpIpv4Udp_inspector, gtpIpv4UdpRtp_inspector};


// // __global__ static void registerRuleGraph(RuleGraph* rules) {

// // //////////////////////////////////////////__Root__///////////////////////////////////////////////////////////

// //     InspectorNode* root_insp = rules->getLastNodes();
// //     root_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;
        
// //         out.checkConditionResult = true;

// //         EthrVlanHeader* hdr = (EthrVlanHeader*) (p->getHeaderData());
// //         out.extractedCondition = &(hdr->vlanTag.tpid);

// //         out.calculatedOffset = 0;

// //         return out;
// //     });

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__Vlan__///////////////////////////////////////////////////////////

// //     InspectorNode* vlan_insp = rules->getLastNodes();
// //     vlan_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;
        
// //         uint16_t tpid = *((uint16_t*) cond);
// //         out.checkConditionResult = (tpid == ntohs(0x8100));

// //         EthrVlanHeader* hdr = (EthrVlanHeader*) (p->getHeaderData());
// //         out.extractedCondition = &(hdr->ethrType);

// //         out.calculatedOffset = sizeof(EthrVlanHeader);

// //         return out;
// //     });

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__Ethernet__///////////////////////////////////////////////////////////  

// //     InspectorNode* ethr_insp = rules->getLastNodes();
// //     ethr_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint16_t tpid = *((uint16_t*) cond);
// //         out.checkConditionResult = (tpid != ntohs(0x8100));

// //         out.extractedCondition = cond;

// //         out.calculatedOffset = sizeof(EthrHeader);

// //         return out;
// //     });

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4__///////////////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4_insp = rules->getLastNodes();
// //     ethrIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint16_t ethrType = *((uint16_t*) cond);
// //         out.checkConditionResult = (ethrType == htons(0x0800));

// //         IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());
// //         out.extractedCondition = &(hdr->protocol);

// //         size_t headerSize = (hdr->ihl*4);
// //         out.calculatedOffset = headerSize;

// //         return out;
// //     });

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4_UDP__///////////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4Udp_insp = rules->getLastNodes();
// //     ethrIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint8_t protocol = *((uint8_t*) cond);
// //         out.checkConditionResult = (protocol == 0x11);

// //         UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
// //         out.extractedCondition = &(hdr->sport);

// //         out.calculatedOffset = sizeof(UDPHeader);

// //         return out;
// //     });

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// //////////////////////////////////////////__IPv4_UDP_RTP__///////////////////////////////////////////////////////////

//     // InspectorNode* ethrIpv4UdpRtp_insp = rules->getLastNodes();
//     // ethrIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
//     //     InspectorFuncOutput out;

//     //     uint8_t version = *((uint8_t*) p->getHeaderData());
//     //     out.checkConditionResult = (version >> 6 == 0b10);

//     //     out.calculatedOffset = 0;

//     //     out.extractedCondition = NULL;

//     //     return out;
//     // }, Rule_EthrIpv4UdpRtp);

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// //////////////////////////////////////////__IPv4_UDP_GTP__///////////////////////////////////////////////////////////

//     // InspectorNode* ethrIpv4UdpGTP_insp = rules->getLastNodes();
//     // ethrIpv4UdpGTP_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
//     //     InspectorFuncOutput out;

//     //     GTPHeader* hdr = (GTPHeader*) (p->getHeaderData());

//     //     uint8_t version = hdr->version;
//     //     uint8_t msgType = hdr->messageType;
//     //     out.checkConditionResult = (((version) == 0b010 || (version) == 0b001) && (msgType) == 0xFF);


//     //     int normalSize = sizeof(GTPHeader) + (hdr->E) * (1) + (hdr->S) * (2) + (hdr->PN) * (1);
//     //     out.calculatedOffset = *((uint8_t*) (p->getHeaderData() + normalSize)) * 4 + normalSize + 1; // 1 : 'extension header length' size 

//     //     out.extractedCondition = NULL;

//     //     return out;
//     // });

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// //////////////////////////////////////////__IPv4_UDP_GTP_IPv4__//////////////////////////////////////////////

//     // InspectorNode* gtpIpv4_insp = rules->getLastNodes();
//     // gtpIpv4_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
//     //     InspectorFuncOutput out;

//     //     IPv4Header* hdr = (IPv4Header*) (p->getHeaderData());

//     //     uint8_t version = hdr->version;
//     //     out.checkConditionResult = (((version) == 0b0100));


//     //     int headerSize = (hdr->ihl*4);
//     //     out.calculatedOffset = headerSize;

//     //     out.extractedCondition = &(hdr->protocol);

//     //     return out;
//     // });

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// //////////////////////////////////////////__IPv4_UDP_GTP_IPv4_UDP__//////////////////////////////////////////

//     // InspectorNode* gtpIpv4Udp_insp = rules->getLastNodes();
//     // gtpIpv4Udp_insp->setInspectorFunction((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
//     //     InspectorFuncOutput out;

//     //     uint8_t protocol = *((uint8_t*) cond);
//     //     out.checkConditionResult = (protocol == 0x11);

//     //     UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
//     //     out.extractedCondition = &(hdr->sport);

//     //     out.calculatedOffset = sizeof(UDPHeader);

//     //     return out;
//     // });

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// //////////////////////////////////////////__IPv4_UDP_GTP_IPv4_UDP_RTP__//////////////////////////////////////

//     // InspectorNode* gtpIpv4UdpRtp_insp = rules->getLastNodes();
//     // gtpIpv4UdpRtp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
//     //     InspectorFuncOutput out;

//     //     uint8_t version = *((uint8_t*) p->getHeaderData());
//     //     out.checkConditionResult = (version >> 6 == 0b10);

//     //     out.calculatedOffset = 0;

//     //     out.extractedCondition = NULL;

//     //     return out;
//     // }, Rule_EthrIpv4UdpGtpIpv4UdpRtp);

//     // ethrIpv4_insp->addChild(ethrIpv4Udp_insp);
//     // ethrIpv4Udp_insp->addChild(ethrIpv4UdpRtp_insp);
//     // ethrIpv4Udp_insp->addChild(ethrIpv4UdpGTP_insp);
//     // ethrIpv4UdpGTP_insp->addChild(gtpIpv4_insp);
//     // gtpIpv4_insp->addChild(gtpIpv4Udp_insp);
//     // gtpIpv4Udp_insp->addChild(gtpIpv4UdpRtp_insp);

//     // root_insp->addChild(vlan_insp);
//     //     vlan_insp->addChild(ethrIpv4_insp);
//     // root_insp->addChild(ethr_insp);
//     //     ethr_insp->addChild(ethrIpv4_insp);

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__ARP__///////////////////////////////////////////////////////////

// //     InspectorNode* ethrArp_insp = rules->getLastNodes();
// //     ethrArp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint16_t ethrType = *((uint16_t*) cond);
// //         out.checkConditionResult = (ethrType == htons(0x0806));

// //         out.extractedCondition = NULL;

// //         out.calculatedOffset = 0;

// //         return out;
// //     }, Rule_EthrArp);



// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4_ICMP__///////////////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4Icmp_insp = rules->getLastNodes();
// //     ethrIpv4Icmp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint8_t protocol = *((uint8_t*) cond);
// //         out.checkConditionResult = (protocol == 0x01);

// //         out.extractedCondition = NULL;

// //         out.calculatedOffset = sizeof(ICMPHeader);

// //         return out;
// //     }, Rule_EthrIPv4ICMP);

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4_UDP__///////////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4Udp_insp = rules->getLastNodes();
// //     ethrIpv4Udp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint8_t protocol = *((uint8_t*) cond);
// //         out.checkConditionResult = (protocol == 0x11);

// //         UDPHeader* hdr = (UDPHeader*) (p->getHeaderData());
// //         out.extractedCondition = &(hdr->sport);

// //         out.calculatedOffset = sizeof(UDPHeader);

// //         return out;
// //     }, Rule_EthrIpv4Udp);

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4_UDP_DNS__///////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4UdpDns_insp = rules->getLastNodes();
// //     ethrIpv4UdpDns_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint16_t sport = *((uint16_t*) cond);
// //         uint16_t dport = *((uint16_t*) (cond+2));
// //         out.checkConditionResult = ((sport == htons(0x0035)) || (dport == htons(0x0035)));

// //         out.extractedCondition = NULL;

// //         out.calculatedOffset = sizeof(DNSHeader);

// //         return out;
// //     }, Rule_EthrIpv4UdpDns);

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4_TCP__///////////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4Tcp_insp = rules->getLastNodes();
// //     ethrIpv4Tcp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint8_t protocol = *((uint8_t*) cond);
// //         out.checkConditionResult = (protocol == 0x06);

// //         TCPHeader* hdr = (TCPHeader*) (p->getHeaderData());
// //         int headerLength = hdr->headerLength * 4;
// //         out.extractedCondition = (p->getHeaderData() + headerLength);

// //         out.calculatedOffset = headerLength;

// //         return out;
// //     }, Rule_EthrIpv4Tcp);

// // /////////////////////////////////////////////////////////////////////////////////////////////////////////////

// // //////////////////////////////////////////__IPv4_TCP_HTTP__//////////////////////////////////////////////////

// //     InspectorNode* ethrIpv4TcpHttp_insp = rules->getLastNodes();
// //     ethrIpv4TcpHttp_insp->setRule((Inspector_t) [](HeaderBuffer* p, void* cond) -> InspectorFuncOutput {
// //         InspectorFuncOutput out;

// //         uint8_t* method = (uint8_t*) cond;
// //         out.checkConditionResult = 
// //             (method[0]=='G' && method[1]=='E' && method[2]=='T') ||
// //             (method[0]=='P' && method[1]=='O' && method[2]=='S' && method[3]=='T') ||
// //             (method[0]=='P' && method[1]=='U' && method[2]=='T') ||
// //             (method[0]=='D' && method[1]=='E' && method[2]=='L' && method[3]=='E' && method[4]=='T' && method[5]=='E') ||
// //             (method[0]=='H' && method[1]=='E' && method[2]=='A' && method[3]=='D') ||
// //             (method[0]=='O' && method[1]=='P' && method[2]=='T' && method[3]=='I' && method[4]=='O' && method[5]=='N' && method[6]=='S') ||
// //             (method[0]=='P' && method[1]=='A' && method[2]=='T' && method[3]=='C' && method[4]=='H') ||
// //             (method[0]=='T' && method[1]=='R' && method[2]=='A' && method[3]=='C' && method[4]=='E') ||
// //             (method[0]=='C' && method[1]=='O' && method[2]=='N' && method[3]=='N' && method[4]=='E' && method[5]=='C' && method[6]=='T');

// //         out.extractedCondition = NULL;

// //         out.calculatedOffset = 0;

// //         return out;
// //     }, Rule_EthrIpv4TcpHttp);    




    
//     // ethr_insp->addChild(ethrArp_insp);
//     // ethr_insp->addChild(ethrIpv4_insp);
//     //     ethrIpv4_insp->addChild(ethrIpv4Icmp_insp);
//     //     ethrIpv4_insp->addChild(ethrIpv4Udp_insp);
//     //         ethrIpv4Udp_insp->addChild(ethrIpv4UdpDns_insp);
//     //         // ethrIpv4Udp_insp->addChild(ethrIpv4UdpRtp_insp);
//     //     ethrIpv4_insp->addChild(ethrIpv4Tcp_insp);
//     //         ethrIpv4Tcp_insp->addChild(ethrIpv4TcpHttp_insp);
// // }