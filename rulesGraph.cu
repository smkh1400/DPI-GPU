#include "rulesGraph.cuh"
#include "config/config.h"

#include <string.h>
#include <stdio.h>

#define ALIGN_ADDRESS(addr, struct, alignedAddr)                {                                                                                   \
                                                                    size_t alignment = alignof(struct);                                             \
                                                                    uintptr_t ptr = (uintptr_t) (addr);                                             \
                                                                    void* alignedAddress = (void*) ((ptr + (alignment - 1)) & ~(alignment - 1)) ;   \
                                                                    alignedAddr = (struct*) alignedAddress;                                         \
                                                                }   

__device__ __host__ const char* getRuleName(uint32_t ruleId) {
    switch (ruleId)
    {
        case Rule_EthrArp:                                          return "Ethernet-ARP";
        case Rule_VlanEthrArp:                                      return "Ethernet-Vlan-ARP";

        case Rule_EthrIPv4Icmp:                                     return "Ethernet-IPv4-ICMP";
        case Rule_VlanEthrIPv4Icmp:                                 return "Ethernet-Vlan-IPv4-ICMP";

        case Rule_EthrIpv4UdpRtp:                                   return "Ethernet-IPv4-UDP-RTP";
        case Rule_VlanEthrIpv4UdpRtp:                               return "Ethernet-Vlan_IPv4-UDP-RTP";

        case Rule_EthrIpv4UdpSip:                                   return "Ethernet-IPv4-UDP-SIP";
        case Rule_VlanEthrIpv4UdpSip:                               return "Ethernet-Vlan_IPv4-UDP-SIP";

        case Rule_EthrIpv4UdpGtpIpv4UdpRtp:                         return "Ethernet-IPv4-UDP-GTP-IPv4-UDP-RTP";
        case Rule_VlanEthrIpv4UdpGtpIpv4UdpRtp:                     return "Ethernet-Vlan_IPv4-UDP-GTP-IPv4-UDP-RTP";

        case Rule_EthrIpv4UdpGtpIpv4UdpSip:                         return "Ethernet-IPv4-UDP-GTP-IPv4-UDP-SIP";
        case Rule_VlanEthrIpv4UdpGtpIpv4UdpSip:                     return "Ethernet-Vlan_IPv4-UDP-GTP-IPv4-UDP-SIP";

        case Rule_EthrIpv4UdpDns:                                   return "Ethernet-IPv4-UDP-DNS";
        case Rule_VlanEthrIpv4UdpDns:                               return "Ethernet-Vlan-IPv4-UDP-DNS";
        
        case Rule_EthrIpv4TcpHttp:                                  return "Ethernet-IPv4-TCP-HTTP";
        case Rule_VlanEthrIpv4TcpHttp:                              return "Ethernet-Vlan-IPv4-TCP-HTTP";

        case Rule_EthrIpv4Sctp:                                     return "Ethernet-IPv4-SCTP";
        case Rule_VlanEthrIpv4Sctp:                                 return "Ethernet-Vlan-IPv4-SCTP";
        default:                                                    return "N/A";
    }
};

__device__ HeaderBuffer::HeaderBuffer(const uint8_t *packetData, size_t packetLen){
    this->headerOffset = 0;
    this->ruleId = Rule_NotRegistered;
    this->packetLen = packetLen;
    this->flag = true;
    this->alive = true;
    this->valid = true;
    this->setHeaderData(packetData);
}

__device__ uint8_t *HeaderBuffer::getHeaderData() {
    return (uint8_t*) (headerData+headerOffset);
}

__device__ void HeaderBuffer::setHeaderData(const uint8_t *data) {
    headerData = data;
}

__device__ size_t HeaderBuffer::getValidLen() {
    return packetLen - headerOffset;
}

__device__ void InspectorNode::processNode(HeaderBuffer* header, void* cond, InspectorFuncOutput* out) { 
    inspectorFunction(header, cond, out);


    bool warpExit = __all_sync(__activemask() ,header->ruleId != Rule_NotRegistered || !header->valid);
    if(warpExit) {
        header->alive = false;
        return;
    }

    header->flag &= out->checkConditionResult;
    bool c0 = (header->ruleId == Rule_NotRegistered);
    bool c1 = (header->flag == true);
    bool c2 = (header->valid == true);
    header->ruleId = (RuleID) ((!c0) * (header->ruleId) + (c0) * (c1) * (c2) * (ruleId) + (c0) * (!c1) * (!c2) * (Rule_NotRegistered));     // valid for Rule_NotRegistered == 0

    size_t newOffset = header->headerOffset + out->calculatedOffset;
    // header->headerOffset = (header->packetLen >= newOffset && newOffset <= HEADER_BUFFER_DATA_MAX_SIZE) * newOffset;
    header->valid *= (header->packetLen >= newOffset);
    header->headerOffset = (header->valid) * newOffset;


    bool pFlag = header->flag;
    int32_t pOffset = header->headerOffset;
    void* pExtractedPtr = out->extractedCondition;

    for(size_t i = 0 ; i < childrenCount ; i++) {
        childrenNodes[i]->processNode(header, (void*) out->extractedCondition, out);

        if(!header->alive) return;

        header->flag = pFlag;
        header->headerOffset = pOffset;
        out->extractedCondition = pExtractedPtr;
    }
}

__device__ InspectorNode* InspectorNode::hasThisChild(InspectorNode* child) {
    for(int i = 0 ; i < childrenCount ; i++) 
        if(childrenNodes[i]->inspectorFunction == child->inspectorFunction)
            return childrenNodes[i];
    return NULL;
}

__device__ bool InspectorNode::insertChild(InspectorNode* n) {
    if(childrenCount >= INSPECTOR_NODE_CHILDREN_MAX_COUNT) {
        printf(">> Children Count Exceeded The Limit %p\n", inspectorFunction);
        return false;
    }
    childrenNodes[childrenCount] = n;
    childrenCount++;

    return true;
}

__device__ static void root_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    out->checkConditionResult = true;
    out->extractedCondition = NULL;
    out->calculatedOffset = 0;
}

 __host__ __device__ RuleTrie::RuleTrie() {
    this->initTrie();
 }

  __device__ void RuleTrie::initTrie() {
    // root.childrenCount = 0;
    root.inspectorFunction = (Inspector_t) root_inspector;
    // root.ruleId = Rule_NotRegistered;
    // nodeCounter = 0;
 }

__device__ bool RuleTrie::insertRule(Inspector_t rule[], size_t nodesCount, RuleID ruleId) {
    InspectorNode* currentNode = &root;
    size_t ruleCounter = 0;
    bool res = true; 

    InspectorNode n(rule[ruleCounter]);
    InspectorNode* currentNodeTemp;

    while(ruleCounter < nodesCount) {
        if((currentNodeTemp = currentNode->hasThisChild(&n)) != NULL) {
            ruleCounter++;
            n.inspectorFunction = rule[ruleCounter];
            currentNode = currentNodeTemp;

            continue;
        } 

        InspectorNode* newNode = new InspectorNode(rule[ruleCounter]);
        res &= currentNode->insertChild(newNode);
        if(!res) break;
        
        currentNode = newNode;
        ruleCounter++;
        nodeCounter++;
    }

    if(res) currentNode->ruleId = ruleId;

    return res;
}

__device__ bool RuleTrie::insertRules(Rule_t rules[], size_t ruleCount) {
    bool res = true;
    for(int i = 0 ; i < ruleCount ; i++) {
        res &= insertRule(rules[i].inspectors, rules[i].inspectorsCount, rules[i].ruleId);
        // printf(">> Rule %s Is Added , RuleCount: %d\n", rules[i].ruleName, rules[i].inspectorsCount);
    }
    return res;
}

__device__ void RuleTrie::processTrie(HeaderBuffer* h) {
    InspectorFuncOutput out;
    root.processNode(h, NULL, &out);
}

__device__ void RuleTrie::printTrieHelper(const InspectorNode& parent, int depth) {
    for(int i =0 ; i < depth ; i++) printf("\t");
    printf("%ld (%s)\n", (uintptr_t) parent.inspectorFunction, getRuleName(parent.ruleId));
    for (int i = 0; i < parent.childrenCount; i++) {
        printTrieHelper(*parent.childrenNodes[i], depth + 1);
    }
}

__device__ void RuleTrie::printTrie() {
    this->printTrieHelper(this->root, 0);
}