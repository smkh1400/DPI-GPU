#include "rulesGraph.cuh"

#include <string.h>
#include <stdio.h>


 
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
        default:                                                    return "N/A";
    }
};

__host__ PacketBuffer::PacketBuffer(const uint8_t* data, size_t len) {
    memset(packetData, 0 , PACKET_BUFFER_DATA_MAX_SIZE);
    memcpy(packetData, data, (len < PACKET_BUFFER_DATA_MAX_SIZE) ? len : PACKET_BUFFER_DATA_MAX_SIZE);
    packetLen = len;
    ruleId = Rule_NotRegistered;
}
__device__ uint8_t* HeaderBuffer::getHeaderData() {
    return (uint8_t*) (headerData+headerOffset);
}

__device__ bool InspectorNode::addChild(InspectorNode* child) {
    if(childrenCount >= INSPECTOR_NODE_CHILDREN_MAX_COUNT) {
        return false;
    }

    childrenNodes[childrenCount++] = child;
    return true;
}

__device__ void InspectorNode::processNode(HeaderBuffer* header, void* cond, InspectorFuncOutput* out) {
    inspectorFunction(header, cond, out);

    header->flag &= out->checkConditionResult;
    header->ruleId = header->ruleId!=Rule_NotRegistered ? header->ruleId : header->flag ? ruleId : Rule_NotRegistered;
    // bool c0 = (header->ruleId == Rule_NotRegistered);
    // bool c1 = (header->flag == true);
    // header->ruleId = (!c0) * (header->ruleId) + (c0) * (c1) * (ruleId) + (c0) * (!c1) * (Rule_NotRegistered);
    size_t newOffset = header->headerOffset + out->calculatedOffset;
    header->headerOffset = (header->packetLen >= newOffset & newOffset <= HEADER_BUFFER_DATA_MAX_SIZE) * newOffset;

    bool pFlag = header->flag;
    int32_t pOffset = header->headerOffset;
    void* pExtractedPtr = out->extractedCondition;

    for(size_t i = 0 ; i < childrenCount ; i++) {
        childrenNodes[i]->processNode(header, (void*) out->extractedCondition, out);
        header->flag = pFlag;
        header->headerOffset = pOffset;
        out->extractedCondition = pExtractedPtr;
    }
}

__device__ void InspectorNode::setInspectorFunction(Inspector_t inspectorFun) {
    inspectorFunction = inspectorFun;
    ruleId = Rule_NotRegistered;
}

__device__ void InspectorNode::setRuleId(uint32_t ruleID) {
    ruleId = ruleID;
}

__device__ void InspectorNode::setRule(Inspector_t inspectorFun, uint32_t ruleID) {
    setInspectorFunction(inspectorFun);
    setRuleId(ruleID);
}

__device__ bool InspectorNode::isEqual(InspectorNode* a, InspectorNode* b) {
    return a->inspectorFunction == b->inspectorFunction;
}

__device__ InspectorNode* InspectorNode::hasThisChild(InspectorNode* child) {
    for(int i = 0 ; i < childrenCount ; i++) 
        if(InspectorNode::isEqual(childrenNodes[i], child))
            return childrenNodes[i];
    return NULL;
}

__device__ bool InspectorNode::insertChild(InspectorNode* n) {
    if(childrenCount >= INSPECTOR_NODE_CHILDREN_MAX_COUNT) 
        return false;
    childrenNodes[childrenCount] = n;
    childrenCount++;
    return true;
}

__device__ static void root_inspector(HeaderBuffer* p, void* cond, InspectorFuncOutput* out) {
    out->checkConditionResult = true;
    out->extractedCondition = NULL;
    out->calculatedOffset = 0;
}

__device__ void RuleTrie::initTrie() {
    root.childrenCount = 0; 
    root.inspectorFunction = (Inspector_t) root_inspector;
    root.ruleId = Rule_NotRegistered;
    nodeCounter = 0;
}

__device__ bool RuleTrie::insertRule(Inspector_t rule[], size_t nodesCount, RuleName ruleId) {
    InspectorNode* currentNode = &root;
    size_t ruleCounter = 0;
    bool res = true; 

    InspectorNode n;
    n.inspectorFunction = rule[ruleCounter];
    InspectorNode* currentNodeTemp;
    while((ruleCounter < nodesCount) && ((currentNodeTemp = currentNode->hasThisChild(&n)) != NULL)) {
        ruleCounter++;
        n.inspectorFunction = rule[ruleCounter];
        currentNode = currentNodeTemp;
    }

    while(ruleCounter < nodesCount) {
        InspectorNode* newNode = &nodes[nodeCounter];
        newNode->childrenCount = 0;
        newNode->ruleId = Rule_NotRegistered;
        newNode->inspectorFunction = rule[ruleCounter];
        res &= currentNode->insertChild(newNode);
        if(!res) break;
        
        currentNode = newNode;
        ruleCounter++;
        nodeCounter++;
    }

    if(res) currentNode->ruleId = ruleId;

    return res;
}


__device__ void RuleTrie::processTrie(HeaderBuffer* h) {
    InspectorFuncOutput out;
    root.processNode(h, NULL, &out);
}

__device__ void RuleTrie::printTrie(InspectorNode* parent, int depth) {
    for(int i =0 ; i < depth ; i++) printf("\t");
    printf("%ld (%s)\n", (uintptr_t) parent->inspectorFunction, getRuleName(parent->ruleId));
    for (int i = 0; i < parent->childrenCount; i++) {
        printTrie(parent->childrenNodes[i], depth + 1);
    }
}

// __device__ void RuleTrie::printTrie() {
//     InspectorNode* currentNode = &root;
//     int depth = -1;
//     while (1) {
//         depth += 1;
//         for(int j = 0; j < depth; j++) printf("\t");
//         printf("%ld\n", (uintptr_t) currentNode->inspectorFunction);
//         for (int i = 0; i < currentNode->childrenCount; i++) {
//             currentNode = currentNode->childrenNodes[i];
//         }
//     }

// }