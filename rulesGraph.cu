#include "rulesGraph.cuh"

#include <string.h>
#include <stdio.h>

#define __DEBUG_ENABLE              (1)
#define __DEBUG_LOG(...)         {if(__DEBUG_ENABLE) {printf(__VA_ARGS__);}}

const char* getRuleName(uint32_t ruleId) {
    switch (ruleId)
    {
        case Rule_EthrArp:           return "Ethernet-ARP";
        case Rule_EthrIpv4:          return "Ethernet-IPv4";
        case Rule_EthrIPv4ICMP:      return "Ethernet-IPv4-ICMP";
        case Rule_EthrIpv4Tcp:       return "Ethernet-IPv4-TCP";
        case Rule_EthrIpv4Udp:       return "Ethernet-IPv4-UDP";
        case Rule_EthrIpv4UdpRtp:    return "Ethernet-IPv4-UDP-RTP";
        case Rule_EthrIpv4UdpSip:    return "Ethernet-IPv4-UDP-SIP";
        case Rule_EthrIpv4UdpGtpIpv4UdpRtp:    return "Ethernet-IPv4-UDP-GTP-IPv4-UDP-RTP";
        case Rule_EthrIpv4UdpGtpIpv4UdpSip:    return "Ethernet-IPv4-UDP-GTP-IPv4-UDP-SIP";
        case Rule_EthrVlanIpv4UdpRtp:    return "Ethernet-Vlan_IPv4-UDP-RTP";
        case Rule_EthrVlanIpv4UdpSip:    return "Ethernet-Vlan_IPv4-UDP-SIP";
        case Rule_EthrVlanIpv4UdpGtpIpv4UdpRtp:    return "Ethernet-Vlan_IPv4-UDP-GTP-IPv4-UDP-RTP";
        case Rule_EthrVlanIpv4UdpGtpIpv4UdpSip:    return "Ethernet-Vlan_IPv4-UDP-GTP-IPv4-UDP-SIP";
        case Rule_EthrIpv4UdpDns:    return "Ethernet-IPv4-UDP-DNS";
        case Rule_EthrIpv4TcpHttp:   return "Ethernet-IPv4-TCP-HTTP";
        default:                     return "N/A";
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

__device__ void InspectorNode::processNode(HeaderBuffer* header, void* cond) {
    InspectorFuncOutput out = inspectorFunction(header, cond);

    header->flag &= out.checkConditionResult;
    header->ruleId = header->ruleId!=Rule_NotRegistered ? header->ruleId : header->flag ? ruleId : Rule_NotRegistered;
    size_t newOffset = header->headerOffset + out.calculatedOffset;
    header->headerOffset = (header->packetLen >= newOffset && newOffset <= HEADER_BUFFER_DATA_MAX_SIZE) * newOffset;


    bool pFlag = header->flag;
    int32_t pOffset = header->headerOffset;

    for(size_t i = 0 ; i < childrenCount ; i++) {
        childrenNodes[i]->processNode(header, (void*) out.extractedCondition);
        header->flag = pFlag;
        header->headerOffset = pOffset;
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
