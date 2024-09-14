#ifndef GPU_RULES_GRAPH_H_
#define GPU_RULES_GRAPH_H_

#include <cuda_runtime.h> 
#include <stdint.h>
#include <sys/types.h>

enum RuleNames {
    Rule_NotRegistered,
    Rule_EthrArp,
    Rule_EthrIpv4,
        Rule_EthrIPv4ICMP,
        Rule_EthrIpv4Tcp,
            Rule_EthrIpv4TcpHttp,
        Rule_EthrIpv4Udp,
            Rule_EthrIpv4UdpDns,
            Rule_EthrIpv4UdpRtp,
            Rule_EthrIpv4UdpSip,
            Rule_EthrIpv4UdpGtpIpv4UdpRtp,
            Rule_EthrIpv4UdpGtpIpv4UdpSip,
            Rule_EthrVlanIpv4UdpRtp,
            Rule_EthrVlanIpv4UdpSip,
            Rule_EthrVlanIpv4UdpGtpIpv4UdpRtp,
            Rule_EthrVlanIpv4UdpGtpIpv4UdpSip,
    Rule_Count
};


const char* getRuleName(uint32_t ruleId);

template <typename T>
class Queue {
public:
#define QUEUE_BUFFER_MAX_LEN        10
    T   array[QUEUE_BUFFER_MAX_LEN];
    size_t counter;

    __device__ __host__ Queue() : counter(0){
        for(size_t i = 0 ; i < QUEUE_BUFFER_MAX_LEN ; i++)
            array[i] = 0;
    }

    __device__ __host__ void clone(Queue& other) {
        for(size_t i = 0 ; i < QUEUE_BUFFER_MAX_LEN ; i++)
            array[i] = other.array[i];
    }

    __device__ __host__ void push(T x) {
        array[counter++] = x;
    }

    __device__ __host__ T pop() {
        return array[counter--];
    }

    __device__ __host__ T get() {
        return array[counter-1];
    }
};

class HeaderBuffer {
public:
#define HEADER_BUFFER_DATA_MAX_SIZE     1024
    uint8_t     headerData[HEADER_BUFFER_DATA_MAX_SIZE];
    uint32_t        headerOffset;
    // Queue<uint16_t>       ruleId;
    uint32_t                ruleId;
    bool            flag;
    size_t      packetLen;

    __device__ HeaderBuffer() : headerOffset(0) , flag(true) , ruleId(Rule_NotRegistered) {}

    __device__ uint8_t* getHeaderData();

    friend class InspectorNode;    
};

class PacketBuffer {
public:
#define PACKET_BUFFER_DATA_MAX_SIZE     1600
    uint8_t         packetData[PACKET_BUFFER_DATA_MAX_SIZE];
    // Queue<uint16_t>        ruleId;
    uint32_t            ruleId;
    size_t                  packetLen;

// public:
    __device__ PacketBuffer() : ruleId(Rule_NotRegistered) {}

    __host__  PacketBuffer(const uint8_t* data, size_t len);

    friend class InspectorNode;
};


struct InspectorFuncOutput {
    bool        checkConditionResult;
    void*       extractedCondition;
    int32_t     calculatedOffset;
};

typedef void (*Inspector_t) (HeaderBuffer*, void*, InspectorFuncOutput*);

class InspectorNode {
private:
#define INSPECTOR_NODE_CHILDREN_MAX_COUNT   10

    Inspector_t inspectorFunction;
    InspectorNode* childrenNodes[INSPECTOR_NODE_CHILDREN_MAX_COUNT];
    size_t childrenCount;
    uint32_t ruleId;

public:

    __device__ InspectorNode() {}

    __device__ InspectorNode(Inspector_t inspectorFun) : inspectorFunction(inspectorFun) , childrenCount(0) , ruleId(Rule_NotRegistered) {}

    __device__ InspectorNode(Inspector_t inspectorFun, uint32_t ruleId) : inspectorFunction(inspectorFun) , childrenCount(0) , ruleId(ruleId) {}

    __device__ bool addChild(InspectorNode* child);

    __device__ void processNode(HeaderBuffer* packet, void* cond, InspectorFuncOutput* out);

    __device__ void setInspectorFunction(Inspector_t inspectorFun);

    __device__ void setRuleId(uint32_t ruleId);

    __device__ void setRule(Inspector_t inspectorFun, uint32_t ruleId);
};

#endif // GPU_RULES_GRAPH_H_

#if (PACKET_BUFFER_DATA_MAX_SIZE < HEADER_BUFFER_DATA_MAX_SIZE)
    #error "Packet Buffer Smaller Than Header Buffer"
#endif