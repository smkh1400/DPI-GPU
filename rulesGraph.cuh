#ifndef GPU_RULES_GRAPH_H_
#define GPU_RULES_GRAPH_H_

#include <cuda_runtime.h> 
#include <stdint.h>
#include <sys/types.h>

enum RuleName {
    Rule_NotRegistered,

    Rule_EthrArp,
    Rule_VlanEthrArp,

    Rule_EthrIPv4Icmp,
    Rule_VlanEthrIPv4Icmp,

    Rule_EthrIpv4TcpHttp,
    Rule_VlanEthrIpv4TcpHttp,

    Rule_EthrIpv4UdpDns,
    Rule_VlanEthrIpv4UdpDns,

    Rule_EthrIpv4UdpRtp,
    Rule_VlanEthrIpv4UdpRtp,

    Rule_EthrIpv4UdpSip,
    Rule_VlanEthrIpv4UdpSip,

    Rule_EthrIpv4UdpGtpIpv4UdpRtp,
    Rule_VlanEthrIpv4UdpGtpIpv4UdpRtp,

    Rule_EthrIpv4UdpGtpIpv4UdpSip,
    Rule_VlanEthrIpv4UdpGtpIpv4UdpSip, 
    
    Rule_Count
};


const char* getRuleName(uint32_t ruleId);

class HeaderBuffer {
public:
#define HEADER_BUFFER_DATA_MAX_SIZE     1000
    uint8_t                 headerData[HEADER_BUFFER_DATA_MAX_SIZE];
    uint16_t                headerOffset;
    uint8_t                 ruleId;
    bool                    flag;
    uint16_t                packetLen;

    __device__ HeaderBuffer() : headerOffset(0) , flag(true) , ruleId(Rule_NotRegistered) {}

    __device__ uint8_t* getHeaderData();

    friend class InspectorNode;    
};

struct PacketMetadata {
    size_t  packetOffset;
    size_t  packetLen;
};

struct PacketInfo {
    uint8_t ruleId;
};

struct InspectorFuncOutput {
    bool        checkConditionResult;
    void*       extractedCondition;
    uint32_t     calculatedOffset;
};

typedef void (*Inspector_t) (HeaderBuffer*, void*, InspectorFuncOutput*);

struct Rule_t {
public:
#define RULE_MAX_INSPECTOR_COUNT        10

    Inspector_t     inspectors[RULE_MAX_INSPECTOR_COUNT];
    size_t          inspectorsCount;
    RuleName          ruleId;
    const uint8_t*  ruleName;

#define REGISTER_RULE(ruleID, ...)          (Rule_t) {__VA_ARGS__, sizeof(((Inspector_t[]) __VA_ARGS__))/sizeof(Inspector_t), ruleID, #ruleID}

};

class InspectorNode {
public:
#define INSPECTOR_NODE_CHILDREN_MAX_COUNT   10

    Inspector_t inspectorFunction;
    InspectorNode* childrenNodes[INSPECTOR_NODE_CHILDREN_MAX_COUNT];
    size_t childrenCount;
    uint32_t ruleId;

    __device__ static bool isEqual(InspectorNode* a, InspectorNode* b);

    __device__ InspectorNode() {}

    __device__ InspectorNode(Inspector_t inspectorFun) : inspectorFunction(inspectorFun) , childrenCount(0) , ruleId(Rule_NotRegistered) {}

    __device__ InspectorNode(Inspector_t inspectorFun, uint32_t ruleId) : inspectorFunction(inspectorFun) , childrenCount(0) , ruleId(ruleId) {}

    __device__ bool addChild(InspectorNode* child);

    __device__ void processNode(HeaderBuffer* packet, void* cond, InspectorFuncOutput* out);

    __device__ void setInspectorFunction(Inspector_t inspectorFun);

    __device__ InspectorNode* hasThisChild(InspectorNode* child);

    __device__ bool insertChild(InspectorNode* n);

    __device__ void setRuleId(uint32_t ruleId);

    __device__ void setRule(Inspector_t inspectorFun, uint32_t ruleId);

    friend class RuleTrie;
};

class RuleTrie {
public:
#define RULE_TRIE_MAX_INSPECTOR_NODE_COUNT          50
#define RULE_TRIE_MAX_INDIVIDUAL_RULE_COUNT         20

    InspectorNode root;
    InspectorNode nodes[RULE_TRIE_MAX_INSPECTOR_NODE_COUNT];
    size_t nodeCounter;

    __host__ __device__ RuleTrie() {}

    __device__  void initTrie();

    __device__ bool insertRule(Inspector_t rule[], size_t nodesCount, RuleName ruleId);

    __device__ bool insertRules(Rule_t rules[], size_t ruleCount);

    __device__ void processTrie(HeaderBuffer* h);

    __device__ void printTrie(InspectorNode* parent, int depth);
};

#endif // GPU_RULES_GRAPH_H_