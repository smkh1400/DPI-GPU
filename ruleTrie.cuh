
// #include <stdint.h>
// #include <sys/types.h>

// class HeaderBuffer {
// public:

//     uint8_t packetData[128];
//     uint32_t ruleId;
//     bool isDone : 1;
//     bool isValid : 1;
// };

// struct InspectorFuncOutput {
//     bool        checkConditionResult;
//     void*       extractedCondition;
//     int32_t     calculatedOffset;
// };

// typedef InspectorFuncOutput (*InspectorFunc_t) (HeaderBuffer*, void*);

// /* used in trie, holding InspectorFunctions */
// class InspectorNode {
// public:
//     InspectorNode* children[100];
//     size_t childrenCount;
//     InspectorFunc_t inspectorFunc;
//     uint32_t ruleId;

//     void addChild(InspectorNode* node);
// };

// class RuleTrie {
//     InspectorNode root;
//     InspectorNode nodes[100];
//     size_t nodeCounter;

//     void insertRule(InspectorFunc_t rule[], InspectorNode*);

//     void searchRule(HeaderBuffer* p);
// };

// void RuleTrie::insertRule(InspectorFunc_t rule[], InspectorNode* currentNode) {
//     size_t ruleLen = sizeof(rule)/sizeof(rule[0]);
//     size_t ruleCounter = 0;
//     // InspectorNode* currentNode = &root;

//     for(size_t i = 0 ; i < currentNode->childrenCount ; i++) {
//         currentNode = currentNode->children[i];

//         if(currentNode->inspectorFunc == rule[ruleCounter]) {
//             return insertRule(rule, currentNode);
//         } 
//         else {
//             InspectorNode* newNode = &nodes[nodeCounter++];
//             newNode->inspectorFunc = rule[ruleCounter++];
//             currentNode->addChild(newNode);
//             return insertRule(rule, newNode);
//         }
//     }

// }

// void RuleTrie::insertRule(InspectorFunc_t rule[]) {
//     InspectorNode* currentNode = &root;

//     for(size_t i = 0 ; i < currentNode->childrenCount ; i++) {
//         currentNode = currentNode->children[i];

//         if(currentNode->inspectorFunc == rule[i]) {
//             currentNode = 
//         } else {
//             continue;
//         }
//     }
// }