
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
//     bool isLeaf;

//     void addChild(InspectorNode* node);
// };

// class RuleTrie {
// public:
//     InspectorNode root;
//     InspectorNode nodes[100];
//     size_t nodeCounter;

//     RuleTrie() : nodeCounter(0) {}

//     void insertRule(InspectorFunc_t rule[]);

//     void searchRule(HeaderBuffer* p);
// };

// static int findNodeInChildrenNodes(InspectorNode* parent, InspectorFunc_t func) {
//     for(size_t i = 0 ; i < parent->childrenCount ; i++)
//         if(parent->children[i]->inspectorFunc = func) 
//             return i;
//     return -1;
// }

// void RuleTrie::insertRule(InspectorFunc_t rule[]) {
//     int ruleLen = sizeof(rule)/sizeof(rule[0]);
//     int ruleCounter = 0;
//     // InspectorNode* currentNode = &root;

//     InspectorNode* currentNode = &root;
//     int id;
//     while((id=findNodeInChildrenNodes(currentNode, rule[ruleCounter])) != -1) {
//         currentNode = currentNode->children[id];
//         ruleCounter++;
//     }

//     int restRuleCount = ruleLen-ruleCounter;
//     for(int i = 0 ; i < restRuleCount ; i++) {
//         InspectorNode* newNode = &nodes[nodeCounter++];
//         newNode->inspectorFunc = rule[ruleCounter++];
//         currentNode->addChild(newNode);
//         if(ruleCounter)
//     }
// }

// void RuleTrie::insertRule(InspectorFunc_t rule[]) {
//     size_t ruleLen = sizeof(rule)/sizeof(rule[0]);
//     InspectorNode* currentNode = &root;
//     int k;

//     for (int i = 0; i < ruleLen; i++) {
//         int k = -1;
//         // for (int j = 0; j < currentNode->childrenCount; j++) {
//         //     InspectorNode* currentChild = currentNode->children[j];
//         //     if (currentChild->inspectorFunc == rule[i]) {
//         //         k = j;
//         //         break;
//         //     }
            
//         // }
//         k = findNodeInChildrenNodes(currentNode, rule[i]);
//         if (k == -1) {
//             InspectorNode* newNode = &nodes[nodeCounter++];
//             currentNode->addChild(newNode);
//             k = currentNode->childrenCount - 1;
//         }
//         currentNode = currentNode->children[k];
//     }

// }
