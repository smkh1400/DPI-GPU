#ifndef GPU_RULES_H_
#define GPU_RULES_H_

#include "rulesGraph.cuh"

#define RULE_SIZE(rule)         (sizeof(rule)/sizeof(rule[0]))           

__global__ void registerRules(RuleTrie* trie);

#endif