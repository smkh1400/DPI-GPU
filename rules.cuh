#ifndef GPU_RULES_H_
#define GPU_RULES_H_

#include "rulesGraph.cuh"

__global__ void registerRules(RuleTrie* trie);

#endif