#ifndef GPUTIMER_CUH
#define GPUTIMER_CUH

#include <cuda_runtime.h>

struct GPUTimer {
    cudaEvent_t startEvent;
    cudaEvent_t endEvent;
    
    GPUTimer() {
        cudaEventCreate(&startEvent);
        cudaEventCreate(&endEvent);
    }

    ~GPUTimer() {
        cudaEventDestroy(startEvent);
        cudaEventDestroy(endEvent);
    }

    void start() {
        cudaEventRecord(startEvent, 0);
    }

    void end() {
        cudaEventRecord(endEvent, 0);
    }

    float elapsed() {
        float elapsed;
        cudaEventSynchronize(endEvent);
        cudaEventElapsedTime(&elapsed, startEvent, endEvent);
        return elapsed / 1000;
    }

};

#endif