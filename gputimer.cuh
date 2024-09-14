#ifndef GPUTIMER_CUH
#define GPUTIMER_CUH

#include <cuda_runtime.h>
#include <stdio.h>

#define CHECK_CUDA_ERROR(fun)                                                   \
{                                                                               \
    cudaError_t err = fun;                                                      \
    if(err != cudaSuccess) {                                                    \
        printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
        return -1;                                                               \
    }                                                                           \
}

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
        CHECK_CUDA_ERROR(cudaEventSynchronize(endEvent));
        CHECK_CUDA_ERROR(cudaEventElapsedTime(&elapsed, startEvent, endEvent));
        return elapsed;
    }

};

#endif