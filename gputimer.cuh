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
    cudaStream_t stream;
    
    GPUTimer(cudaStream_t eventStream) {
        cudaEventCreate(&startEvent);
        cudaEventCreate(&endEvent);
        stream = eventStream;
    }

    ~GPUTimer() {
        cudaEventDestroy(startEvent);
        cudaEventDestroy(endEvent);
    }

    void start() {
        cudaEventRecord(startEvent, stream);
    }

    void end() {
        cudaEventRecord(endEvent, stream);
    }

    float elapsed() {
        float elapsed;
        CHECK_CUDA_ERROR(cudaEventSynchronize(endEvent));
        CHECK_CUDA_ERROR(cudaEventElapsedTime(&elapsed, startEvent, endEvent));
        return elapsed;
    }

};

#endif