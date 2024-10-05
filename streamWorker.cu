#include <cuda_runtime.h>
#include "rulesGraph.cuh"
#include "config/config.h"
#include <string>
#include <pcap.h>
#include <iostream>
#include "gputimer.cuh"

#define _GB_                (1024.0*1024.0*1024.0)             
#define _MB_                (1024.0*1024.0)             
#define _KB_                (1024.0) 

#define ALIGN_ADDRESS(addr, struct, alignedAddr)                {                                                                                   \
                                                                    size_t alignment = alignof(struct);                                             \
                                                                    uintptr_t ptr = (uintptr_t) (addr);                                             \
                                                                    void* alignedAddress = (void*) ((ptr + (alignment - 1)) & ~(alignment - 1)) ;   \
                                                                    alignedAddr = (struct*) alignedAddress;                                         \
                                                                } 

#define CHECK_CUDA_ERROR_(fun)                                                   \
{                                                                               \
    cudaError_t err = fun;                                                      \
    if(err != cudaSuccess) {                                                    \
        printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
        return false;                                                               \
    }                                                                           \
}

#define COLOR_RESET                             "\x1b[0m"
#define COLOR_RED                               "\x1b[31m"
#define COLOR_GREEN                             "\x1b[32m"
#define COLOR_BLUE                              "\x1b[34m"

#define PRINT_STREAM(COLOR, ...)                       if(1) {printf("[%s%s%s] - ", COLOR.c_str(), streamName.c_str(), COLOR_RESET); printf(__VA_ARGS__);}

static int readPacketOfflineMode(PacketMetadata* packetsMetadata, size_t mempoolSize ,PacketMempool* packetsMempool , size_t packetCount ,pcap_t* handle, size_t* counter, size_t* packetSize, double* startTime) {
    size_t packetOffset = 0;
    size_t packetCounter = 0;
    int result;
    static const u_char *packet;
    static struct pcap_pkthdr *header;
    double timeStamp;

    do {
        if(packet != NULL && header != NULL) {

            timeStamp = (double)(header->ts.tv_sec) + (double)((header->ts.tv_usec*1.0) / 1e6f);

            if((Configfields::chunkTimeLimit != CONFIG_FIELD_DOUBLE_NOT_SET_VAL) && (timeStamp - *startTime > Configfields::chunkTimeLimit / 2)) break;                                              // Time Limit

            if((packetCounter >= packetCount)) break;                                                     // Count Limit
            PacketMetadata md = {.packetOffset = packetOffset, .packetLen = header->caplen};
            packetsMetadata[packetCounter] = md;

            if(md.packetOffset+md.packetLen+sizeof(PacketInfo) >= mempoolSize) break;                          // Mempool Limit
            memcpy(packetsMempool+md.packetOffset+sizeof(PacketInfo), packet, md.packetLen);

            packetCounter += 1;
            packetOffset += md.packetLen+sizeof(PacketInfo);
        }
    }
    while(((result = (pcap_next_ex(handle, &header, &packet))) >= 0));

    *startTime = timeStamp;
    *packetSize = packetOffset;
    *counter = packetCounter;

    return result;
}

static __global__ void performProcessKernel(PacketMetadata* packetsMetadata, uint8_t* packetsMempool, size_t packetCount, RuleTrie* trie) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= packetCount) return;

    PacketMetadata md;     
    md = packetsMetadata[idx];     

    HeaderBuffer h(packetsMempool + (md.packetOffset + sizeof(PacketInfo)), md.packetLen);

    PacketInfo* info;
    ALIGN_ADDRESS(packetsMempool+md.packetOffset, PacketInfo, info);

    trie->processTrie(&h);
    info->ruleId = h.ruleId;

}

struct MempoolInfo_t {
    size_t packetsCount;
    size_t packetsSize;
};

class StreamWorker {
private:
    std::string         color;
    cudaStream_t        stream;
    std::string         streamName;
    cudaEvent_t         timer;
    size_t              mempoolSize;
    size_t              maxPacketCount;

    PacketMempool*      d_packetMempool;
    PacketMempool*      h_packetMempool;
    PacketMetadata*     d_packetMetadata;
    PacketMetadata*     h_packetMetadata;

    GPUTimer*           timerHD;
    GPUTimer*           timerKernel;
    GPUTimer*           timerDH;
    float               durationHD;
    float               durationKernel;
    float               durationDH;

    struct StreamReport {
        size_t          totalPacketCount = 0;
        size_t          totalPacketSize = 0;
        size_t          totalRuleCount[Rule_Count] = {0};
    } streamReport;
            
public:

    StreamWorker(std::string streamName, std::string streamColor) {
        cudaStreamCreate(&this->stream);
        cudaEventCreate(&this->timer);
        this->streamName = streamName; 
        this->color = streamColor;

        timerHD = new GPUTimer(stream);
        timerKernel = new GPUTimer(stream);
        timerDH = new GPUTimer(stream);
    }

    StreamWorker() {
        StreamWorker("", "");
    }

    bool allocateMemory(size_t mempoolSize, size_t packetCount, bool verbose) {
        CHECK_CUDA_ERROR_(cudaHostAlloc((void**) &h_packetMempool, mempoolSize, cudaHostAllocDefault));
        CHECK_CUDA_ERROR_(cudaHostAlloc((void**) &h_packetMetadata, packetCount*sizeof(PacketMetadata), cudaHostAllocDefault));

        CHECK_CUDA_ERROR_(cudaMalloc((void**) &d_packetMempool, mempoolSize));
        CHECK_CUDA_ERROR_(cudaMalloc((void**) &d_packetMetadata, packetCount*sizeof(PacketMetadata)));

        if (h_packetMempool == NULL || h_packetMetadata == NULL) {
            PRINT_STREAM(color, "Unable to allocaote Mempool or Metadata\n");
        } else {
             if (verbose) PRINT_STREAM(color, "Memory Allocated : mempoolSize : %ld, packetCount : %ld\n", mempoolSize, packetCount);
        }

        this->mempoolSize = mempoolSize;
        this->maxPacketCount = packetCount;

        return true;
    }

    int readPacket(pcap_t* handle, MempoolInfo_t& mempoolInfo, double* startTime, bool verbose) {        
        size_t counter;
        size_t pSize;
        // double startTime = 0;
        int result;

        if(Configfields::readPacketMode.compare("offline") == 0)
            result = readPacketOfflineMode(h_packetMetadata, mempoolSize, h_packetMempool, maxPacketCount, handle, &counter, &pSize, startTime);
        else {
            PRINT_STREAM(color, "Invalid Read Mode in Config file\n");
            return -1;
        }

        if(result < 0 && result != -2) {
            PRINT_STREAM(color, "Something went wrong in reading packets(%d)\n", result);
            PRINT_STREAM(color, "The Error was : %s\n", pcap_geterr(handle));
            PRINT_STREAM(color, "The counter was %ld\n", mempoolInfo.packetsCount);
        }

        streamReport.totalPacketCount += counter;
        streamReport.totalPacketSize += pSize;

        mempoolInfo.packetsCount = counter;
        mempoolInfo.packetsSize = pSize;

        if (verbose) PRINT_STREAM(color, "%ld Packets Read From Pcap File\n\n", mempoolInfo.packetsCount);

        return result;

    }

    bool performHD(MempoolInfo_t& memInfo, bool verbose) {
        if (Configfields::isTimerSet) timerHD->start();
        CHECK_CUDA_ERROR_(cudaMemcpyAsync((void*) d_packetMempool, (void*) h_packetMempool, memInfo.packetsSize, cudaMemcpyHostToDevice, stream));
        CHECK_CUDA_ERROR_(cudaMemcpyAsync((void*) d_packetMetadata, (void*) h_packetMetadata, memInfo.packetsCount * sizeof(PacketMetadata), cudaMemcpyHostToDevice, stream));
        if (Configfields::isTimerSet) timerHD->end();
        if (Configfields::isTimerSet) durationHD = timerHD->elapsed();

        if (verbose) PRINT_STREAM(color, "%ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Host To Device \n" , (memInfo.packetsCount), (memInfo.packetsSize)/(_GB_), (memInfo.packetsCount * sizeof(PacketMetadata)) / (_GB_));
        if (verbose && Configfields::isTimerSet) PRINT_STREAM(color, "\t| DurationHD : %lf ms\n", durationHD);
        if (verbose && Configfields::isTimerSet) PRINT_STREAM(color, "\t| BandwidthHD : %lf Gb/s\n\n", ((memInfo.packetsSize + memInfo.packetsCount * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_ * durationHD));

        return true;
    }

    bool performProcess(RuleTrie* trie, size_t packetCount, MempoolInfo_t& memInfo, bool verbose) {
        dim3 blockDim(Configfields::threadPerBlock,1,1);
        dim3 gridDim((packetCount + blockDim.x - 1) / blockDim.x,1,1);

        if (Configfields::isTimerSet) timerKernel->start();
        performProcessKernel<<<gridDim, blockDim, 0, stream>>>(d_packetMetadata, d_packetMempool, packetCount, trie);
        if (Configfields::isTimerSet) timerKernel->end();
        if (Configfields::isTimerSet) durationKernel = timerKernel->elapsed();

        if (verbose) PRINT_STREAM(color, "RuleTrie Was Processed For %d Threads Per Block\n", blockDim.x);
        if (verbose) PRINT_STREAM(color, "%ld Packets (%.3lf GB) Processed On GPU\n", packetCount, ((memInfo.packetsSize) * 1.0)/(_GB_));
        if (verbose && Configfields::isTimerSet) PRINT_STREAM(color, "\t| DurationKernel : %lf ms\n", durationKernel);
        if (verbose && Configfields::isTimerSet) PRINT_STREAM(color, "\t| BandwidthKernel : %lf Gb/s\n\n", ((memInfo.packetsSize) * 1000.0 * 8.0)/(_GB_ * durationKernel));

        return true;
    }

    bool performDH(MempoolInfo_t& memInfo, bool verbose) {
        if (Configfields::isTimerSet) timerDH->start();
        CHECK_CUDA_ERROR_(cudaMemcpyAsync((void*) h_packetMempool, (void*) d_packetMempool, memInfo.packetsSize, cudaMemcpyDeviceToHost, stream));
        CHECK_CUDA_ERROR_(cudaMemcpyAsync((void*) h_packetMetadata, (void*) d_packetMetadata, memInfo.packetsCount * sizeof(PacketMetadata), cudaMemcpyDeviceToHost, stream));
        if (Configfields::isTimerSet) timerDH->end();
        if (Configfields::isTimerSet) durationDH = timerDH->elapsed();

        if (verbose) PRINT_STREAM(color, "%ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Device To Host \n" , (memInfo.packetsCount), (memInfo.packetsSize)/(_GB_), (memInfo.packetsCount * sizeof(PacketMetadata)) / (_GB_));
        if (verbose && Configfields::isTimerSet) PRINT_STREAM(color, "\t| DurationDH : %lf ms\n", durationDH);
        if (verbose && Configfields::isTimerSet) PRINT_STREAM(color, "\t| BandwidthDH : %lf Gb/s\n\n", ((memInfo.packetsSize + memInfo.packetsCount * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_ * durationDH));

        CHECK_CUDA_ERROR_(cudaStreamSynchronize(stream));

        return true;
    }

    bool reportCounter(MempoolInfo_t& memInfo) {
        for(size_t i = 0 ; i < memInfo.packetsCount ; i++) {
            PacketMetadata md = h_packetMetadata[i];
            PacketInfo* info;

            ALIGN_ADDRESS(h_packetMempool + md.packetOffset, PacketInfo, info);
            streamReport.totalRuleCount[info->ruleId]++;
        }

        memInfo.packetsCount = 0;
        memInfo.packetsSize = 0;

        return true;
    }

    bool freeMempory(bool verbose) {
        cudaFreeHost((void*) h_packetMempool);
        cudaFreeHost((void*) h_packetMetadata);

        cudaFree((void*) d_packetMempool);
        cudaFree((void*) d_packetMetadata);

        cudaStreamDestroy(stream);
        cudaEventDestroy(timer);
        streamName.~basic_string();

        return true;
    }

    StreamReport getReport() {
        return streamReport;
    }
};