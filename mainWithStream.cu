#include <cuda_runtime.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <endian.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#include "rulesGraph.cuh"
#include "header.h"
#include "gputimer.cuh"
#include "rules.cuh"
#include "config/config.h"

#define CHECK_CUDA_ERROR(fun)                                                   \
{                                                                               \
    cudaError_t err = fun;                                                      \
    if(err != cudaSuccess) {                                                    \
        printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
        return -1;                                                               \
    }                                                                           \
}

#define __DEBUG_ENABLE      (1)
#define __DEBUG_LOG(...)         {if(__DEBUG_ENABLE) {printf(__VA_ARGS__);}}

#define ALIGN_ADDRESS(addr, struct, alignedAddr)                {                                                                                   \
                                                                    size_t alignment = alignof(struct);                                             \
                                                                    uintptr_t ptr = (uintptr_t) (addr);                                             \
                                                                    void* alignedAddress = (void*) ((ptr + (alignment - 1)) & ~(alignment - 1)) ;   \
                                                                    alignedAddr = (struct*) alignedAddress;                                         \
                                                                }   

#define _GB_                (1024.0*1024.0*1024.0)             
#define _MB_                (1024.0*1024.0)             
#define _KB_                (1024.0)             

#define HOST_RAM_SIZE       (60.0 * _GB_)    
#define DEVICE_RAM_SIZE     (21.0 * _GB_)

#define MIN(x, y)           ((x) < (y) ? (x) : (y))

#define THREADS_PER_SM                                      (1536)                  // MAX THREADS IN SM
#define SM_PER_GPU                                          (128)
#define SIZE_OF_PACKET                                      (sizeof(HeaderBuffer))  // ~1K 
#define PACKETS_PER_SM                                      (ConfigFeilds::packetsPerThread * THREADS_PER_SM)
#define PACKETS_SIZE_PER_SM                                 (PACKETS_PER_SM * SIZE_OF_PACKET)
#define REGISTER_FILE_SIZE_PER_SM                           (256 * _KB_)
#define PACKETS_LOCAL_SIZE_PER_SM                           (PACKETS_SIZE_PER_SM - REGISTER_FILE_SIZE_PER_SM)
#define PACKETS_LOCAL_SIZE_PER_GPU                          (SM_PER_GPU * PACKETS_LOCAL_SIZE_PER_SM)

#define PACKET_BUFFER_CHUNK_SIZE            (PACKETS_PER_SM * SM_PER_GPU)

#define RULE_TRIE_SIZE                      (sizeof(RuleTrie))
#define PACKETS_INFO_SIZE                   (PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketInfo))
#define PACKETS_METADATA_SIZE               (PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketMetadata))
#define PACKETS_MEMPOOL_SIZE                (MIN(DEVICE_RAM_SIZE, HOST_RAM_SIZE) - (PACKETS_METADATA_SIZE + RULE_TRIE_SIZE))


__global__ void performProcess(PacketMetadata* packetsMetadata, uint8_t* packetsMempool, size_t packetCount, RuleTrie* trie) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    HeaderBuffer h;

    if (idx >= packetCount) return;

    PacketMetadata md = packetsMetadata[idx];     
    PacketInfo* info;

    ALIGN_ADDRESS(packetsMempool+md.packetOffset, PacketInfo, info);
    
    memcpy(h.headerData, packetsMempool + (md.packetOffset + sizeof(PacketInfo)), HEADER_BUFFER_DATA_MAX_SIZE * sizeof(uint8_t));

    h.packetLen = md.packetLen;
    trie->processTrie(&h);
    info->ruleId = h.ruleId;
}

static int readPacketChunkTimeMode(PacketMetadata* packetsMetadata, uint8_t* packetsMempool ,pcap_t* handle, size_t* counter, size_t* packetSize, double* startTime) {
    *counter = 0;
    size_t packetOffset = 0;
    int result;
    static const u_char *packet;
    static struct pcap_pkthdr *header;
    double timeStamp;

    do {
        if(packet != NULL && header != NULL) {
            timeStamp = (double)(header->ts.tv_sec) + (double)((header->ts.tv_usec*1.0) / 1e6f);

            if(timeStamp - *startTime > ConfigFeilds::interval/2) break;                                            // Time Mode

            if(*counter * sizeof(PacketMetadata) >= PACKETS_METADATA_SIZE/2) break;                                 // packetMetadata Capacity

            PacketMetadata md = {.packetOffset = packetOffset, .packetLen = header->caplen};
            packetsMetadata[*counter] = md;

            if(md.packetOffset+md.packetLen+sizeof(PacketInfo) >= PACKETS_MEMPOOL_SIZE / 2) break;                  // Mempool Capacity

            memcpy(packetsMempool+md.packetOffset+sizeof(PacketInfo), packet, md.packetLen);

            *counter += 1;
            packetOffset += md.packetLen+sizeof(PacketInfo);
        }
    }
    while(((result = (pcap_next_ex(handle, &header, &packet))) >= 0));

    *startTime = timeStamp;
    *packetSize = packetOffset;

    return result;
}

static pcap_t* openPcapFile(const char* pcapFilePath) {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = (pcap_t*) malloc(sizeof(pcap_t*));
    
    handle = pcap_open_offline(pcapFilePath, errBuf);

    return handle;
} 

static double findFirstTimeStamp(const char* pcapFilePath) {
    pcap_t* handle = openPcapFile(pcapFilePath);
    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;

    if ((result = (pcap_next_ex(handle, &header, &packet))) < 0) return -1;

    double firstTime = (double) header->ts.tv_sec + (double) ((header->ts.tv_usec*1.0) / 1e6f);

    pcap_close(handle);

    return firstTime;
}

static int readPacketChunk(PacketMetadata* packetsMetadata, uint8_t* packetsMempool ,pcap_t* handle, size_t* counter, size_t* packetSize) {
    *counter = 0;
    size_t packetOffset = 0;
    int result;
    const u_char *packet;
    struct pcap_pkthdr *header;

    while((*counter < PACKET_BUFFER_CHUNK_SIZE / 2)) {

        if(((result = (pcap_next_ex(handle, &header, &packet))) < 0)) break;

        PacketMetadata md = {.packetOffset = packetOffset, .packetLen = header->caplen};
        packetsMetadata[*counter] = md;

        if(md.packetOffset+md.packetLen+sizeof(PacketInfo) >= PACKETS_MEMPOOL_SIZE / 2) break; // TODO
        memcpy(packetsMempool+md.packetOffset+sizeof(PacketInfo), packet, md.packetLen);

        *counter += 1;
        packetOffset += md.packetLen+sizeof(PacketInfo);
    }

    *packetSize = packetOffset;
    return result;
}   

static bool inline hasPcapExtension(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if(ext != NULL && strcmp(ext, ".pcap") == 0) 
        return true;
    return false;
}



static int processPcapFile(const char* pcapFilePath, bool verbose) {

    pcap_t* handle;
    pcap_t* tempHandle;

    if(!hasPcapExtension(pcapFilePath)) 
    {
        printf("Invalid Extension, Excepted .pcap\n");
        return -1;
    }

    handle = openPcapFile(pcapFilePath);
    tempHandle = openPcapFile(pcapFilePath);

    if(handle == NULL || tempHandle == NULL)
    {
        printf("Unable To Open Pcap File : %s\n", pcapFilePath);
        return -1;
    } 

    if(verbose) printf("Pcap File %s Opened\n", pcapFilePath);
    
    size_t pcapFileSize;
    {
        FILE* fd = fopen(pcapFilePath, "r");


        fseek(fd, 0, SEEK_END);
        pcapFileSize = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        fclose(fd);
    }  

    PacketMetadata* h_packetsMetadataPing;
    PacketMetadata* h_packetsMetadataPong;
    PacketMetadata* d_packetsMetadataPing;
    PacketMetadata* d_packetsMetadataPong;

    uint8_t* d_packetsMemPoolPing;
    uint8_t* d_packetsMemPoolPong;
    uint8_t* h_packetsMemPoolPing;
    uint8_t* h_packetsMemPoolPong;

    CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMetadataPing, PACKETS_METADATA_SIZE / 2, cudaHostAllocDefault));
    CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMetadataPong, PACKETS_METADATA_SIZE / 2, cudaHostAllocDefault));
    CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMemPoolPing, PACKETS_MEMPOOL_SIZE / 2, cudaHostAllocDefault));
    CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMemPoolPong, PACKETS_MEMPOOL_SIZE / 2, cudaHostAllocDefault));

    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMetadataPing, PACKETS_METADATA_SIZE / 2));
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMetadataPong, PACKETS_METADATA_SIZE / 2));
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMemPoolPing, PACKETS_MEMPOOL_SIZE / 2));
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMemPoolPong, PACKETS_MEMPOOL_SIZE / 2));

    if(h_packetsMetadataPing == NULL || h_packetsMetadataPong == NULL || h_packetsMemPoolPing == NULL || h_packetsMemPoolPong == NULL) {
        printf("Unable to allocate Mempool and Metadata\n");
        return -1;
    }


    CHECK_CUDA_ERROR(cudaThreadSetLimit(cudaLimitStackSize, 10*1024));

    RuleTrie* d_trie;
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_trie, RULE_TRIE_SIZE * 10)); // can't remember why we allocate 10 times the RULE_TRIE_SIZE

    registerRules<<<1,1>>>(d_trie);
    CHECK_CUDA_ERROR(cudaDeviceSynchronize());
    if(verbose) printf("RuleGraph Was Registered On Device\n");

    size_t stackSize;
    CHECK_CUDA_ERROR(cudaThreadGetLimit(&stackSize, cudaLimitStackSize));

    size_t counterPing;
    size_t counterPong;
    size_t packetSizePing;
    size_t packetSizePong;
    size_t HDPacketSizePing;
    size_t HDPacketSizePong;
    size_t DHPacketSizePing;
    size_t DHPacketSizePong;
    size_t chunkCounter = 0;

    size_t totalCounter = 0;
    size_t totalPacketSize = 0;
    size_t totalHDPacketSize = 0;
    size_t totalDHPacketSize = 0;

    double totalHDDuration = 0;
    double totalDHDuration = 0;
    double totalKernelDuration = 0;

    int ruleCount[Rule_Count] = {0};

    cudaStream_t pingStream;
    cudaStream_t pongStream;

    cudaStreamCreate(&pingStream);
    cudaStreamCreate(&pongStream);


    float durationChunk;
    GPUTimer timerChunk(0);
    double totalDuration = 0;

    float durationDHPing;
    GPUTimer timerDHPing(pingStream);

    float durationDHPong;
    GPUTimer timerDHPong(pongStream);

    float durationHDPing;
    GPUTimer timerHDPing(pingStream);

    float durationHDPong;
    GPUTimer timerHDPong(pongStream);

    float durationKernelPing;
    GPUTimer timerKernelPing(pingStream);

    float durationKernelPong;
    GPUTimer timerKernelPong(pongStream);

    double startTime = findFirstTimeStamp(pcapFilePath);

    int result = 0;

    while (1) {
        
        if(verbose) printf(">> Chunk %d Started\n", chunkCounter+1);

        if(result != -2)
        {
            //ping
            if (ConfigFeilds::readPacketMode.compare("offline") == 0)                // TODO 
                result = readPacketChunk(h_packetsMetadataPing, h_packetsMemPoolPing, handle, &counterPing, &packetSizePing);
            else if(ConfigFeilds::readPacketMode.compare("online") == 0) 
                result = readPacketChunkTimeMode(h_packetsMetadataPing, h_packetsMemPoolPing, handle, &counterPing, &packetSizePing, &startTime);
            
            if(result < 0 && result != -2 && verbose) {
                printf("Something went wrong in reading packets(%d)\n", result);
                printf("The Error was : %s\n", pcap_geterr(handle));
                printf("The counter was %d\n", counterPing);
            }

            if(result == -1) 
                break;

            totalCounter += counterPing;
            totalPacketSize += packetSizePing;

            if(verbose) printf("[PING] - %ld Packets Read From Pcap File\n", counterPing);
        } else {
            counterPing = 0;
            packetSizePing = 0;

            if(verbose) printf("[PING] - End Of Pcap File\n");

            break;
        } 

        //pong

        if(result != -2) {

            if (ConfigFeilds::readPacketMode.compare("offline") == 0)                // TODO 
                result = readPacketChunk(h_packetsMetadataPong, h_packetsMemPoolPong, handle, &counterPong, &packetSizePong);
            else if(ConfigFeilds::readPacketMode.compare("online") == 0) 
                result = readPacketChunkTimeMode(h_packetsMetadataPong, h_packetsMemPoolPong, handle, &counterPong, &packetSizePong, &startTime);
            
            if(result < 0 && result != -2 && verbose) {
                printf("Something went wrong in reading packets(%d)\n", result);
                printf("The Error was : %s\n", pcap_geterr(handle));
                printf("The counter was %d\n", counterPong);
            }

            if(result == -1) 
                break;

            totalCounter += counterPong;
            totalPacketSize += packetSizePong;

            if(verbose) printf("[PONG] - %ld Packets Read From Pcap File\n", counterPing);
        } else {
            counterPong = 0;
            packetSizePong = 0;

            if(verbose) printf("[PONG] - End Of Pcap File\n");
        }

        timerChunk.start();

        if (ConfigFeilds::isTimerSet) timerHDPing.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMemPoolPing, (void*) h_packetsMemPoolPing, packetSizePing, cudaMemcpyHostToDevice, pingStream));
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMetadataPing, (void*) h_packetsMetadataPing, counterPing * sizeof(PacketMetadata), cudaMemcpyHostToDevice, pingStream));
        if (ConfigFeilds::isTimerSet) timerHDPing.end();
        if (ConfigFeilds::isTimerSet) durationHDPing = timerHDPing.elapsed();
        if (ConfigFeilds::isTimerSet) totalHDDuration += durationHDPing;

        if(verbose) printf("[PING] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Host To Device \n", (counterPing), (packetSizePing)/(_GB_), (counterPing * sizeof(PacketMetadata)) / (_GB_));
        if(verbose && ConfigFeilds::isTimerSet) printf("[PING]\t| DurationHDPing : %lf ms\n", durationHDPing);
        if(verbose && ConfigFeilds::isTimerSet) printf("[PING]\t| BandwidthHDPing : %lf Gb/s\n", ((packetSizePing + counterPing * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationHDPing));

        if (ConfigFeilds::isTimerSet) timerHDPong.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMemPoolPong, (void*) h_packetsMemPoolPong, packetSizePong, cudaMemcpyHostToDevice, pongStream));
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMetadataPong, (void*) h_packetsMetadataPong, counterPong * sizeof(PacketMetadata), cudaMemcpyHostToDevice, pongStream));
        if (ConfigFeilds::isTimerSet) timerHDPong.end();
        if (ConfigFeilds::isTimerSet) durationHDPong = timerHDPong.elapsed();
        if (ConfigFeilds::isTimerSet) totalHDDuration += durationHDPong;

        if(verbose) printf("[PONG] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Host To Device \n", (counterPong), (packetSizePong)/(_GB_), (counterPong * sizeof(PacketMetadata)) / (_GB_));
        if(verbose && ConfigFeilds::isTimerSet) printf("[PONG]\t| DurationHDPong : %lf ms\n", durationHDPong);
        if(verbose && ConfigFeilds::isTimerSet) printf("[PONG]\t| BandwidthHDPong : %lf Gb/s\n", ((packetSizePong + counterPong * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationHDPong));
        
        if(verbose) printf("______________________________________________________________________\n");

        totalHDPacketSize += packetSizePing + packetSizePong + (counterPing + counterPong) * sizeof(PacketMetadata);

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        int threadPerBlock = 256;
        
        if (ConfigFeilds::isTimerSet) timerKernelPing.start();
        performProcess<<<((counterPing+threadPerBlock-1)/threadPerBlock), threadPerBlock, 0, pingStream>>>(d_packetsMetadataPing, d_packetsMemPoolPing, counterPing, d_trie);
        if (ConfigFeilds::isTimerSet) timerKernelPing.end();
        if (ConfigFeilds::isTimerSet) durationKernelPing = timerKernelPing.elapsed();
        if (ConfigFeilds::isTimerSet) totalKernelDuration += durationKernelPing;
                
        if(verbose) printf("[PING] -  RuleGraph Was Processed For %d Threads Per Block\n", threadPerBlock);
        if(verbose) printf("[PING] - %ld Packets (%.3lf GB) Processed On GPU\n", counterPing, ((packetSizePing) * 1.0)/(_GB_));
        if(verbose  && ConfigFeilds::isTimerSet) printf("[PING]\t| DurationKernel : %lf ms\n", durationKernelPing);
        if(verbose  && ConfigFeilds::isTimerSet) printf("[PING]\t| BandwidthKernel : %lf Gb/s\n", ((packetSizePing) * 1000.0 * 8.0)/(_GB_*durationKernelPing));

        if (ConfigFeilds::isTimerSet) timerKernelPong.start();
        performProcess<<<((counterPong+threadPerBlock-1)/threadPerBlock), threadPerBlock, 0, pongStream>>>(d_packetsMetadataPong, d_packetsMemPoolPong, counterPong, d_trie);
        if (ConfigFeilds::isTimerSet) timerKernelPong.end();
        if (ConfigFeilds::isTimerSet) durationKernelPong = timerKernelPong.elapsed();
        if (ConfigFeilds::isTimerSet) totalKernelDuration += durationKernelPong;

        if(verbose) printf("[PONG] - RuleGraph Was Processed For %d Threads Per Block\n", threadPerBlock);
        if(verbose) printf("[PONG] - %ld Packets (%.3lf GB) Processed On GPU \n", counterPong, ((packetSizePong) * 1.0)/(_GB_));
        if(verbose  && ConfigFeilds::isTimerSet) printf("[PONG]\t| DurationKernelPong : %lf ms\n", durationKernelPong);
        if(verbose  && ConfigFeilds::isTimerSet) printf("[PONG]\t| BandwidthKernelPong : %lf Gb/s\n", ((packetSizePong) * 1000.0 * 8.0)/(_GB_*durationKernelPong));

        if(verbose) printf("______________________________________________________________________\n");

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


        if (ConfigFeilds::isTimerSet) timerDHPing.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMetadataPing, (void*) d_packetsMetadataPing, counterPing * sizeof(PacketMetadata), cudaMemcpyDeviceToHost, pingStream));
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMemPoolPing, (void*) d_packetsMemPoolPing, packetSizePing, cudaMemcpyDeviceToHost, pingStream));
        if (ConfigFeilds::isTimerSet) timerDHPing.end();
        if (ConfigFeilds::isTimerSet) durationDHPing = timerDHPing.elapsed();
        if (ConfigFeilds::isTimerSet) totalDHDuration += durationDHPing;

        // if(verbose) printf("[PING] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Device to Host\n", (counterPing), (packetSizePing)/(_GB_), (counterPing * sizeof(PacketMetadata)) / (_GB_));
        // if(verbose && ConfigFeilds::isTimerSet) printf("[PONG]\t| DurationDHPing : %lf ms\n", durationDHPing);
        // if(verbose && ConfigFeilds::isTimerSet) printf("[PING]\t| BandwidthDHPing : %lf Gb/s\n", ((packetSizePing + counterPing * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationDHPing));

        if (ConfigFeilds::isTimerSet) timerDHPong.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMetadataPong, (void*) d_packetsMetadataPong, counterPong * sizeof(PacketMetadata), cudaMemcpyDeviceToHost, pongStream));
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMemPoolPong, (void*) d_packetsMemPoolPong, packetSizePong, cudaMemcpyDeviceToHost, pongStream));
        if (ConfigFeilds::isTimerSet) timerDHPong.end();
        if (ConfigFeilds::isTimerSet) durationDHPong = timerDHPong.elapsed();
        if (ConfigFeilds::isTimerSet) totalDHDuration += durationDHPong;

        // if(verbose) printf("[PONG] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Device to Host\n", (counterPong), (packetSizePong)/(_GB_), (counterPong * sizeof(PacketMetadata)) / (_GB_));
        // if(verbose && ConfigFeilds::isTimerSet) printf("[PONG]\t| DurationDHPong : %lf ms\n", durationDHPong);
        // if(verbose && ConfigFeilds::isTimerSet) printf("[PONG]\t| BandwidthDHPong : %lf Gb/s\n", ((packetSizePong + counterPong * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationDHPong));

        if(verbose) printf("______________________________________________________________________\n");

        totalDHPacketSize += (packetSizePing + packetSizePong) + (counterPing + counterPong) * sizeof(PacketMetadata);

        timerChunk.end();
        durationChunk = timerChunk.elapsed();
        totalDuration += durationChunk;

        if(verbose) printf(">> %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered\n", (counterPing + counterPong), (packetSizePing + packetSizePong)/(_GB_), ((counterPing + counterPong) * sizeof(PacketMetadata)) / (_GB_));
        if(verbose) printf("\t| DurationChunk : %lf ms\n", durationChunk);
        if(verbose) printf("\t| BandwidthChunk : %lf Gb/s\n", (((packetSizePing + packetSizePong) + (counterPing + counterPong) * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_ * durationChunk));
        if(verbose) printf("########################################################################\n\n");


        cudaStreamSynchronize(pingStream);
        cudaStreamSynchronize(pongStream);

        //ping
        for(size_t i = 0 ; i < counterPing ; i++) {  
            PacketMetadata md = h_packetsMetadataPing[i];
            PacketInfo* info;

            ALIGN_ADDRESS(h_packetsMemPoolPing + md.packetOffset, PacketInfo, info);

            ruleCount[info->ruleId]++;
        }

        //pong
        for(size_t i = 0 ; i < counterPong ; i++) {  
            PacketMetadata md = h_packetsMetadataPong[i];
            PacketInfo* info;

            ALIGN_ADDRESS(h_packetsMemPoolPong+md.packetOffset, PacketInfo, info);

            ruleCount[info->ruleId]++;
        }

        if(!verbose){
            printf("\033[2K\r");
            fflush(stdout);

            printf("# %0.3lf% Of %s Is Procesed", ((totalPacketSize*1.0)/(pcapFileSize*1.0))*100, pcapFilePath);
            fflush(stdout);
        }

        chunkCounter++;

        if(result == -2)
            break;
    }


    if(!verbose){
        printf("\033[2K\r");
        fflush(stdout);

        printf("# 100%% Of %s Is Procesed\n", pcapFilePath);
        fflush(stdout);
    }

    pcap_close(handle);

    printf(">> Result:\n\t| Total Packets: %ld\n", totalCounter);

    for(size_t i = 0 ; i < Rule_Count ; i++)
        if(ruleCount[i] != 0) printf("\t| %s : %d\n", getRuleName(i), ruleCount[i]);

    
    printf("\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\t| Bandwidth: %lf MPacket/s\n\t| Size: %lf Gb\n", totalDuration, (totalPacketSize * 8.0 * 1000.0) / (totalDuration * _GB_), (totalCounter * 1000.0) / (totalDuration * _MB_)  ,(totalPacketSize * 8.0)/(_GB_));    
    
    return 0;
}


static int processDirectory(const char* directoryPath, bool verbose) {
    struct dirent* entry;
    DIR* dp;

    dp = opendir(directoryPath);
    if(dp == NULL) {
        printf("Unable To Open Directory %s\n", directoryPath);
        return -1;
    }

    while((entry = readdir(dp)) != NULL) {
        if(entry->d_type == DT_REG && hasPcapExtension(entry->d_name)) {
            char fullPath[1024];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, entry->d_name);            
            processPcapFile(fullPath, verbose);
        }
    }

    closedir(dp);
}

#define HELP_COMMAND_LINE       "Usage: ./ruleGraph [options] <arguments>"                                                  \
                                "\nAvailable Options:"                                                                      \
                                "\n\t-f\t\t: Select The Pcap File"                                                          \
                                "\n\t-d\t\t: Select The Directory Containing Multiple Pcap Files"                           \
                                "\n\t-c\t\t: Select The Config File (Default Is Set To 'config.yml')"                       \
                                "\n\t-v\t\t: Make The Operation More Talkative"                                             \
                                "\n\t-h\t\t: Print Help And Exit\n" 

int main(int argc, char* argv[]) {

    if(argc == 1) {
        printf(HELP_COMMAND_LINE);
        return -1;
    }

    int opt;
    bool processDir = false;
    bool processFile = false;
    bool haveConfigFileName = false;
    bool verbose = false;
    char* pstr = NULL;
    char* configFilePath = NULL;

    while((opt = getopt(argc, argv, "d:f:c:hv")) != -1) {
        switch (opt)
        {
        case 'd':
            processDir = true;
            pstr = optarg;
            break;

        case 'f':
            processFile = true;
            pstr = optarg;
            break;

        case 'c':
            haveConfigFileName = true;
            configFilePath = optarg;
            break;

        case 'h':   
            printf(HELP_COMMAND_LINE);
            return 0;

        case 'v':
            verbose = true;
            break;

        case ':':
            printf("Option -$c requires an argument\n", optopt);
            return -1;

        case '?':
            printf("Unknown Option: -%c\n", optopt);
            return -1;
        }
    }

    if (!haveConfigFileName) {
        configFilePath = "config.yml";  // default
    }

    ConfigLoader::loadAllFeilds(configFilePath);

    if(processDir) 
        return processDirectory(pstr, verbose);

    if(processFile)
        return processPcapFile(pstr, verbose);


    return -1;
}