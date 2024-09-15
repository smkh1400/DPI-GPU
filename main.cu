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

#define swapEndian16(x)     ((uint16_t) (((x) >> 8) | ((x) << 8)))

#if __BYTE_ORDER == __LITTLE_ENDIAN
    #define htons(x) swapEndian16(x)
    #define ntohs(x) swapEndian16(x)
#else 
    #define htons(x) x
    #define ntohs(x) x
#endif

#define LOAD_UINT8(p)               (*((uint8_t*) (p)))
#define LOAD_UINT16(p)              (uint16_t) (LOAD_UINT8(p)    | (LOAD_UINT8(p+1)    << 8))
#define LOAD_UINT32(p)              (uint32_t) ((LOAD_UINT16(p)) | ((LOAD_UINT16(p+2)) << 16))


__global__ void performProcess(PacketBuffer* packets, size_t packetCount, RuleTrie* trie) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= packetCount) return;

    HeaderBuffer h;
    InspectorFuncOutput out;

    memcpy(h.headerData, packets[idx].packetData, HEADER_BUFFER_DATA_MAX_SIZE * sizeof(uint8_t));

    h.packetLen = packets[idx].packetLen;
    trie->processTrie(&h);
    packets[idx].ruleId = h.ruleId;
}


#define _GB_                (1024.0*1024.0*1024.0)             
#define _MB_                (1024.0*1024.0)             
#define _KB_                (1024.0)             

#define HOST_RAM_SIZE       (60 * _GB_)    
#define DEVICE_RAM_SIZE     (20 * _GB_)

#define MIN(x, y)           ((x) < (y) ? (x) : (y))

#define PACKETS_PER_THREAD                  (64) //it could be 66 at max
#define MAX_PACKET_IN_RAM                   ((long long) ((long long) MIN(HOST_RAM_SIZE, DEVICE_RAM_SIZE)) / (sizeof(PacketBuffer)))
#define DEVICE_TOTAL_THREADS                (196608)

#define PACKET_BUFFER_CHUNK_SIZE            (MIN(DEVICE_TOTAL_THREADS*PACKETS_PER_THREAD, MAX_PACKET_IN_RAM))

static int readPacketChunk(PacketBuffer* h_packets, pcap_t* handle, size_t* counter, size_t* packetSize) {
    *counter = 0;
    *packetSize = 0;
    int result;
    const u_char *packet;
    struct pcap_pkthdr *header;

    while((*counter < PACKET_BUFFER_CHUNK_SIZE / 2)) {

        if(!((result = (pcap_next_ex(handle, &header, &packet))) >= 0)) break;

        PacketBuffer p(packet, header->caplen);

        h_packets[(*counter)] = p;
        *counter += 1;
        *packetSize += p.packetLen;
        // if(counter*sizeof(PacketBuffer) >= DEVICE_RAM_SIZE) break;     
    }

    return result;
}   

static bool hasPcapExtension(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if(ext != NULL && strcmp(ext, ".pcap") == 0) 
        return true;
    return false;
}

static pcap_t* openPcapFile(const char* pcapFilePath) {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = (pcap_t*) malloc(sizeof(pcap_t*));
    
    handle = pcap_open_offline(pcapFilePath, errBuf);

    return handle;
} 

static int processPcapFile(const char* pcapFilePath, bool verbose) {
    pcap_t* handle;

    if(!hasPcapExtension(pcapFilePath)) 
    {
        printf("Invalid Extension, Excepted .pcap\n");
        return -1;
    }

    handle = openPcapFile(pcapFilePath);
    if(handle == NULL)
    {
        printf("Unable To Open Pcap File : %s\n", pcapFilePath);
        return -1;
    } 

    FILE* fd = fopen("https.txt", "w");
    
    size_t pcapFileSize;

    {
        FILE* fd = fopen(pcapFilePath, "r");


        fseek(fd, 0, SEEK_END);
        pcapFileSize = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        fclose(fd);
    }


    // PacketBuffer* h_packets = (PacketBuffer*) calloc(PACKET_BUFFER_CHUNK_SIZE, sizeof(PacketBuffer));
    PacketBuffer* h_packets_ping;
    PacketBuffer* h_packets_pong;

    cudaHostAlloc((void**) &h_packets_ping, (PACKET_BUFFER_CHUNK_SIZE / 2) * sizeof(PacketBuffer), cudaHostAllocDefault);
    cudaHostAlloc((void**) &h_packets_pong, (PACKET_BUFFER_CHUNK_SIZE / 2) * sizeof(PacketBuffer), cudaHostAllocDefault);

    

    if(h_packets_ping == NULL || h_packets_pong == NULL)   
    {
        printf("Unable to allocate Packets\n");
        return -1;
    }

    if(verbose) printf("Pcap File %s Opened\n", pcapFilePath);

    PacketBuffer* d_packets_ping;
    PacketBuffer* d_packets_pong;

    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packets_ping, (PACKET_BUFFER_CHUNK_SIZE / 2) * sizeof(PacketBuffer)));
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packets_pong, (PACKET_BUFFER_CHUNK_SIZE / 2) * sizeof(PacketBuffer)));




    size_t stackSize;
    CHECK_CUDA_ERROR(cudaThreadGetLimit(&stackSize, cudaLimitStackSize));

    // if(stackSize < (HEADER_BUFFER_DATA_MAX_SIZE*))
        CHECK_CUDA_ERROR(cudaThreadSetLimit(cudaLimitStackSize, 1024*20));


    RuleTrie* d_trie;
    CHECK_CUDA_ERROR(cudaMalloc((void**) &d_trie, sizeof(RuleTrie)));

    registerRules<<<1,1>>>(d_trie);
    CHECK_CUDA_ERROR(cudaDeviceSynchronize());
    if(verbose) printf("RuleGraph Was Registered On Device\n");

    size_t counterPing;
    size_t counterPong;
    size_t packetSize;
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
    int result;

    cudaStream_t pingStream;
    cudaStream_t pongStream;

    cudaStreamCreate(&pingStream);
    cudaStreamCreate(&pongStream);

    float durationPing, durationPong;
    GPUTimer timerPing(pingStream);
    GPUTimer timerPong(pongStream);

    while (1) {
        if(verbose) printf(">> Chunk %d Started\n", chunkCounter+1);
        //ping

        int result = readPacketChunk(h_packets_ping, handle, &counterPing, &packetSize);
        if(result < 0 && result != -2 && verbose) {
            printf("Something went wrong in reading packets(%d)\n", result);
            printf("The Error was : %s\n", pcap_geterr(handle));
            printf("The counter was %d\n", counterPing);
        }

        totalCounter += counterPing;
        totalPacketSize += packetSize;

        //pong
        result = readPacketChunk(h_packets_pong, handle, &counterPong, &packetSize);
        if(result < 0 && result != -2 && verbose) {
            printf("Something went wrong in reading packets(%d)\n", result);
            printf("The Error was : %s\n", pcap_geterr(handle));
            printf("The counter was %d\n", counterPong);
        }

        totalCounter += counterPong;
        totalPacketSize += packetSize;

        if(verbose) printf("%ld Packets Was Read From Pcap File\n", counterPing + counterPong);
        
        HDPacketSizePing = counterPing*sizeof(PacketBuffer);
        HDPacketSizePong = counterPong*sizeof(PacketBuffer);

        timerPing.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packets_ping, (void*) h_packets_ping, HDPacketSizePing, cudaMemcpyHostToDevice, pingStream));
        timerPing.end();
        durationPing = timerPing.elapsed();
        totalHDDuration += durationPing;


        timerPong.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packets_pong, (void*) h_packets_pong, HDPacketSizePong, cudaMemcpyHostToDevice, pongStream));
        timerPong.end();
        durationPong = timerPong.elapsed();
        totalHDDuration += durationPong;


        totalHDPacketSize += HDPacketSizePing + HDPacketSizePong;

        if(verbose) printf(">> %ld Packets (%lf GB) Transfered From Host To Device \n", counterPing + counterPong, ((counterPing + counterPong)*sizeof(PacketBuffer))/(_GB_));
        if(verbose) printf("\t| DurationPing : %lf ms\n", durationPing);
        if(verbose) printf("\t| DurationPong : %lf ms\n", durationPong);
        if(verbose) printf("\t| BandwidthPing : %lf Gb/s\n", ((counterPing)*sizeof(PacketBuffer)*1000.0*8.0)/(_GB_*durationPing));
        if(verbose) printf("\t| BandwidthPong : %lf Gb/s\n", ((counterPong)*sizeof(PacketBuffer)*1000.0*8.0)/(_GB_*durationPong));

        
        int threadPerBlock = 256;
        
        timerPing.start();
        performProcess<<<((counterPing+threadPerBlock-1)/threadPerBlock), threadPerBlock, 0, pingStream>>>(d_packets_ping, counterPing, d_trie);
        timerPing.end();
        durationPing = timerPing.elapsed();
        totalKernelDuration += durationPing;


        timerPong.start();    
        performProcess<<<((counterPong+threadPerBlock-1)/threadPerBlock), threadPerBlock, 0, pongStream>>>(d_packets_pong, counterPong, d_trie);
        timerPong.end();
        durationPong = timerPong.elapsed();
        totalKernelDuration += durationPong;

        if(verbose) printf(">> RuleGraph Was Processed For %d Threads Per Block \n", threadPerBlock);
        if(verbose) printf(">> %ld Packets (%.3lf GB) Processed On GPU \n", counterPing + counterPong, (sizeof(HeaderBuffer)*(counterPing + counterPong)*1.0)/(_GB_));
        if(verbose) printf("\t| DurationPing : %lf ms\n", durationPing);
        if(verbose) printf("\t| DurationPong : %lf ms\n", durationPong);
        if(verbose) printf("\t| BandwidthPing : %lf Gb/s\n", (sizeof(HeaderBuffer)*(counterPing)*1000.0*8.0)/(_GB_*durationPing));
        if(verbose) printf("\t| BandwidthPong : %lf Gb/s\n", (sizeof(HeaderBuffer)*(counterPong)*1000.0*8.0)/(_GB_*durationPong));

        DHPacketSizePing = counterPing * sizeof(PacketBuffer);
        DHPacketSizePong = counterPong * sizeof(PacketBuffer);

        timerPing.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packets_ping, (void*) d_packets_ping, DHPacketSizePing, cudaMemcpyDeviceToHost, pingStream));
        timerPing.end();
        durationPing = timerPing.elapsed();
        totalDHDuration += durationPing;

        timerPong.start();
        CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packets_pong, (void*) d_packets_pong, DHPacketSizePong, cudaMemcpyDeviceToHost, pongStream));
        timerPong.end();
        durationPong = timerPong.elapsed();
        totalDHDuration += durationPong;

        if(verbose) printf(">> %ld Packets (%lf GB) Transfered From Device to Host\n", (counterPing + counterPong), ((counterPing + counterPong)*sizeof(PacketBuffer))/(_GB_));
        if(verbose) printf("\t| DurationPing : %lf ms\n", durationPing);
        if(verbose) printf("\t| DurationPong : %lf ms\n", durationPong);
        if(verbose) printf("\t| BandwidthPing : %lf Gb/s\n", ((counterPing)*sizeof(PacketBuffer)*1000.0*8.0)/(_GB_*durationPing));
        if(verbose) printf("\t| BandwidthPong : %lf Gb/s\n", ((counterPong)*sizeof(PacketBuffer)*1000.0*8.0)/(_GB_*durationPong));

        cudaStreamSynchronize(pingStream);
        cudaStreamSynchronize(pongStream);

        for(size_t i = 0 ; i < counterPing ; i++) {  
            ruleCount[h_packets_ping[i].ruleId]++;
            if(h_packets_ping[i].ruleId == Rule_EthrIpv4TcpHttp) fprintf(fd ,"%d\n", i+1);
        }

        for(size_t i = 0 ; i < counterPong ; i++) {  
            ruleCount[h_packets_pong[i].ruleId]++;
            if(h_packets_ping[i].ruleId == Rule_EthrIpv4TcpHttp) fprintf(fd ,"%d\n", i+1);
        }

        if(!verbose){
            printf("\033[2K\r");
            fflush(stdout);

            printf("# %0.3lf% Of %s Is Procesed", ((totalPacketSize*1.0)/(pcapFileSize*1.0))*100, pcapFilePath);
            fflush(stdout);
        }

        if (result == -2) {
            break;
        }

        chunkCounter++;
        if(verbose) printf("---------------------------------------------------------------\n\n");
    }


    if(!verbose){
        printf("\033[2K\r");
        fflush(stdout);

        printf("# 100%% Of %s Is Procesed\n", pcapFilePath);
        fflush(stdout);
    }

    pcap_close(handle);
    fclose(fd);

    printf("\t| Total Packets: %ld\n", totalCounter);

    for(size_t i = 0 ; i < Rule_Count ; i++)
        if(ruleCount[i] != 0) printf("\t| %s : %d\n", getRuleName(i), ruleCount[i]);

    printf(">> Host To Device:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n", totalHDDuration, (sizeof(HeaderBuffer)*totalCounter*8*1000.0)/(totalHDDuration*_GB_));
    printf(">> Kernel:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n", totalKernelDuration, (sizeof(HeaderBuffer)*totalCounter*8*1000.0)/(totalKernelDuration*_GB_));
    printf(">> Device To Host:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\n", totalDHDuration, (sizeof(HeaderBuffer)*totalCounter*8*1000.0)/(totalDHDuration*_GB_));
    printf("**********************************************************************************************\n\n");
    
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

#define HLEP_COMMAND_LINE       "Usage: ./ruleGraph [options] <arguments>\nAvailable Options:\n\t-f\t\t: Select The Pcap File\n\t-d\t\t: Select The Directory Containing Multiple Pcap Files\n\t-v\t\t: Make The Operation More Talkative\n\t-h\t\t: Print Help And Exit\n" 

int main(int argc, char* argv[]) {
    if(argc == 1)
    {
        printf(HLEP_COMMAND_LINE);
        return -1;
    }

    int opt, xfnd;
    xfnd = 0;
    bool processDir = false;
    bool processFile = false;
    bool verbose = false;
    char* pstr = NULL;

    while((opt = getopt(argc, argv, "d:f:hv")) != -1) {
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

        case 'h':   
            printf(HLEP_COMMAND_LINE);
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

    if(processDir) 
        return processDirectory(pstr, verbose);

    if(processFile)
        return processPcapFile(pstr, verbose);

    return -1;
}