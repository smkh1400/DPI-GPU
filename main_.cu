#include <cuda_runtime.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

#include "rulesGraph.cuh"
#include "streamWorker.cu"
#include "config/config.h"
#include "rules.cuh"
#include "gputimer.cuh"

#define PACKETS_MEMPOOL_SIZE        (10*_GB_)

#define CHECK_CUDA_ERROR(fun)                                                   \
{                                                                               \
    cudaError_t err = fun;                                                      \
    if(err != cudaSuccess) {                                                    \
        printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
        return -1;                                                               \
    }                                                                           \
}

static inline bool hasPcapExtension(const char* filename) {
    const char* ext = strrchr(filename, '.');
    return (ext != NULL) && (strcmp(ext, ".pcap") == 0);
}

static inline pcap_t* openPcapFile(const char* pcapFilePath) {
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

    if ((result = (pcap_next_ex(handle, &header, &packet))) < 0) return (int) result;
    double firstTime = (double) header->ts.tv_sec + (double) ((header->ts.tv_usec*1.0) / 1e6f);

    pcap_close(handle);

    return firstTime;
}

static int processPcapFile(const char* pcapFilePath, bool verbose) {
    

    if(!hasPcapExtension(pcapFilePath)) {
        printf("Invalid Extension, Excepted .pcap\n");
        return -1;
    }

    pcap_t* handle;
    handle = openPcapFile(pcapFilePath);

    if(handle == NULL) {
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

    StreamWorker pingStream("PING", COLOR_RED);
    StreamWorker pongStream("PONG", COLOR_GREEN);
    StreamWorker pangStream("PANG", COLOR_BLUE);

    MempoolInfo_t pingMemInfo = {.packetsCount = 0, .packetsSize = 0};
    MempoolInfo_t pongMemInfo = {.packetsCount = 0, .packetsSize = 0};
    MempoolInfo_t pangMemInfo = {.packetsCount = 0, .packetsSize = 0};

    RuleTrie* trie;

    pingStream.allocateMemory(PACKETS_MEMPOOL_SIZE / 3, Configfields::chunkCountLimit / 3, verbose);
    pongStream.allocateMemory(PACKETS_MEMPOOL_SIZE / 3, Configfields::chunkCountLimit / 3, verbose);
    pangStream.allocateMemory(PACKETS_MEMPOOL_SIZE / 3, Configfields::chunkCountLimit / 3, verbose);

    // why we didn't increase the stack limit and why does it work???

    CHECK_CUDA_ERROR(cudaMalloc((void**) &trie, sizeof(RuleTrie)));
    registerRules<<<1,1>>>(trie);
    CHECK_CUDA_ERROR(cudaDeviceSynchronize());
    if(verbose) printf(">> RuleTrie was registered on device\n");

    double startTime = findFirstTimeStamp(pcapFilePath);
    int result = 0;

    float durationChunk;
    GPUTimer timerChunk(0);
    double totalDuration = 0;

    size_t chunkCounter = 0;


    while(1) {

        if(verbose) printf("____________________________________________________________________\n\n");
        if(verbose) printf(">> Chunk %ld started\n", chunkCounter + 1);

        if(verbose) printf("___________________________READING PACKET___________________________\n");

        if (result != -2) {
            result = pingStream.readPacket(handle, pingMemInfo, &startTime, verbose);

            if (result == -1)
                break;
        } else {
            break;
        }

        if (result != -2) {
            result = pongStream.readPacket(handle, pongMemInfo, &startTime, verbose);

            if (result == -1)
                break;
        }

        if (result != -2) {
            result = pangStream.readPacket(handle, pangMemInfo, &startTime, verbose);

            if (result == -1)
                break;
        } 

        if(verbose) printf("___________________________HOST TO DEVICE___________________________\n");

        timerChunk.start();

        pingStream.performHD(pingMemInfo, verbose);
        pongStream.performHD(pongMemInfo, verbose);
        pangStream.performHD(pangMemInfo, verbose);

        if(verbose) printf("_______________________________KERNEL_______________________________\n");

        pingStream.performProcess(trie, pingMemInfo.packetsCount, pingMemInfo, verbose);
        pongStream.performProcess(trie, pongMemInfo.packetsCount, pongMemInfo, verbose);
        pangStream.performProcess(trie, pangMemInfo.packetsCount, pangMemInfo, verbose);

        if(verbose) printf("___________________________DEVICE TO HOST___________________________\n");

        pingStream.performDH(pingMemInfo, verbose);
        pongStream.performDH(pongMemInfo, verbose);
        pangStream.performDH(pangMemInfo, verbose);


        timerChunk.end();
        durationChunk = timerChunk.elapsed();
        totalDuration += durationChunk;

        if(verbose) printf("____________________________CHUNK REPORT____________________________\n");

        int chunkTotalCount = pingMemInfo.packetsCount + pongMemInfo.packetsCount + pangMemInfo.packetsCount;
        int chunkTotalSize = pingMemInfo.packetsSize + pongMemInfo.packetsSize + pangMemInfo.packetsSize;

        if(verbose) printf(">> %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered\n", (chunkTotalCount), (chunkTotalSize)/(_GB_), ((chunkTotalCount) * sizeof(PacketMetadata)) / (_GB_));
        if(verbose) printf("\t| DurationChunk : %lf ms\n", durationChunk);
        if(verbose) printf("\t| BandwidthChunk : %lf Gb/s\n\n", (((chunkTotalSize) + (chunkTotalCount) * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_ * durationChunk));
        
        if(verbose) printf("____________________________END OF CHUNK____________________________\n");

        pingStream.reportCounter(pingMemInfo);
        pongStream.reportCounter(pongMemInfo);
        pangStream.reportCounter(pangMemInfo);

        if(!verbose){
            printf("\033[2K\r");
            fflush(stdout);

            int totalPacketCount = pingStream.getReport().totalPacketCount + pongStream.getReport().totalPacketCount + pangStream.getReport().totalPacketCount;
            size_t totalPacketSize = pingStream.getReport().totalPacketSize + pongStream.getReport().totalPacketSize + pangStream.getReport().totalPacketSize;

            printf("# %0.3lf%% Of %s Is Processed", (((totalPacketCount * (16 - sizeof(PacketInfo)) + totalPacketSize) * 1.0)/(pcapFileSize * 1.0)) * 100, pcapFilePath);
            fflush(stdout);
        }

        chunkCounter++;
    }

    pcap_close(handle);
    
    pingStream.freeMempory(verbose);
    pongStream.freeMempory(verbose);
    pangStream.freeMempory(verbose);

    // printf("PING total counter: %ld\n", pingStream.getReport().totalPacketCount);

    size_t totalCounter = pingStream.getReport().totalPacketCount + pongStream.getReport().totalPacketCount + pangStream.getReport().totalPacketCount;
    size_t totalSize = pingStream.getReport().totalPacketSize + pongStream.getReport().totalPacketSize + pangStream.getReport().totalPacketSize;

    printf("\n>> Result:\n\t| Total Packets: %ld\n", totalCounter);
    for(size_t i = 0 ; i < Rule_Count ; i++)
        if(pingStream.getReport().totalRuleCount[i] + pongStream.getReport().totalRuleCount[i] + pangStream.getReport().totalRuleCount[i] != 0) 
           printf("\t| %s : %d\n", getRuleName(i), pingStream.getReport().totalRuleCount[i] + pongStream.getReport().totalRuleCount[i] + pangStream.getReport().totalRuleCount[i]);
    
    printf("\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\t| Bandwidth: %lf MPacket/s\n\t| Size: %lf Gb\n", 
        totalDuration, ((totalSize + totalCounter*sizeof(PacketInfo)) * 8.0 * 1000.0) / (totalDuration * _GB_), (totalCounter * 1000.0) / (totalDuration * _MB_)  ,(totalSize * 8.0)/(_GB_));    

    return 1;
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
    return 0;
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
            printf("Option -%c requires an argument\n", optopt);
            return -1;

        case '?':
            printf("Unknown Option: -%c\n", optopt);
            return -1;
        }
    }

    if (!haveConfigFileName) {
        configFilePath = "config.yml";  // default
    }

    ConfigLoader::loadAllfields(configFilePath);

    if(processDir) 
        return processDirectory(pstr, verbose);

    if(processFile)
        return processPcapFile(pstr, verbose);


    return -1;
}