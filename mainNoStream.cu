// #include <cuda_runtime.h>
// #include <pcap.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <vector>
// #include <endian.h>
// #include <time.h>
// #include <unistd.h>
// #include <dirent.h>

// #include "rulesGraph.cuh"
// #include "header.h"
// #include "gputimer.cuh"
// #include "rules.cuh"

// #define CHECK_CUDA_ERROR(fun)                                                   \
// {                                                                               \
//     cudaError_t err = fun;                                                      \
//     if(err != cudaSuccess) {                                                    \
//         printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
//         return -1;                                                               \
//     }                                                                           \
// }

// #define __DEBUG_ENABLE      (1)
// #define __DEBUG_LOG(...)         {if(__DEBUG_ENABLE) {printf(__VA_ARGS__);}}

// #define swapEndian16(x)     ((uint16_t) (((x) >> 8) | ((x) << 8)))

// #if __BYTE_ORDER == __LITTLE_ENDIAN
//     #define htons(x) swapEndian16(x)
//     #define ntohs(x) swapEndian16(x)
// #else 
//     #define htons(x) x
//     #define ntohs(x) x
// #endif

// #define LOAD_UINT8(p)               (*((uint8_t*) (p)))
// #define LOAD_UINT16(p)              (uint16_t) (LOAD_UINT8(p)    | (LOAD_UINT8(p+1)    << 8))
// #define LOAD_UINT32(p)              (uint32_t) ((LOAD_UINT16(p)) | ((LOAD_UINT16(p+2)) << 16))

// #define ALIGN_ADDRESS(addr, struct, alignedAddr)                {                                                                                   \
//                                                                     size_t alignment = alignof(struct);                                             \
//                                                                     uintptr_t ptr = (uintptr_t) (addr);                                             \
//                                                                     void* alignedAddress = (void*) ((ptr + (alignment - 1)) & ~(alignment - 1)) ;   \
//                                                                     alignedAddr = (struct*) alignedAddress;                                         \
//                                                                 }   

// #define _GB_                (1024.0*1024.0*1024.0)             
// #define _MB_                (1024.0*1024.0)             
// #define _KB_                (1024.0)             

// #define HOST_RAM_SIZE       (60.0 * _GB_)    
// #define DEVICE_RAM_SIZE     (21.0 * _GB_)

// #define MIN(x, y)           ((x) < (y) ? (x) : (y))

// #define PACKETS_PER_THREAD                                  (1)                    
// #define PACKETS_PER_KERNEL                                  (64)                    // USED IN LOOP
// #define THREADS_PER_SM                                      (1536)                  // MAX THREADS IN SM
// #define SM_PER_GPU                                          (128)
// #define SIZE_OF_PACKET                                      (sizeof(HeaderBuffer))  // ~1K 
// #define PACKETS_PER_SM                                      (PACKETS_PER_THREAD * THREADS_PER_SM)
// #define PACKETS_SIZE_PER_SM                                 (PACKETS_PER_SM * SIZE_OF_PACKET)
// #define REGISTER_FILE_SIZE_PER_SM                           (256 * _KB_)
// #define PACKETS_LOCAL_SIZE_PER_SM                           (PACKETS_SIZE_PER_SM - REGISTER_FILE_SIZE_PER_SM)
// #define PACKETS_LOCAL_SIZE_PER_GPU                          (SM_PER_GPU * PACKETS_LOCAL_SIZE_PER_SM)

// #define PACKET_BUFFER_CHUNK_SIZE            (PACKETS_PER_SM * PACKETS_PER_KERNEL * SM_PER_GPU)

// #define RULE_TRIE_SIZE                      (sizeof(RuleTrie))
// #define PACKETS_INFO_SIZE                   (PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketInfo))
// #define PACKETS_METADATA_SIZE               (PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketMetadata))
// #define PACKETS_MEMPOOL_SIZE                (MIN(DEVICE_RAM_SIZE, HOST_RAM_SIZE) - (PACKETS_METADATA_SIZE + RULE_TRIE_SIZE + PACKETS_LOCAL_SIZE_PER_GPU))
// // #define PACKETS_MEMPOOL_SIZE                (1 * _GB_)


// __global__ void performProcess(PacketMetadata* packetsMetadata, uint8_t* packetsMempool, size_t packetCount, RuleTrie* trie) {
//     int idx = blockIdx.x * blockDim.x + threadIdx.x;
//     int index;
//     HeaderBuffer h;

//     idx *= PACKETS_PER_KERNEL;
//     for(int i = 0 ; i < PACKETS_PER_KERNEL ; i++)  {                            // unroll
//         index = idx+i;

//         if (index >= packetCount) return;
//         resetHeaderBuffer(h);

//         PacketMetadata md = packetsMetadata[index];     
//         PacketInfo* info;

//         ALIGN_ADDRESS(packetsMempool+md.packetOffset, PacketInfo, info);
//         memcpy(h.headerData, packetsMempool + (md.packetOffset + sizeof(PacketInfo)), HEADER_BUFFER_DATA_MAX_SIZE * sizeof(uint8_t));

//         h.packetLen = md.packetLen;
//         trie->processTrie(&h);
//         info->ruleId = h.ruleId;
//     }
// }


// static int readPacketChunk(PacketMetadata* packetsMetadata, uint8_t* packetsMempool ,pcap_t* handle, size_t* counter, size_t* packetSize) {
//     *counter = 0;
//     size_t packetOffset = 0;
//     int result;
//     const u_char *packet;
//     struct pcap_pkthdr *header;

//     while((*counter < PACKET_BUFFER_CHUNK_SIZE)) {

//         if(((result = (pcap_next_ex(handle, &header, &packet))) < 0)) break;

//         PacketMetadata md = {.packetOffset = packetOffset, .packetLen = header->caplen};
//         packetsMetadata[*counter] = md;

//         if(md.packetOffset+md.packetLen+sizeof(PacketInfo) >= PACKETS_MEMPOOL_SIZE) break;
//         memcpy(packetsMempool+md.packetOffset+sizeof(PacketInfo), packet, md.packetLen);

//         *counter += 1;
//         packetOffset += md.packetLen+sizeof(PacketInfo);
//     }

//     *packetSize = packetOffset;
//     return result;
// }   

// static bool hasPcapExtension(const char* filename) {
//     const char* ext = strrchr(filename, '.');
//     if(ext != NULL && strcmp(ext, ".pcap") == 0) 
//         return true;
//     return false;
// }

// static pcap_t* openPcapFile(const char* pcapFilePath) {
//     char errBuf[PCAP_ERRBUF_SIZE];
//     pcap_t* handle = (pcap_t*) malloc(sizeof(pcap_t*));
    
//     handle = pcap_open_offline(pcapFilePath, errBuf);

//     return handle;
// } 

// static int processPcapFile(const char* pcapFilePath, bool verbose) {
//     pcap_t* handle;

//     if(!hasPcapExtension(pcapFilePath)) 
//     {
//         printf("Invalid Extension, Excepted .pcap\n");
//         return -1;
//     }

//     handle = openPcapFile(pcapFilePath);
//     if(handle == NULL)
//     {
//         printf("Unable To Open Pcap File : %s\n", pcapFilePath);
//         return -1;
//     } 

//     if(verbose) printf("Pcap File %s Opened\n", pcapFilePath);
    
//     size_t pcapFileSize;
//     {
//         FILE* fd = fopen(pcapFilePath, "r");


//         fseek(fd, 0, SEEK_END);
//         pcapFileSize = ftell(fd);
//         fseek(fd, 0, SEEK_SET);

//         fclose(fd);
//     }  

//     FILE* fd = fopen("arp_results.txt", "w");

//     PacketMetadata* h_packetsMetadata;
//     PacketMetadata* d_packetsMetadata;

//     uint8_t* d_packetsMemPool;
//     uint8_t* h_packetsMemPool;

//     // h_packetsMetadata = (PacketMetadata*) malloc(PACKETS_METADATA_SIZE);
//     // h_packetsMemPool = (uint8_t*) malloc(PACKETS_MEMPOOL_SIZE);

//     CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMetadata, PACKETS_METADATA_SIZE, cudaHostAllocDefault));
//     CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMemPool, PACKETS_MEMPOOL_SIZE, cudaHostAllocDefault));

//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMetadata, PACKETS_METADATA_SIZE));
//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMemPool, PACKETS_MEMPOOL_SIZE));

//     if(h_packetsMetadata == NULL || h_packetsMemPool == NULL) {
//         printf("Unable to allocate Mempool and Metadata\n");
//         return -1;
//     }


//     CHECK_CUDA_ERROR(cudaThreadSetLimit(cudaLimitStackSize, 10*1024));

//     RuleTrie* d_trie;
//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_trie, RULE_TRIE_SIZE*10));

//     registerRules<<<1,1>>>(d_trie);
//     CHECK_CUDA_ERROR(cudaDeviceSynchronize());
//     if(verbose) printf("RuleGraph Was Registered On Device\n");

//     size_t stackSize;
//     CHECK_CUDA_ERROR(cudaThreadGetLimit(&stackSize, cudaLimitStackSize));

//     size_t counter;

//     size_t counterPing;
//     size_t counterPong;
//     size_t packetSize;
//     size_t HDPacketSizePing;
//     size_t HDPacketSizePong;
//     size_t DHPacketSizePing;
//     size_t DHPacketSizePong;
//     size_t chunkCounter = 0;

//     size_t totalCounter = 0;
//     size_t totalPacketSize = 0;
//     size_t totalHDPacketSize = 0;
//     size_t totalDHPacketSize = 0;

//     double totalHDDuration = 0;
//     double totalDHDuration = 0;
//     double totalKernelDuration = 0;

//     int ruleCount[Rule_Count] = {0};
//     int result;

//     // cudaStream_t pingStream;
//     // cudaStream_t pongStream;

//     // cudaStreamCreate(&pingStream);
//     // cudaStreamCreate(&pongStream);

//     float durationChunk;
//     GPUTimer timerChunk(0);
//     double totalDuration = 0;

//     float durationDH;
//     GPUTimer timerDH(0);

//     float durationHD;
//     GPUTimer timerHD(0);

//     float durationKernel;
//     GPUTimer timerKernel(0);

//     while (1) {

//         //ping
//         int result = readPacketChunk(h_packetsMetadata, h_packetsMemPool, handle, &counter, &packetSize);
//         if(result < 0 && result != -2 && verbose) {
//             printf("Something went wrong in reading packets(%d)\n", result);
//             printf("The Error was : %s\n", pcap_geterr(handle));
//             printf("The counter was %d\n", counterPing);
//         }

//         if(result == -1) 
//             break;

//         if(verbose) printf(">> Chunk %d Started\n", chunkCounter+1);

//         totalCounter += counter;
//         totalPacketSize += packetSize;

//         if(verbose) printf("%ld Packets Was Read From Pcap File\n", counter);

//         timerChunk.start();

//         timerHD.start();
//         CHECK_CUDA_ERROR(cudaMemcpy((void*) d_packetsMemPool, (void*) h_packetsMemPool, packetSize, cudaMemcpyHostToDevice));
//         CHECK_CUDA_ERROR(cudaMemcpy((void*) d_packetsMetadata, (void*) h_packetsMetadata, counter * sizeof(PacketMetadata), cudaMemcpyHostToDevice));
//         timerHD.end();
//         durationHD = timerHD.elapsed();
//         totalHDDuration += durationHD;

//         totalHDPacketSize += packetSize + counter * sizeof(PacketMetadata);

//         if(verbose) printf(">> %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Host To Device \n", counter, (packetSize)/(_GB_), (counter * sizeof(PacketMetadata)) / (_GB_));
//         if(verbose) printf("\t| DurationHD : %lf ms\n", durationHD);
//         if(verbose) printf("\t| BandwidthHD : %lf Gb/s\n", ((packetSize + counter * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationHD));

        
//         int threadPerBlock = 256;
        
//         timerKernel.start();
//         performProcess<<<(((counter+PACKETS_PER_KERNEL-1)/PACKETS_PER_KERNEL+threadPerBlock-1)/threadPerBlock), threadPerBlock>>>(d_packetsMetadata, d_packetsMemPool, counter, d_trie);
//         timerKernel.end();
//         durationKernel = timerKernel.elapsed();
//         totalKernelDuration += durationKernel;
                

//         // timerPong.start();    
//         // performProcess<<<((counterPong+threadPerBlock-1)/threadPerBlock), threadPerBlock, 0, pongStream>>>(d_packets_pong, counterPong, d_trie);
//         // timerPong.end();
//         // durationPong = timerPong.elapsed();
//         // totalKernelDuration += durationPong;

//         if(verbose) printf(">> RuleGraph Was Processed For %d Threads Per Block each block Processing %d packets\n", threadPerBlock, PACKETS_PER_KERNEL);
//         if(verbose) printf(">> %ld Packets (%.3lf GB) Processed On GPU \n", counter, ((packetSize) * 1.0)/(_GB_));
//         if(verbose) printf("\t| DurationKernel : %lf ms\n", durationKernel);
//         if(verbose) printf("\t| BandwidthKernel : %lf Gb/s\n", ((packetSize) * 1000.0 * 8.0)/(_GB_*durationKernel));

//         // DHPacketSizePing = counterPing * sizeof(PacketBuffer);
//         // DHPacketSizePong = counterPong * sizeof(PacketBuffer);

//         timerDH.start();
//         CHECK_CUDA_ERROR(cudaMemcpy((void*) h_packetsMetadata, (void*) d_packetsMetadata, counter * sizeof(PacketMetadata), cudaMemcpyDeviceToHost));
//         CHECK_CUDA_ERROR(cudaMemcpy((void*) h_packetsMemPool, (void*) d_packetsMemPool, packetSize, cudaMemcpyDeviceToHost));
//         timerDH.end();
//         durationDH = timerDH.elapsed();
//         totalDHDuration += durationDH;

//         totalDHPacketSize += packetSize + counter * sizeof(PacketMetadata);

//         timerChunk.end();
//         durationChunk = timerChunk.elapsed();
//         totalDuration += durationChunk;

//         if(verbose) printf(">> %ld Packets (%lf GB Mempool and %lf GB Mem) Transfered From Device to Host\n", counter, (packetSize)/(_GB_), (counter * sizeof(PacketMetadata)) / (_GB_));
//         if(verbose) printf("\t| DurationDH : %lf ms\n", durationDH);
//         if(verbose) printf("\t| BandwidthDH : %lf Gb/s\n", ((packetSize + counter * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationDH));
//         if(verbose) printf("********************************************************************************************************\n\n");

//         // cudaStreamSynchronize(pingStream);
//         // cudaStreamSynchronize(pongStream);


//         for(size_t i = 0 ; i < counter ; i++) {  
//             PacketMetadata md = h_packetsMetadata[i];
//             PacketInfo* info;

//             ALIGN_ADDRESS(h_packetsMemPool+md.packetOffset, PacketInfo, info);



//             ruleCount[info->ruleId]++;

//             if(info->ruleId == Rule_EthrIPv4Icmp) fprintf(fd ,"%d\n", i+1);
//         }

//         // for(size_t i = 0 ; i < counterPong ; i++) {  
//         //     ruleCount[h_packets_pong[i].ruleId]++;
//         //     if(h_packets_ping[i].ruleId == Rule_EthrIpv4TcpHttp) fprintf(fd ,"%d\n", i+1);
//         // }

//         if(!verbose){
//             printf("\033[2K\r");
//             fflush(stdout);

//             printf("# %0.3lf% Of %s Is Procesed", ((totalPacketSize*1.0)/(pcapFileSize*1.0))*100, pcapFilePath);
//             fflush(stdout);
//         }

//         if (result == -2) {
//             break;
//         }

//         chunkCounter++;
//         if(verbose) printf("---------------------------------------------------------------\n\n");
//     }


//     if(!verbose){
//         printf("\033[2K\r");
//         fflush(stdout);

//         printf("# 100%% Of %s Is Procesed\n", pcapFilePath);
//         fflush(stdout);
//     }

//     pcap_close(handle);
//     fclose(fd);

//     printf("\t| Total Packets: %ld\n", totalCounter);

//     for(size_t i = 0 ; i < Rule_Count ; i++)
//         if(ruleCount[i] != 0) printf("\t| %s : %d\n", getRuleName(i), ruleCount[i]);
//     printf("**********************************************************************************************\n\n");

    
//     printf(">> Host To Device:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n", totalHDDuration, ((totalHDPacketSize) * 8 * 1000.0)/(totalHDDuration*_GB_));
//     printf(">> Kernel:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n", totalKernelDuration, (totalPacketSize * 8 * 1000.0)/(totalKernelDuration*_GB_));
//     printf(">> Device To Host:\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\n", totalDHDuration, ((totalDHPacketSize) * 8 * 1000.0)/(totalDHDuration*_GB_));
//     printf(">> Total: \n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\n", totalDuration, (totalHDPacketSize * 8.0 * 1000.0) / (totalDuration * _GB_));
//     printf("**********************************************************************************************\n\n");
    
//     return 0;
// }


// static int processDirectory(const char* directoryPath, bool verbose) {
//     struct dirent* entry;
//     DIR* dp;

//     dp = opendir(directoryPath);
//     if(dp == NULL) {
//         printf("Unable To Open Directory %s\n", directoryPath);
//         return -1;
//     }

//     while((entry = readdir(dp)) != NULL) {
//         if(entry->d_type == DT_REG && hasPcapExtension(entry->d_name)) {
//             char fullPath[1024];
//             snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, entry->d_name);            
//             processPcapFile(fullPath, verbose);
//         }
//     }

//     closedir(dp);
// }

// #define HLEP_COMMAND_LINE       "Usage: ./ruleGraph [options] <arguments>\nAvailable Options:\n\t-f\t\t: Select The Pcap File\n\t-d\t\t: Select The Directory Containing Multiple Pcap Files\n\t-v\t\t: Make The Operation More Talkative\n\t-h\t\t: Print Help And Exit\n" 

// int main(int argc, char* argv[]) {
//     if(argc == 1)
//     {
//         printf(HLEP_COMMAND_LINE);
//         return -1;
//     }

//     int opt, xfnd;
//     xfnd = 0;
//     bool processDir = false;
//     bool processFile = false;
//     bool verbose = false;
//     char* pstr = NULL;

//     while((opt = getopt(argc, argv, "d:f:hv")) != -1) {
//         switch (opt)
//         {
//         case 'd':
//             processDir = true;
//             pstr = optarg;
//             break;

//         case 'f':
//             processFile = true;
//             pstr = optarg;
//             break;

//         case 'h':   
//             printf(HLEP_COMMAND_LINE);
//             return 0;

//         case 'v':
//             verbose = true;
//             break;

//         case ':':
//             printf("Option -$c requires an argument\n", optopt);
//             return -1;

//         case '?':
//             printf("Unknown Option: -%c\n", optopt);
//             return -1;
//         }
//     }

//     if(processDir) 
//         return processDirectory(pstr, verbose);

//     if(processFile)
//         return processPcapFile(pstr, verbose);

//     return -1;
// }