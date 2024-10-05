// #include <cuda_runtime.h>
// #include <pcap.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <endian.h>
// #include <unistd.h>
// #include <dirent.h>

// #include "rulesGraph.cuh"
// #include "header.h"
// #include "gputimer.cuh"
// #include "rules.cuh"
// #include "config/config.h"
// // #include "streamWorker.cu"

// #define CHECK_CUDA_ERROR(fun)                                                   \
// {                                                                               \
//     cudaError_t err = fun;                                                      \
//     if(err != cudaSuccess) {                                                    \
//         printf("CUDA at %s:%d: %s\n", __FUNCTION__, __LINE__ , cudaGetErrorString(err));           \
//         return -1;                                                               \
//     }                                                                           \
// }

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

// #define DEFAULT_PACKET_BUFFER_CHUNK_SIZE    (196608*8)
// #define PACKET_BUFFER_CHUNK_SIZE            ((Configfields::chunkCountLimit != CONFIG_FIELD_INT_NOT_SET_VAL) ? Configfields::chunkCountLimit : DEFAULT_PACKET_BUFFER_CHUNK_SIZE)

// #define RULE_TRIE_SIZE                      (sizeof(RuleTrie))
// #define PACKETS_INFO_SIZE                   (PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketInfo))
// #define PACKETS_METADATA_SIZE               (PACKET_BUFFER_CHUNK_SIZE*sizeof(PacketMetadata))
// #define PACKETS_MEMPOOL_SIZE                (MIN(DEVICE_RAM_SIZE, HOST_RAM_SIZE) - (PACKETS_METADATA_SIZE + RULE_TRIE_SIZE))


// __global__ void performProcess(PacketMetadata* packetsMetadata, uint8_t* packetsMempool, size_t packetCount, RuleTrie* trie) {
//     int idx = blockIdx.x * blockDim.x + threadIdx.x;
//     if (idx >= packetCount) return;

//     PacketMetadata md;     
//     md = packetsMetadata[idx];     

//     HeaderBuffer h(packetsMempool + (md.packetOffset + sizeof(PacketInfo)), md.packetLen);

//     PacketInfo* info;
//     ALIGN_ADDRESS(packetsMempool+md.packetOffset, PacketInfo, info);

//     trie->processTrie(&h);
//     info->ruleId = h.ruleId;
// }

// static int readPacketOfflineMode(PacketMetadata* packetsMetadata, uint8_t* packetsMempool ,pcap_t* handle, size_t* counter, size_t* packetSize, double* startTime) {
//     size_t packetOffset = 0;
//     size_t packetCounter = 0;
//     int result;
//     static const u_char *packet;
//     static struct pcap_pkthdr *header;
//     double timeStamp;

//     do {
//         if(packet != NULL && header != NULL) {
//             // if(header->caplen != header->len)   continue;

//             timeStamp = (double)(header->ts.tv_sec) + (double)((header->ts.tv_usec*1.0) / 1e6f);

//             if((Configfields::chunkTimeLimit != CONFIG_FIELD_DOUBLE_NOT_SET_VAL) && (timeStamp - *startTime > Configfields::chunkTimeLimit / 2)) break;                                              // Time Limit

//             if((packetCounter >= PACKET_BUFFER_CHUNK_SIZE / 2)) break;                                                     // Count Limit
//             PacketMetadata md = {.packetOffset = packetOffset, .packetLen = header->caplen};
//             packetsMetadata[packetCounter] = md;

//             if(md.packetOffset+md.packetLen+sizeof(PacketInfo) >= PACKETS_MEMPOOL_SIZE / 2) break;                          // Mempool Limit
//             memcpy(packetsMempool+md.packetOffset+sizeof(PacketInfo), packet, md.packetLen);

//             packetCounter += 1;
//             packetOffset += md.packetLen+sizeof(PacketInfo);
//         }
//     }
//     while(((result = (pcap_next_ex(handle, &header, &packet))) >= 0));

//     *startTime = timeStamp;
//     *packetSize = packetOffset;
//     *counter = packetCounter;

//     return result;
// }

// static inline pcap_t* openPcapFile(const char* pcapFilePath) {
//     char errBuf[PCAP_ERRBUF_SIZE];
//     pcap_t* handle = (pcap_t*) malloc(sizeof(pcap_t*));
    
//     handle = pcap_open_offline(pcapFilePath, errBuf);

//     return handle;
// } 

// static double findFirstTimeStamp(const char* pcapFilePath) {
//     pcap_t* handle = openPcapFile(pcapFilePath);
//     struct pcap_pkthdr *header;
//     const u_char *packet;
//     int result;

//     if ((result = (pcap_next_ex(handle, &header, &packet))) < 0) return (int) result;
//     double firstTime = (double) header->ts.tv_sec + (double) ((header->ts.tv_usec*1.0) / 1e6f);

//     pcap_close(handle);

//     return firstTime;
// }

// static inline bool hasPcapExtension(const char* filename) {
//     const char* ext = strrchr(filename, '.');
//     return (ext != NULL) && (strcmp(ext, ".pcap") == 0);
// }

// static int processPcapFile(const char* pcapFilePath, bool verbose) {


//     if(!hasPcapExtension(pcapFilePath)) {
//         printf("Invalid Extension, Excepted .pcap\n");
//         return -1;
//     }

//     pcap_t* handle;
//     handle = openPcapFile(pcapFilePath);

//     if(handle == NULL) {
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


//     PacketMetadata* h_packetsMetadataPing;
//     PacketMetadata* h_packetsMetadataPong;
//     PacketMetadata* d_packetsMetadataPing;
//     PacketMetadata* d_packetsMetadataPong;

//     uint8_t* d_packetsMemPoolPing;
//     uint8_t* d_packetsMemPoolPong;
//     uint8_t* h_packetsMemPoolPing;
//     uint8_t* h_packetsMemPoolPong;

//     CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMetadataPing, PACKETS_METADATA_SIZE / 2, cudaHostAllocDefault));
//     CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMetadataPong, PACKETS_METADATA_SIZE / 2, cudaHostAllocDefault));
//     CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMemPoolPing, PACKETS_MEMPOOL_SIZE / 2, cudaHostAllocDefault));
//     CHECK_CUDA_ERROR(cudaHostAlloc((void**) &h_packetsMemPoolPong, PACKETS_MEMPOOL_SIZE / 2, cudaHostAllocDefault));

//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMetadataPing, PACKETS_METADATA_SIZE / 2));
//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMetadataPong, PACKETS_METADATA_SIZE / 2));
//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMemPoolPing, PACKETS_MEMPOOL_SIZE / 2));
//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_packetsMemPoolPong, PACKETS_MEMPOOL_SIZE / 2));

//     RuleTrie* d_trie;
//     CHECK_CUDA_ERROR(cudaMalloc((void**) &d_trie, RULE_TRIE_SIZE)); 
    

//     if(h_packetsMetadataPing == NULL || h_packetsMetadataPong == NULL || h_packetsMemPoolPing == NULL || h_packetsMemPoolPong == NULL) {
//         printf("Unable to allocate Mempool or Metadata\n");
//         return -1;
//     }

//     CHECK_CUDA_ERROR(cudaThreadSetLimit(cudaLimitStackSize, 10*1024));

//     registerRules<<<1,1>>>(d_trie);
//     CHECK_CUDA_ERROR(cudaDeviceSynchronize());
//     if(verbose) printf(">> RuleGraph Was Registered On Device\n");

//     StreamWorker pingStream_("PING");
//     StreamWorker pongStream_("PONG");
//     StreamWorker pangStream_("PANG");

//     pingStream_.allocateMemory(PACKETS_MEMPOOL_SIZE/3, PACKETS_METADATA_SIZE/3);
//     pongStream_.allocateMemory(PACKETS_MEMPOOL_SIZE/3, PACKETS_METADATA_SIZE/3);
//     pangStream_.allocateMemory(PACKETS_MEMPOOL_SIZE/3, PACKETS_METADATA_SIZE/3);
    
//     size_t counterPing;
//     size_t counterPong;
//     size_t packetSizePing;
//     size_t packetSizePong;
//     size_t chunkCounter = 0;

//     size_t totalCounter = 0;
//     size_t totalPacketSize = 0;
//     size_t totalHDPacketSize = 0;
//     size_t totalDHPacketSize = 0;

//     double totalHDDuration = 0;
//     double totalDHDuration = 0;
//     double totalKernelDuration = 0;

//     int ruleCount[Rule_Count] = {0};

//     cudaStream_t pingStream;
//     cudaStream_t pongStream;

//     CHECK_CUDA_ERROR(cudaStreamCreate(&pingStream));
//     CHECK_CUDA_ERROR(cudaStreamCreate(&pongStream));

//     float durationChunk;
//     GPUTimer timerChunk(0);
//     double totalDuration = 0;

//     float durationDHPing;
//     GPUTimer timerDHPing(pingStream);

//     float durationDHPong;
//     GPUTimer timerDHPong(pongStream);

//     float durationHDPing;
//     GPUTimer timerHDPing(pingStream);

//     float durationHDPong;
//     GPUTimer timerHDPong(pongStream);

//     float durationKernelPing;
//     GPUTimer timerKernelPing(pingStream);

//     float durationKernelPong;
//     GPUTimer timerKernelPong(pongStream);

//     double startTime = findFirstTimeStamp(pcapFilePath);
//     int result = 0;


//     while (1) {

//         if(verbose) printf(">> Chunk %ld Started\n", chunkCounter+1);

//         if(result != -2)
//         {
//             //ping
//             if (Configfields::readPacketMode.compare("offline") == 0)                // TODO 
//                 result = readPacketOfflineMode(h_packetsMetadataPing, h_packetsMemPoolPing, handle, &counterPing, &packetSizePing, &startTime);
//             else {
//                 printf("Invalid Read Mode in Config file\n");
//                 return -1;
//             }

//             if(result < 0 && result != -2 && verbose) {
//                 printf("Something went wrong in reading packets(%d)\n", result);
//                 printf("The Error was : %s\n", pcap_geterr(handle));
//                 printf("The counter was %ld\n", counterPing);
//             }

//             if(result == -1) 
//                 break;

//             totalCounter += counterPing;
//             totalPacketSize += packetSizePing;

//             if(verbose) printf("[PING] - %ld Packets Read From Pcap File\n", counterPing);
//         } else {
//             counterPing = 0;
//             packetSizePing = 0;

//             if(verbose) printf("[PING] - End Of Pcap File\n");

//             break;
//         } 

//         //pong
//         if(result != -2) {

//             if (Configfields::readPacketMode.compare("offline") == 0)                // TODO 
//                 result = readPacketOfflineMode(h_packetsMetadataPong, h_packetsMemPoolPong, handle, &counterPong, &packetSizePong, &startTime);
            
//             if(result < 0 && result != -2 && verbose) {
//                 printf("Something went wrong in reading packets(%d)\n", result);
//                 printf("The Error was : %s\n", pcap_geterr(handle));
//                 printf("The counter was %ld\n", counterPong);
//             }

//             if(result == -1) 
//                 break;

//             totalCounter += counterPong;
//             totalPacketSize += packetSizePong;

//             if(verbose) printf("[PONG] - %ld Packets Read From Pcap File\n", counterPing);
//         } else {
//             counterPong = 0;
//             packetSizePong = 0;

//             if(verbose) printf("[PONG] - End Of Pcap File\n");
//         }

//         timerChunk.start();

//         if (Configfields::isTimerSet) timerHDPing.start();
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMemPoolPing, (void*) h_packetsMemPoolPing, packetSizePing, cudaMemcpyHostToDevice, pingStream));
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMetadataPing, (void*) h_packetsMetadataPing, counterPing * sizeof(PacketMetadata), cudaMemcpyHostToDevice, pingStream));
//         if (Configfields::isTimerSet) timerHDPing.end();
//         if (Configfields::isTimerSet) durationHDPing = timerHDPing.elapsed();
//         if (Configfields::isTimerSet) totalHDDuration += durationHDPing;

//         if(verbose) printf("[PING] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Host To Device \n", (counterPing), (packetSizePing)/(_GB_), (counterPing * sizeof(PacketMetadata)) / (_GB_));
//         if(verbose && Configfields::isTimerSet) printf("[PING]\t| DurationHDPing : %lf ms\n", durationHDPing);
//         if(verbose && Configfields::isTimerSet) printf("[PING]\t| BandwidthHDPing : %lf Gb/s\n", ((packetSizePing + counterPing * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationHDPing));

//         if (Configfields::isTimerSet) timerHDPong.start();
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMemPoolPong, (void*) h_packetsMemPoolPong, packetSizePong, cudaMemcpyHostToDevice, pongStream));
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) d_packetsMetadataPong, (void*) h_packetsMetadataPong, counterPong * sizeof(PacketMetadata), cudaMemcpyHostToDevice, pongStream));
//         if (Configfields::isTimerSet) timerHDPong.end();
//         if (Configfields::isTimerSet) durationHDPong = timerHDPong.elapsed();
//         if (Configfields::isTimerSet) totalHDDuration += durationHDPong;

//         if(verbose) printf("[PONG] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Host To Device \n", (counterPong), (packetSizePong)/(_GB_), (counterPong * sizeof(PacketMetadata)) / (_GB_));
//         if(verbose && Configfields::isTimerSet) printf("[PONG]\t| DurationHDPong : %lf ms\n", durationHDPong);
//         if(verbose && Configfields::isTimerSet) printf("[PONG]\t| BandwidthHDPong : %lf Gb/s\n", ((packetSizePong + counterPong * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationHDPong));
        
//         if(verbose) printf("______________________________________________________________________\n");

//         totalHDPacketSize += packetSizePing + packetSizePong + (counterPing + counterPong) * sizeof(PacketMetadata);

//         /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
//         int threadPerBlock = Configfields::threadPerBlock;
        
//         if (Configfields::isTimerSet) timerKernelPing.start();
//         performProcess<<<((counterPing + threadPerBlock - 1)/threadPerBlock), threadPerBlock, 0, pingStream>>>(d_packetsMetadataPing, d_packetsMemPoolPing, counterPing, d_trie);
//         if (Configfields::isTimerSet) timerKernelPing.end();
//         if (Configfields::isTimerSet) durationKernelPing = timerKernelPing.elapsed();
//         if (Configfields::isTimerSet) totalKernelDuration += durationKernelPing;
                
//         if(verbose) printf("[PING] -  RuleGraph Was Processed For %d Threads Per Block\n", threadPerBlock);
//         if(verbose) printf("[PING] - %ld Packets (%.3lf GB) Processed On GPU\n", counterPing, ((packetSizePing) * 1.0)/(_GB_));
//         if(verbose  && Configfields::isTimerSet) printf("[PING]\t| DurationKernelPing : %lf ms\n", durationKernelPing);
//         if(verbose  && Configfields::isTimerSet) printf("[PING]\t| BandwidthKernelPing : %lf Gb/s\n", ((packetSizePing) * 1000.0 * 8.0)/(_GB_*durationKernelPing));

//         if (Configfields::isTimerSet) timerKernelPong.start();
//         performProcess<<<((counterPong + threadPerBlock - 1)/threadPerBlock), threadPerBlock, 0, pongStream>>>(d_packetsMetadataPong, d_packetsMemPoolPong, counterPong, d_trie);
//         if (Configfields::isTimerSet) timerKernelPong.end();
//         if (Configfields::isTimerSet) durationKernelPong = timerKernelPong.elapsed();
//         if (Configfields::isTimerSet) totalKernelDuration += durationKernelPong;

//         if(verbose) printf("[PONG] - RuleGraph Was Processed For %d Threads Per Block\n", threadPerBlock);
//         if(verbose) printf("[PONG] - %ld Packets (%.3lf GB) Processed On GPU \n", counterPong, ((packetSizePong) * 1.0)/(_GB_));
//         if(verbose  && Configfields::isTimerSet) printf("[PONG]\t| DurationKernelPong : %lf ms\n", durationKernelPong);
//         if(verbose  && Configfields::isTimerSet) printf("[PONG]\t| BandwidthKernelPong : %lf Gb/s\n", ((packetSizePong) * 1000.0 * 8.0)/(_GB_*durationKernelPong));

//         if(verbose) printf("______________________________________________________________________\n");

//         ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//         if (Configfields::isTimerSet) timerDHPing.start();
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMetadataPing, (void*) d_packetsMetadataPing, counterPing * sizeof(PacketMetadata), cudaMemcpyDeviceToHost, pingStream));
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMemPoolPing, (void*) d_packetsMemPoolPing, packetSizePing, cudaMemcpyDeviceToHost, pingStream));
//         if (Configfields::isTimerSet) timerDHPing.end();
//         if (Configfields::isTimerSet) durationDHPing = timerDHPing.elapsed();
//         if (Configfields::isTimerSet) totalDHDuration += durationDHPing;

//         if(verbose) printf("[PING] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Device to Host\n", (counterPing), (packetSizePing)/(_GB_), (counterPing * sizeof(PacketMetadata)) / (_GB_));
//         // if(verbose && Configfields::isTimerSet) printf("[PING]\t| DurationDHPing : %lf ms\n", durationDHPing);
//         if(verbose && Configfields::isTimerSet) printf("[PING]\t| BandwidthDHPing : %lf Gb/s\n", ((packetSizePing + counterPing * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationDHPing));

//         if (Configfields::isTimerSet) timerDHPong.start();
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMetadataPong, (void*) d_packetsMetadataPong, counterPong * sizeof(PacketMetadata), cudaMemcpyDeviceToHost, pongStream));
//         CHECK_CUDA_ERROR(cudaMemcpyAsync((void*) h_packetsMemPoolPong, (void*) d_packetsMemPoolPong, packetSizePong, cudaMemcpyDeviceToHost, pongStream));
//         if (Configfields::isTimerSet) timerDHPong.end();
//         if (Configfields::isTimerSet) durationDHPong = timerDHPong.elapsed();
//         if (Configfields::isTimerSet) totalDHDuration += durationDHPong;

//         if(verbose) printf("[PONG] - %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered From Device to Host\n", (counterPong), (packetSizePong)/(_GB_), (counterPong * sizeof(PacketMetadata)) / (_GB_));
//         if(verbose && Configfields::isTimerSet) printf("[PONG]\t| DurationDHPong : %lf ms\n", durationDHPong);
//         if(verbose && Configfields::isTimerSet) printf("[PONG]\t| BandwidthDHPong : %lf Gb/s\n", ((packetSizePong + counterPong * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_*durationDHPong));

//         if(verbose) printf("______________________________________________________________________\n");

//         totalDHPacketSize += (packetSizePing + packetSizePong) + (counterPing + counterPong) * sizeof(PacketMetadata);

//         timerChunk.end();
//         durationChunk = timerChunk.elapsed();
//         totalDuration += durationChunk;

//         if(verbose) printf(">> %ld Packets (%lf GB Mempool and %lf GB Metadata) Transfered\n", (counterPing + counterPong), (packetSizePing + packetSizePong)/(_GB_), ((counterPing + counterPong) * sizeof(PacketMetadata)) / (_GB_));
//         if(verbose) printf("\t| DurationChunk : %lf ms\n", durationChunk);
//         if(verbose) printf("\t| BandwidthChunk : %lf Gb/s\n", (((packetSizePing + packetSizePong) + (counterPing + counterPong) * sizeof(PacketMetadata)) * 1000.0 * 8.0)/(_GB_ * durationChunk));
//         if(verbose) printf("########################################################################\n\n");

//         cudaStreamSynchronize(pingStream);
//         cudaStreamSynchronize(pongStream);

//         //ping
//         for(size_t i = 0 ; i < counterPing ; i++) {  
//             PacketMetadata md = h_packetsMetadataPing[i];
//             PacketInfo* info;

//             ALIGN_ADDRESS(h_packetsMemPoolPing + md.packetOffset, PacketInfo, info);
//             ruleCount[info->ruleId]++;

//         }

//         //pong
//         for(size_t i = 0 ; i < counterPong ; i++) {  
//             PacketMetadata md = h_packetsMetadataPong[i];
//             PacketInfo* info;

//             ALIGN_ADDRESS(h_packetsMemPoolPong + md.packetOffset, PacketInfo, info);
//             ruleCount[info->ruleId]++;

//         }

//         if(!verbose){
//             printf("\033[2K\r");
//             fflush(stdout);

//             printf("# %0.3lf%% Of %s Is Processed", (((totalCounter*(16-sizeof(PacketInfo)) + totalPacketSize)*1.0)/(pcapFileSize*1.0))*100, pcapFilePath);
//             fflush(stdout);
//         } 

//         chunkCounter++;

//         if(result == -2)
//             break;
//     } printf("\n");
//     pcap_close(handle);

//     printf(">> Result:\n\t| Total Packets: %ld\n", totalCounter);
//     for(size_t i = 0 ; i < Rule_Count ; i++)
//         if(ruleCount[i] != 0) printf("\t| %s : %d\n", getRuleName(i), ruleCount[i]);
    
//     printf("\n\t| Duration: %lf ms\n\t| Bandwidth: %lf Gb/s\n\t| Bandwidth: %lf MPacket/s\n\t| Size: %lf Gb\n", 
//         totalDuration, (totalPacketSize * 8.0 * 1000.0) / (totalDuration * _GB_), (totalCounter * 1000.0) / (totalDuration * _MB_)  ,(totalPacketSize * 8.0)/(_GB_));    
    
//     CHECK_CUDA_ERROR(cudaFree((void*) d_trie));
//     CHECK_CUDA_ERROR(cudaFree((void*) d_packetsMemPoolPing));
//     CHECK_CUDA_ERROR(cudaFree((void*) d_packetsMemPoolPong));
//     CHECK_CUDA_ERROR(cudaFree((void*) d_packetsMetadataPing));
//     CHECK_CUDA_ERROR(cudaFree((void*) d_packetsMetadataPong));

//     CHECK_CUDA_ERROR(cudaFreeHost((void*) h_packetsMemPoolPing));
//     CHECK_CUDA_ERROR(cudaFreeHost((void*) h_packetsMemPoolPong));
//     CHECK_CUDA_ERROR(cudaFreeHost((void*) h_packetsMetadataPing));
//     CHECK_CUDA_ERROR(cudaFreeHost((void*) h_packetsMetadataPong));

//     CHECK_CUDA_ERROR(cudaStreamDestroy(pingStream));
//     CHECK_CUDA_ERROR(cudaStreamDestroy(pongStream));

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
//     return 0;
// }

// #define HELP_COMMAND_LINE       "Usage: ./ruleGraph [options] <arguments>"                                                  \
//                                 "\nAvailable Options:"                                                                      \
//                                 "\n\t-f\t\t: Select The Pcap File"                                                          \
//                                 "\n\t-d\t\t: Select The Directory Containing Multiple Pcap Files"                           \
//                                 "\n\t-c\t\t: Select The Config File (Default Is Set To 'config.yml')"                       \
//                                 "\n\t-v\t\t: Make The Operation More Talkative"                                             \
//                                 "\n\t-h\t\t: Print Help And Exit\n" 

// int main(int argc, char* argv[]) {

//     if(argc == 1) {
//         printf(HELP_COMMAND_LINE);
//         return -1;
//     }

//     int opt;
//     bool processDir = false;
//     bool processFile = false;
//     bool haveConfigFileName = false;
//     bool verbose = false;
//     char* pstr = NULL;
//     char* configFilePath = NULL;

//     while((opt = getopt(argc, argv, "d:f:c:hv")) != -1) {
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

//         case 'c':
//             haveConfigFileName = true;
//             configFilePath = optarg;
//             break;

//         case 'h':   
//             printf(HELP_COMMAND_LINE);
//             return 0;

//         case 'v':
//             verbose = true;
//             break;

//         case ':':
//             printf("Option -%c requires an argument\n", optopt);
//             return -1;

//         case '?':
//             printf("Unknown Option: -%c\n", optopt);
//             return -1;
//         }
//     }

//     if (!haveConfigFileName) {
//         configFilePath = "config.yml";  // default
//     }

//     ConfigLoader::loadAllfields(configFilePath);

//     if(processDir) 
//         return processDirectory(pstr, verbose);

//     if(processFile)
//         return processPcapFile(pstr, verbose);


//     return -1;
// }