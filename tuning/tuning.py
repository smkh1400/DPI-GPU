import sys
import csv
import os
import yaml

chunkSizeCoef = 1
threadPerBlockCoef = 1
pcapFileName = "3.pcap"

with open('config.yml', 'r') as file:
    data = yaml.safe_load(file)


for i in range(10):  #chunkCount

    chunkSize = 196608 * chunkSizeCoef
    data['chunkCountLimit'] = chunkSize

    for j in range(5):  #threadPerBlock 

        threadPerBlock = 32 * threadPerBlockCoef
        data['threadPerBlock'] = threadPerBlock

        with open('config.yml', 'w') as file:
            yaml.dump(data, file)

        os.system(f"../main -f ../../pcap/{pcapFileName} -c config.yml")

        threadPerBlockCoef *= 2

    chunkSizeCoef *= 2
    threadPerBlockCoef = 1

