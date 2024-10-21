# Deep Packet Inspection with cuda GPU

## Overview

This project implements a **Deep Packet Inspection (DPI)** application designed to classify network packets based on custom-defined rules. The application leverages **CUDA** for high-performance packet processing on the GPU.

The main goal of this project is to build a high-throughput DPI engine that can detect and classify network packets according to specific rule-based conditions. The detection phase is optimized using a tree-based structure to store rules, enabling efficient parallel processing of packets.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

- **NVIDIA GPU** with CUDA support (e.g., RTX 4090).
- **CUDA Toolkit** (version compatible with your GPU).
- **Libpcap** for reading pcap files.
- **CMake** for project compilation.
- **C++17** or later for building the project.
- **yaml-cpp** for configuration settings

### Installation

2. Clone the repository
   ```sh
   git clone https://github.com/smkh1400/DPI-GPU.git
   cd DPI-GPU
   ```
3. Built the project using **make**
   ```sh
   make -B
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

1. Configure the settings in _config.yml_
   ```yml
   isTimerSet: false
   readPacketMode: offline
   chunkCountLimit: 1572864
   chunkTimeLimit: -1
   threadPerBlock: 32
   ```
2. Run the application for a specific pcap file using flag -f
   ```sh
   ./main -f <path_to_pcap_file>
   ```
   Or for a directory containing pcap files
   ```sh
   ./main -d <path_to_directory_of_pcap_files>
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->

## Contact

Seyed Mohammadreza Khosravian: mz2012kh82@gmail.com

MohammadMehdi Sattari: mamadsadtari83@gmail.com

Project Link: [https://github.com/smkh1400/DPI-GPU](https://github.com/smkh1400/DPI-GPU)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
