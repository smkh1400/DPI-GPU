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

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repository
   ```sh
   git clone 
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```js
   const API_KEY = 'ENTER YOUR API';
   ```
5. Change git remote url to avoid accidental pushes to base project
   ```sh
   git remote set-url origin github_username/repo_name
   git remote -v # confirm the changes
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Your Name - [@your_twitter](https://twitter.com/your_username) - email@example.com

Project Link: [https://github.com/your_username/repo_name](https://github.com/your_username/repo_name)

<p align="right">(<a href="#readme-top">back to top</a>)</p>