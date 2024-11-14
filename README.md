<div align="center">

# EtherWatch

![Commit activity](https://img.shields.io/github/commit-activity/m/iyksh/EtherWatch)
![GitHub top language](https://img.shields.io/github/languages/top/iyksh/EtherWatch?logo=C&label=C)
[![GitHub license](https://img.shields.io/github/license/iyksh/EtherWatch)](https://github.com/iyksh/EtherWatch/blob/main/LICENSE)
[![pt-br](https://img.shields.io/badge/lang-pt--br-green.svg)](./res/README_PTBR.md)

A low-level toolkit written in C, for network analysis and forensic investigators by capturing, analyzing, and logging network traffic. 

</div>

---

## Features

- ✔️ **Packet Capture**: High-performance, low-level packet capture.
- ✔️ **Protocol Analysis**: Support for protocol inspection, including TCP, UDP, ICMP, and DNS (Not yet).
- ✔️ **Cross-Platform**: Runs seamlessly on both Linux and Windows.
- 🚧 **Data Logging**: Structured log outputs for simplified data export and review (in progress).
- 🚧 **Lightweight GUI**: Minimal, user-friendly graphical interface by Raylib (in progress).
- 🛠 **Optimized Performance**: Minimal memory footprint;=.

## Requirements

- **Dependencies**:
  - `Raylib`: Dependency for graphical interface support

### Installing Dependencies

- **Raylib** (for GUI support): Install via package manager or [Raylib's official guide](https://github.com/raysan5/raylib).

## Building and Running

1. **Clone the repository**:
    ```bash
    git clone https://github.com/iyksh/EtherWatch.git
    cd EtherWatch
    ```

2. **Compile**:
    ```bash
    make all
    ```

3. **Run**:
    ```bash
    ./build/etherwatch 
    ```
---

### Disclaimer

EtherWatch is provided for research and educational purposes only. The authors and maintainers are not responsible for any misuse of this toolkit.
