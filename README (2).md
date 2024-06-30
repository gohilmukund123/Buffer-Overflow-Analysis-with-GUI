# Buffer Overflow Exploit Visualization

This project uses a Graphical User Interface (GUI) to visualize and understand buffer overflow exploits which is written using a simple C program. The GUI is built with Python's Tkinter library.

## Overview

Buffer overflow is a vulnerability where data can be written past the allocated buffer size, potentially overwriting adjacent memory. This project provides:

- **Visualization**: Graphical representation of buffer memory and hex dump.
- **Demonstration**: Ability to run custom payloads and visualize overflow scenarios.
- **Error Handling**: Detection and visualization of segmentation faults caused by buffer overflow.

## Files

- **gui.py**: Python script for the GUI using Tkinter.
- **exploit.c**: C program vulnerable to buffer overflow.

## Features

- **Input Payload**: Enter a custom payload to simulate buffer overflow.
- **Visualization**:
  - **Buffer Visualization**: Display of buffer memory with overflow indication.
  - **Hexdump Visualization**: Hexadecimal representation of input with overflow highlighting.
- **Information Display**: Dynamic display of payload length, buffer size, overflow details, and program execution status.
- **Error Handling**: Handling of compilation errors and runtime exceptions.

## Usage

1. Ensure Python 3 and Tkinter are installed.
2. Compile `exploit.c` using `gcc` (ensure `-fno-stack-protector` and `-z execstack` for exploit simulation). Or you can directly run the `gui.py` file. 
3. Run `gui.py` to launch the GUI.
4. Enter a payload in the GUI and click "Run Exploit" to visualize buffer overflow.



## Setup

To run the project locally:

1. Clone the repository:

   ```bash
   git clone https://github.com/gohilmukund123/buffer-overflow-visualization.git
   cd buffer-overflow-visualization
   ```

2. Compile the C program:

   ```bash
   gcc -fno-stack-protector -z execstack -o exploit exploit.c
   ```

3. Launch the GUI:

   ```bash
   python gui.py
   ```
