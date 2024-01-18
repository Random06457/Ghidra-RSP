# Ghidra-RSP

A Nintendo 64 RSP processor module and loader for [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

![Demo](https://github.com/Random06457/Ghidra-RSP/assets/28494085/64c587df-c587-4ef0-8982-8126af713f57)

# Usage
- Drop a RSP binary in Ghidra (content of IMEM).

- In the loader options, you can decide whether to load the RSP binary as a boot microcode or main microcode. (This will just change the base address of the binary, 0x1000 or 0x1080 respectively for boot or main microcode).

- After hitting the OK button, the loader will prompt for a path to load the content of DMEM from. (You can choose not to import any DMEM content by clicking the cancel button in the file prompt).

# Installation

- Open Ghidra
- File-> Install Extensions
- Import zip file from the release section
