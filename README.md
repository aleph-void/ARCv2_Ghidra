### Description
This extension implements ARCv2 instruction set that can be used for disassembly, decompilation and emulation on Ghidra.

This is the Ghidra-Rare fork: the specification is now generated, covers the whole ARCv2 instruction
set as GNU objdump knows it (ARC EM and HS, both byte orders) and is tested against objdump, Ghidra's
emulator and real binaries. See [GHIDRA-RARE.md](GHIDRA-RARE.md) for what it covers, how it was tested
and the results, and [CREDITS.md](CREDITS.md) for the authors and the list of changes.

### Installation
Download a pre-built release zip for your Ghidra version (12.1.3, 12.1.4 or 12.2) from the fork's
Releases page and install it with *File > Install Extensions* in the Ghidra project window, then
restart Ghidra. (The original instructions, unzipping into `<ghidra_folder>\Ghidra\Processors`,
also work for a development copy of this directory.)

Two languages are provided: `ARCv2:LE:32:default` and `ARCv2:BE:32:default`. ELF files
(e_machine 195, EM_ARC_COMPACT2) are recognised automatically; raw images (for example a firmware
`.bin` file) are imported with the *Raw Binary* format and one of these languages.

### Example
The example folder contains an AES-128 white-box implementation compiled for ARCv2 instruction set. 
Start a new project in Ghidra and then open a file:

`<ghidra_folder>\Ghidra\Processors\ARCv2\example\AES\AES.elf`

(with a release zip installed as an extension: `<user settings>/Extensions/ARCv2/example/AES/AES.elf`)

Execute a standard analysis of the binary.

Go to the function `Cipher_uint32` - the binary shall be disassembled and the function shall be correctly decompiled.

![alt text](images/AES_Cipher.PNG)

### TODO
* ~~EXT5 instruction support~~ Fixed in the Ghidra-Rare fork: major opcode 5 (and the other
  extension majors 6 and 7) decode every instruction GNU objdump knows; see GHIDRA-RARE.md.
* Switching the set of used registers: not needed for decoding (a core with the reduced 16-entry
  register file uses the same encodings); register names follow GNU objdump (`r58`/`r59` for the
  accumulator, `ilink`, `lp_count`). Remaining, see GHIDRA-RARE.md.

### License
This extension is licensed under the Apache License Version 2.0.
