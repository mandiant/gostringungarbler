# GoStringUngarbler

Python command-line project to resolve all strings in Go binaries obfuscated by [garble](https://github.com/burrowers/garble).

![ungarbling](/image/gostringungarbler.gif)


This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

**This tool only extracts strings for binaries where garble is run with the flag "-literals". A lot of the time, this flag is not provided when compiling, and the garble-obfuscated samples come with all the strings in plain text.**

## Install

**GoStringUngarbler** relies on the following Python dependencies:

```
- unicorn
- capstone
- pefile
```

To install and use the tool:

```console
$ git clone https://github.com/mandiant/gostringungarbler.git
$ cd gostringungarbler
$ pip install -r requirements.txt
$ python GoStringUngarbler -i <inputfile> -o <outputfile> -s <stringdump>
```

## Usage

```
usage: GoStringUngarbler [-h] -i INPUT [-o OUTPUT] [-s STRING]

Python project to deobfuscate strings in Go binaries protected by garble

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Garble-obfuscated executable path
  -o OUTPUT, --output OUTPUT
                        Deobfuscated output executable path
  -s STRING, --string STRING
                        Extracted string output path
```

The ```"-i"``` command-line argument is required. This argument takes the garble-obfuscated executable to resolve all the obfuscated strings.

The ```"-o"``` command-line argument can be provided to specify the output file path. The tool will deobfuscate the input binary and write the deobfuscated binary here.

The ```"-s"``` command-line argument can be provided to specify the file path to dump strings. The program will write the list of all extracted strings here.

## Features

Currently supporting Windows (PE) & Linux (ELF) binaries obfuscated with Garble v0.11.0 to v0.13.0 and Go v1.21 to v1.23.

New regex patterns will need to be added to support for newer version of the Go compiler as the **garble** obfuscator internally uses the Go compiler to compile its AST transformation.

### String Extraction
The program supports the following string obfuscating scheme from Garble.

- Stack transformation
  - Simple transformation
  - Swap transformation
  - Shuffle transformation
- Seed transformation
- Split transformation

For the details of these obfuscations, see the [string obfuscation documentation](/doc/StringObfuscatrion.md).

### Deobfuscation

The program first resolves all obfuscated strings by hunting down decoding subroutines through regex and emulating them through **unicorn** emulator. To deobfuscate, the program manually patches each decoding subroutine with the following template.

``` asm
xor     eax, eax
lea     rbx, [rip + 0xb]
mov     ecx, <decrypted string length>
call    runtime_slicebytetostring
ret
<decrypted string>
```

In the template above, we simply set up the arguments for ```runtime_slicebytetostring``` and call it. The register ```ebx``` contains the pointer to the decrypted string, and the register ```ecx``` contains the string's length.

As the **garble** obfuscator pushes the obfuscated bytes onto the stack in the decoding subroutine instead of retrieving them from another section in the binary, we know for sure that there will always be enough space in the subroutine body to contain the decrypted string content. 

With this, the **GoStringUngarbler** directly writes the decrypted string immediately following the subroutine being patched in.

![patch subroutine](/image/patched.png)

Below is the decompiled code of the patched function.

![patch decompiled](/image/patched_decompiled.png)

This should significantly speed up the analysis process for malware analysts when encountering samples obfuscated with garble.

## TODO

- Support other architectures
- Support older Go compiler versions (Should we even do this?)
- In-place string patching to eliminate wrapper subroutines
  - This is good for library function auto renaming