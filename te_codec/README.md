## Build
In order to build this application you will need:
* CMake
* Your favorite build tool (e.g. GNU Make, Ninja, ...)
* C Compiler Toolchain (e.g. GCC)

```
mkdir build && cd build
cmake ..
cmake --build .
```
Build application is in `build/riscv-trace-codec`.

## Run
This application expects `riscv-none-embed-objdump` in your PATH environmental variable (FIXME!). You can get it [here](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v10.2.0-1.2).

Example invocation:
```
riscv-trace-codec -e your_elf_file.elf raw_trace.hex
```
