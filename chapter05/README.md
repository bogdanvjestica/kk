## Chapter 3: Code generation to LLVM IR

```bash
clang++ -Xlinker --export-dynamic  -g main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core orcjit native` -O3 -o main
```