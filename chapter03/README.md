## Chapter 3: Code generation to LLVM IR

```bash
clang++ -g -O3 main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core` -o main
```