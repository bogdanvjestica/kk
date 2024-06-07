# Chapter 8: Compiling to Object Files

```bash
clang++ -Xlinker --export-dynamic -g -O3 main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs all` -o main
```