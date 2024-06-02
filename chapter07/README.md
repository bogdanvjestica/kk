# Chapter 7: Extending the Language: Mutable Variables 

```bash
clang++ -Xlinker --export-dynamic -g main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core orcjit native` -O3 -o main
```