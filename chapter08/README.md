# Chapter 7: Extending the Language: Mutable Variables 

```bash
clang++ -Xlinker --export-dynamic -g -O3 main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs all` -o main
```