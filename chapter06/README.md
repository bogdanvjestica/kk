## Chapter 6: Extending the Language: User-defined Operators 

```bash
clang++ -Xlinker --export-dynamic -g main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core orcjit native` -O3 -o main
```