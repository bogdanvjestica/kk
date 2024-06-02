## Chapter 5: Extending the Language: Control Flow

```bash
clang++ -Xlinker --export-dynamic  -g main.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core orcjit native` -O3 -o main
```
