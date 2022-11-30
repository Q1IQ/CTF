Build
```
clang `llvm-config --cxxflags` -Wl,-znodelete -fno-rtti -fPIC -shared whatapass.cpp -o LLVMWhataPass.so `llvm-config --ldflags`
```

Run
```
$ docker build . -t whatapass
$ docker run -it whatapass /bin/bash
root@104961577b89:/home/ctf# clang -emit-llvm -S example.c -o example.ll
root@104961577b89:/home/ctf# ./opt -load ./LLVMWhataPass.so -Whatapass example.ll -o /dev/null
What a pass! 
BB: 0x2293d20
        Inst: 0x2293dc8
        Inst: 0x2294498
        Inst: 0x22944f8
        Inst: 0x22945c0
        Inst: 0x2294640
        Inst: 0x22946c0
        Inst: 0x2294800
        Inst: 0x22949c8
        Inst: 0x2294b60
        Inst: 0x2294cc8
        Inst: 0x2293d70
```