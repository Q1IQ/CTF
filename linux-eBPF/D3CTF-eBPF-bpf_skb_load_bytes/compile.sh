gcc -O3 -masm=intel -U_FORTIFY_SOURCE -E ./exploit.c -o exploit.i
musl-gcc -O3 -masm=intel -S ./exploit.i -o exploit.s
musl-gcc -O3 -masm=intel -c ./exploit.s -o exploit.o
musl-gcc -O3 -masm=intel -static exploit.o -o exploit
