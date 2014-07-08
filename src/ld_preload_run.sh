gcc -Wall -fPIC -shared -o cav.so cav.c
LD_PRELOAD=./cav.so ./sslcav

