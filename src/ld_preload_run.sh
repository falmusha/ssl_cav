echo "\n\n============[ 1. Testing handshake.c ]============\n\n"
LD_PRELOAD=./cav.so ./sslcav

echo "\n\n============[ 2. Testing wget www.google.com ]============\n\n"
LD_PRELOAD=./cav.so wget -nv https://google.com

echo "\n\n============[ 3. Testing wget ecewo.uwaterloo.ca ]============\n\n"
LD_PRELOAD=./cav.so wget -nv https://ecewo.uwaterloo.ca 

echo "\n\n============[ 3. Testing wget pcwebshop.co.uk ]============\n\n"
LD_PRELOAD=./cav.so wget -nv https://pcwebshop.co.uk


