libcav="/vagrant/src/libcav.so"
default_certs_dir="/etc/ssl/certs"


if [ ! -f $libcav ]; then
  echo "!!!! Couldn't find $libcav, please run make form project root !!!!"
  exit
fi

echo "---[ Configure CAV to load certificated from $default_certs_dir ]---"

echo "CA_FILE /path/to/file \n\
CA_DIR $default_certs_dir \n\
LOG path/to/logfile" > ~/.cavrc

echo "---[ Running tests with default os certificates loaded ]---"

echo
echo "\t TEST#1. curl -I https://www.google.com"
echo
LD_PRELOAD=$libcav curl -I https://www.google.com

echo "---[ Configure CAV to NOT load certificates ]---"

echo "CA_FILE /path/to/file \n\
CA_DIR /invalid/path \n\
LOG path/to/logfile" > ~/.cavrc

echo "---[ Running tests with no certificates loaded ]---"

echo
echo "\t TEST#2. curl -I https://www.google.com"
echo
LD_PRELOAD=$libcav curl -I https://www.google.com
