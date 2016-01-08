CAV
=======

Certificate Authority Verification (CAV) is a tool that allows you to intercept
the certificate verification process of any non-browser application using
OpenSSL as a shared library. Interception is made possible by building CAV as a
shared object and using Linux’s `LD_PRELOAD` environment variable to override the
certificate verification functionality of OpenSSL and enforce verification
against a trusted store of your choice.


To learn more about it, check my blog post
[here](http://ifahad7.github.io/blog/2015/12/ssl_cav.html).


# Requirements

1. Linux (_tested on Ubuntu 14.04 LTS_)
2. libssl-dev

If you have vagrant, you can just `vagrant up && vagrant ssh` and then `make`
in the project directory and you'll be good to go. For more details about
installing vagrant, check their
[website](https://www.vagrantup.com/downloads.html).


# Build CAV

_Make sure you have libssl-dev installed or use the vagrant VM provided._

The `Makefile` has three targets

1. `build`: builds CAV as a shared library (`libcav.so`) in the `src` directory.
2. `demo` (default): builds CAV and runs the `demo.sh` script.
3. `clean`: cleans built files.

## Demo

The demo script uses `curl` to show you how CAV can intercept your the SSL
connection. CAV is built in debug mode, so you'll see debug statements that show
you the variuos steps of the verification process. Like this:

```
---------------------------------------
-------- Starting CAV demo ... --------
---------------------------------------
sh demo.sh
---[ Configure CAV to load certificated from /etc/ssl/certs ]---
---[ Running tests with default os certificates loaded ]---

	 TEST#1. curl -I https://www.google.com

cav.c:23:SSL_get_verify_result(): Hijacked
util.c:22:init_config_file(): Looking for CAV configuration in /home/vagrant/.cavrc
util.c:57:init_config_file(): Loaded CAV configurations from /home/vagrant/.cavrc
util.c:58:init_config_file(): CA_DIR = /etc/ssl/certs
util.c:59:init_config_file(): CA_FILE = /path/to/file
util.c:60:init_config_file(): LOG_FILE = path/to/logfile
verify.c:28:verify_cert(): Found peer certificate chain
verify.c:51:verify_X509_cert_chain(): Create new X509 store
verify.c:63:verify_X509_cert_chain(): Loaded certificates to store from  /etc/ssl/certs
verify.c:101:verify_X509_cert(): Created STORE CTX
verify.c:109:verify_X509_cert(): Initlized STORE CTX
verify.c:78:verify_X509_cert_chain(): Verified certificate in chain at index  0
verify.c:101:verify_X509_cert(): Created STORE CTX
verify.c:109:verify_X509_cert(): Initlized STORE CTX
verify.c:78:verify_X509_cert_chain(): Verified certificate in chain at index  1
verify.c:101:verify_X509_cert(): Created STORE CTX
verify.c:109:verify_X509_cert(): Initlized STORE CTX
verify.c:78:verify_X509_cert_chain(): Verified certificate in chain at index  2
verify.c:36:verify_cert(): Successfully verified X509 certificate chain
cav.c:29:SSL_get_verify_result(): Return execution to OpenSSL
HTTP/1.1 302 Found
Cache-Control: private
Content-Type: text/html; charset=UTF-8
Location: https://www.google.ca/?gfe_rd=cr&ei=kEmPVrvGCsSC8Qeh-r7ADg
Content-Length: 259
Date: Fri, 08 Jan 2016 05:30:56 GMT
Server: GFE/2.0

```

The second test does not load a trusted store and shows how CAV can fail the
connection. To run the complete demo, do the following:

```bash
cd ssl_cav # or cd /vagrant if you're in the vagrant VM
make
```

The above commands should build CAV and run the demo for you.


## cavrc

You can run CAV against a trusted certificate store of choice. All you have to
do is create a `$HOME/.cavrc` file with following configuration:

```
CA_FILE /path/to/trusted/certificate/file # Currently not used
CA_DIR /path/to/trusted/certificate/directory # Required
LOG /path/to/log/file # Currently not used
```

CAV picks these configuration every time a new SSL request is established.


# License
ssl_cav is released under the MIT license. See
[LICENSE.md](https://github.com/iFahad7/ssl_cav/blob/master/LICENSE.md) for details.

