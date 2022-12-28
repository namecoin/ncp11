# Experiments with a Namecoin PKCS11 Module

**We do these experiments so you don't have to.  Do not try this at home.  No really, don't.**

## Build Instructions

1. Install the `libltdl` development headers.  On Debian, this can be done via `sudo apt-get install libldtl-dev`
1. Install Go.
1. `go get -d github.com/namecoin/ncp11`
1. `cd $(go env GOPATH)/src/github.com/namecoin/ncp11`
1. `make`

The output file will be named `libnamecoin.so`.

## Installation Instructions

1. Build ncp11 from source (see above) or download binaries from Namecoin.org.
1. Install [certdehydrate-dane-rest-api](https://github.com/namecoin/certdehydrate-dane-rest-api/) and make sure that it's running.  (You'll probably want to set it to launch automatically on boot.)
1. Follow the instructions below for your desired TLS implementation:

### Generic NSS (Anything that uses the shared NSS trust store, e.g. Chromium)

1. `sudo make install`
1. Find the `libnssckbi.so` file that shipped with NSS.  You can easily search for it via `find /usr/ -name libnssckbi.so`.  Commonly found locations include `/usr/lib64/nss/libnssckbi.so` (on Fedora for amd64) and `/usr/lib/x86_64-linux-gnu/nss/libnssckbi.so` (on Debian for amd64).
1. Copy `libnssckbi.so` to `/usr/local/namecoin/libnssckbi-namecoin-target.so`.  For example, `sudo cp /usr/lib64/nss/libnssckbi.so /usr/local/namecoin/libnssckbi-namecoin-target.so`.
1. `make nss-shared-install`

You'll need to restart your NSS-using programs (e.g. Chromium) if you want them to notice that ncp11 is installed.

Remember to re-copy `libnssckbi.so` whenever NSS is upgraded on your system!

### Firefox

1. `sudo make install`
1. Find the `libnssckbi.so` file that shipped with Firefox.  You can easily search for it via `find /usr/ -name libnssckbi.so`.  Commonly found locations include `/usr/lib/firefox-esr/libnssckbi.so` (on Debian for amd64).  Some operating systems (e.g. Fedora) don't ship an NSS that's specific to Firefox and instead make Firefox use the system NSS; if you're on such an OS, use the system `libnssckbi.so`.
1. Copy `libnssckbi.so` to `/usr/local/namecoin/libnssckbi-namecoin-target.so`.  For example, `sudo cp /usr/lib/firefox-esr/libnssckbi.so /usr/local/namecoin/libnssckbi-namecoin-target.so`.
1. `make nss-firefox-install`

Note that it's a very bad idea to install both Generic NSS and Firefox support at the same time, because the copied `libnssckbi.so` instances will conflict.  However, if your OS's Firefox package uses the system NSS (e.g. Fedora), then it's totally fine to install both simultaneously (since the `libnssckbi.so` files are identical).

You'll need to restart Firefox if you want it to notice that ncp11 is installed.

Remember to re-copy `libnssckbi.so` whenever NSS is upgraded on your system!

### Tor Browser

1. Make sure that Tor Browser isn't currently running.
1. Rename `libnssckbi.so` in the Tor Browser `Browser` directory to `libnssckbi-namecoin-target.so`.
1. Copy `libnamecoin.so` from ncp11 to the Tor Browser `Browser` directory.
1. Rename `libnamecoin.so` in the Tor Browser `Browser` directory to `libnssckbi.so`.

You can now start Tor Browser.

Remember to re-do these steps whenever Tor Browser is upgraded on your system!

## License / Credits

Original code Copyright Namecoin Developers 2018-2022.  `ckibproxy`, `fedorarealckbiproxy`, and `testdata` directories, and loose files in root directory, are licensed under LGPLv2.1+.  `moz` directory is licensed under GPLv3+.

Based on:

* https://github.com/miekg/pkcs11
    * BSD 3-Clause License
* https://github.com/Pkcs11Interop/pkcs11-mock
    * Apache 2.0 License
