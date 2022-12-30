# ncp11: Namecoin TLS Certificate Trust PKCS#11 Module

## Build Instructions

1. Install Go.
1. Clone this repo.
1. Configure Go Modules to use the latest experimental Namecoin branches of [pkcs11mod](https://github.com/namecoin/pkcs11mod) and [pkcs11](https://github.com/namecoin/pkcs11) (these will be submitted upstream later).
1. `CGO_ENABLED=1 go build -buildmode c-shared -o libncp11.so`
    1. If building for Windows or macOS, change the output filename to `ncp11.dll` or `libncp11.dylib`.

## Installation Instructions

1. Build ncp11 from source (see above) or download binaries from Namecoin.org.
1. Install [Encaya](https://github.com/namecoin/encaya/) and make sure that it's running.  (You'll probably want to set it to launch automatically on boot.)
1. Install ncp11 like any other PKCS#11 module.

### p11-kit (e.g. NSS, GnuTLS, Firefox, Chromium, and GNOME Web on Fedora)

[Register via .module file](https://docs.fedoraproject.org/en-US/packaging-guidelines/Pkcs11Support/#_registering_the_modules_system_wide)

### NSS (e.g. Firefox on all OS's and Chromium on GNU/Linux)

[modutil -add](https://firefox-source-docs.mozilla.org/security/nss/legacy/tools/modutil/index.html)

### Firefox (probably also LibreWolf, IceCat, etc.)

[Security Devices GUI](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11#using_the_firefox_preferences_dialog_to_install_pkcs_11_modules)

### Firefox

[SecurityDevices Enterprise Policy](https://github.com/mozilla/policy-templates#securitydevices)

## License / Credits

Original code Copyright Namecoin Developers 2018-2022.  `ckibproxy`, `fedorarealckbiproxy`, and `testdata` directories, and loose files in root directory, are licensed under LGPLv2.1+.  `moz` directory is licensed under GPLv3+.

Based on:

* https://github.com/miekg/pkcs11
    * BSD 3-Clause License
* https://github.com/Pkcs11Interop/pkcs11-mock
    * Apache 2.0 License
