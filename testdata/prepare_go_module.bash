#!/usr/bin/env bash

set -euxo pipefail

# The pkcs11mod_script and fetch_script steps of .cirrus.yml.  Cirrus
# ran them inside GOPATH, where "go mod init" could infer the module path, so
# the paths are explicit here.
ncp11_dir="$PWD"

cd ../
git clone https://github.com/namecoin/pkcs11mod.git
cd pkcs11mod
git checkout api-fork-1.1.1.5
go mod init github.com/namecoin/pkcs11mod
go mod tidy
go generate ./...
go mod tidy

cd "$ncp11_dir"
go mod init github.com/namecoin/ncp11
go mod edit -replace github.com/miekg/pkcs11=github.com/namecoin/pkcs11@master-1.1.1.4 -replace github.com/namecoin/pkcs11mod=../pkcs11mod
go mod tidy
go generate ./...
go mod tidy
