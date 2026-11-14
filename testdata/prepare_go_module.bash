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
go mod edit -replace github.com/miekg/pkcs11=github.com/namecoin/pkcs11@master-1.1.1.4 -replace github.com/namecoin/pkcs11mod=../pkcs11mod -replace gopkg.in/alecthomas/kingpin.v2=github.com/alecthomas/kingpin/v2@v2.4.0
go get github.com/btcsuite/btcd@v0.25.0
go get github.com/namecoin/safetlsa@6c9b6938753a71a7232f1b989fc7d59d366be62b
go get github.com/namecoin/ncdns@6aa3d447a50a9e5c4eab258d7c5e83d9a761d9d3
go get github.com/namecoin/encaya@9b4865a21bbf46dc397a8216921b6eb295964965
go mod tidy
go generate ./...
go mod tidy
