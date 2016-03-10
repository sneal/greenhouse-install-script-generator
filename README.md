# Greenhouse install script generator

The greenhouse install script generator is a command line tool that reads
configuration data from your BOSH director to `generate` a batch file with
the appropriate command line parameters to install and configure
GardenWindows.msi and DiegoWindows.msi.

## Installation

Precompiled binaries can be downloaded from the
[Diego Windows Releases](https://github.com/cloudfoundry/diego-windows-release/releases).
See the
[Diego Windows installation instructions](https://github.com/cloudfoundry/diego-windows-release/blob/master/docs/INSTALL.md)
for more detail.

## Usage

Sample for BOSH Lite:
```
generate -boshUrl https://admin:admin@192.168.50.4:25555 -outputDir /tmp/bosh-lite-install-bat -windowsPassword password -windowsUsername username
```
The Windows user must be a local user with administrative privileges,
e.g. domain users are not supported. The password cannot contain special
characters. Only the letters A-Z and the numbers 0-9 are currently allowed.

## Building

1. [Install and configure direnv](http://direnv.net/)
1. `git clone https://github.com/cloudfoundry-incubator/greenhouse-install-script-generator`
1. `cd ./greenhouse-install-script-generator`
1. Allow direnv to execute in this dir `direnv allow`
1. Pull in libs `git submodule init && git submodule update`
1. Build the executable `go build -o $GOPATH/bin/generate ./src/generate/generate.go`


## Tests

We use [Ginkgo](http://onsi.github.io/ginkgo/#the-ginkgo-cli) as our testing
framework and runner. To run the install script generator tests:

1. `go get github.com/onsi/ginkgo/ginkgo`
1. `ginkgo ./src/integration/`
