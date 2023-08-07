# GoBGPSRx 

GoBGPSRx extends GoBGPsec and adds ASPA and AS-Cones validation. 

## GoBGPsec

GoBGPsec uses NIST SRxCrypto library to facilitate crypto calculations
which is able to sign and verify X.509 objects for BGPSec path validation. 
This software is based on [Gobgp](https://github.com/osrg/gobgp) BGP implementation and added codes for 
implementing BGPSec protocol ([RFC 8205](https://tools.ietf.org/html/rfc8205)).

This work is part of the larger [NIST Robust Inter Domain Routing Project](https://www.nist.gov/programs-projects/robust-inter-domain-routing) that addresses a wide range of security and resilience issues in the Internet’s routing infrastructure. The software in this repository is a component of a larger [suite of software tools](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-software-suite) developed within the project.


## Project Status

Active development




## Getting Started

You need a working Go Environment 

* go version > 1.13 
* protoc version == 3.7.1


### Prerequisites
GoBGPSRx requires a running SRx-Server.
GoBGPsec requires to use this crypto library for signing and validation 
when the BGPSec operation starts.
* Need to install SRxCryptoAPI library and SRx-Server first
* Need SRxCryptoAPI library >= v3.0


Download NIST SRx software from the link below. 
```bash
git clone https://github.com/usnistgov/NIST-BGP-SRx.git
```

And then build with buildBGP-SRx.sh script.
It will install automatically all the packages.
```bash
./buildBGP-SRx.sh
```

For more information such as key generation for signing and etc,
please refer to [NIST SRxCryptoAPI](https://github.com/usnistgov/NIST-BGP-SRx/tree/master/srx-crypto-api) page.


### Build 
To import NIST SRxCryptoAPI library, need to specify the library location with a build or
install command. Otherwise LD_LIBRARY_PATH environment variable might be used.



Avoiding the LD_LIBRARY_PATH for Shared Libs in Go (cgo) Applications   
```
export CGO_LDFLAGS="-L/path/to/lib64/srx -Wl,-rpath -Wl,/path/to/lib64/srx"

```


### Install
To Install on Localhost: Replace /root/... path in bgpsec.go with paths on localhosts.

Install binaries into $GOPATH/bin. Simply use 'install' instead of 'build' in commands
```
go install ./...
```
</br></br>

### BGPSec and SRx-Server Configuration
 [GoBGPsec Configuration](docs/sources/bgpsec.md)
</br></br>

### Quick Start

```bash
# gobgpd -p -f /etc/gobgpd.conf --log-level=debug
````
## With Docker
* Replace Docker File of NIST-BGP-SRx repository with Dockerfile in GoBGPSRx
* Copy GoBGPSRx into NIST-BGP-SRx directory 



## Authors & Main Contributors
* Nils Höger (nils.hoeger@unibw.de)
</br></br>


## Contact
* Kyehwan Lee (kyehwanl@nist.gov)
* Nils Höger (nils.hoeger@unibw.de)
</br></br>



## Copyright

### DISCLAIMER
Gobgpsec was developed for applying BGPSec Routing software, NIST BGP-SRx
into GoBGP by employees of the Federal Government in the course of their 
official duties. NIST BGP-SRx is an open source BGPSec implementation for 
supporting RPKI and BGPSec protocol specification in RFC. 
Additional information can be found at [BGP Secure Routing Extension (BGP‑SRx) Prototype](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype)


NIST assumes no responsibility whatsoever for its use by other parties,
and makes no guarantees, expressed or implied, about its quality,
reliability, or any other characteristic.

This software might use libraries that are under original license of
GoBGP or other licenses. Please refer to the licenses of all libraries 
required by this software.

