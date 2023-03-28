package server

/*
#cgo CFLAGS: -I/opt/project/srx_test1/_inst/include/srx
#cgo LDFLAGS: -L/home/centos/Master/NIST-BGP-SRx/local-6.2.0/lib64/srx -lSRxProxy
#include <stdio.h>
#include <stdlib.h>
#include "/home/centos/Master/NIST-BGP-SRx/srx-server/src/client/srx_api.h"
bool connectToSRx(SRxProxy* proxy, const char* host, int port,
                  int handshakeTimeout, bool externalSocketControl);
*/
import "C"

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	//_ "github.com/osrg/gobgp/table"

	_ "os"
)
//Just a test

func TestFunction(as uint32) int {
	b := C.connectToSRx
	fmt.Println(b)
	return 1
}

func NewASPAManager(as uint32) int {
	m := TestFunction(1)
	log.Debug("Jabadabadu")
	//m.BgpsecInit(as)
	return m
}
