package server

/*
#cgo CFLAGS: -I/opt/project/srx_test1/_inst/include/srx
#cgo LDFLAGS: -L/home/centos/Master/NIST-BGP-SRx/local-6.2.0/lib64/srx -lSRxProxy
#include <stdio.h>
#include <stdlib.h>
#include "/home/centos/Master/NIST-BGP-SRx/srx-server/src/client/srx_api.h"
SRxProxy* createSRxProxy(ValidationReady   validationReadyCallback,
                         SignaturesReady   signatureReadyCallback,
                         SyncNotification  requestSynchronizationCallback,
                         SrxCommManagement communicationMgmtCallback,
                         uint32_t proxyID, uint32_t proxyAS, void* userPtr);
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
	srx_proxyID := 1
	as := 2
	bgp := 3

	proxy := C.createSRxProxy(srx_proxyID, as, bgp)
	C.connectToSRx(proxy)
	log.Debug("Jabadabadu")
	//m.BgpsecInit(as)
	return 1
}
