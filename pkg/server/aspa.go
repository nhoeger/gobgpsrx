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

	//_ "github.com/osrg/gobgp/table"
	_ "os"

	log "github.com/sirupsen/logrus"
)

type aspaManager struct {
	AS uint32
}

func TestFunction(as uint32) int {
	b := C.connectToSRx
	fmt.Println(b)
	return 1
}

func (am *aspaManager) SetAS(as uint32) error {
	log.Info("Changing ASPA AS to:")
	log.Info(as)
	if am.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	am.AS = as
	return nil
}

func (am *aspaManager) validate() bool {
	log.Info("In Validation Function")
	ret := false
	log.Info("Returning with")
	log.Info(ret)
	return ret
}

func NewASPAManager(as uint32) (*aspaManager, error) {
	log.Info("+---------------------------------------+")
	log.Info("Creating New ASPA Manager. AS:")
	log.Info(as)
	am := &aspaManager{
		AS: as,
	}
	return am, nil
}
