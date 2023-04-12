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
void verifyUpdate(SRxProxy* proxy, uint32_t localID,
                  bool usePrefixOriginVal, bool usePathVal, bool useAspaVal,
                  SRxDefaultResult* defaultResult,
                  IPPrefix* prefix, uint32_t as32,
                  BGPSecData* bgpsec, SRxASPathList asPathList);
extern void ValEasyCallback();
extern void SignatureEasyCallback();
extern void SyncEasyCallback();
extern void SrxCommEasyCallback();
typedef void (*closure)();
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"

	//_ "github.com/osrg/gobgp/table"
	_ "os"

	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
)

type IPv4Address [4]uint8

type IPv6Address [16]uint8

type IPAddress struct {
	Version uint8
	V4      [16]uint8
}

type PathList struct {
	length         uint8
	segments       C.ASSEGMENT
	asType         C.AS_TYPE
	asRelationship C.AS_REL_TYPE
}

type aspaManager struct {
	AS               uint32
	ConnectionStatus bool
	Proxy            C.SRxProxy
}

//export ValEasyCallback
func ValEasyCallback() {
	log.Info("validation callback from srx proxy")
}

//export SignatureEasyCallback
func SignatureEasyCallback() {
	log.Info("signature callback from srx proxy")
}

//export SyncEasyCallback
func SyncEasyCallback() {
	log.Info("Sync callback from srx proxy")
}

//export SrxCommEasyCallback
func SrxCommEasyCallback() {
	log.Info("SrxComm callback from srx proxy")
}

func (am *aspaManager) SetAS(as uint32) error {
	log.Info("Changing ASPA AS to:")
	log.Info(as)
	if am.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	am.AS = as
	//am.Proxy = nil
	return nil
}

func (am *aspaManager) validate(e *fsmMsg) {
	//m := e.MsgData.(*bgp.BGPMessage)
	//update := m.Body.(*bgp.BGPUpdate)
	log.WithFields(log.Fields{"Topic": "bgpsec"}).Infof("Validate server operated ")

	var nlri_processed bool
	var prefix_addr net.IP
	var prefix_len uint8
	var nlri_afi uint16
	var nlri_safi uint8
	log.Info("In Validation Function")

	var Res C.SRxResultSource
	Res = 0
	var test C.SRxResult
	test.roaResult = 0
	test.bgpsecResult = 0
	test.aspaResult = 0
	var defaultResult C.SRxDefaultResult
	defaultResult.resSourceROA = Res
	defaultResult.resSourceBGPSEC = Res
	defaultResult.resSourceASPA = Res
	defaultResult.result = test
	log.Info("In Validation Function 2")

	//
	// find nlri attribute first and extract prefix info for bgpsec validation
	//
	for _, path := range e.PathList {

		// find MP NLRI attribute first
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI) {
				log.Debug("received MP NLRI: %#v", path)
				prefix_addr = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Prefix
				prefix_len = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Length
				nlri_afi = p.(*bgp.PathAttributeMpReachNLRI).AFI
				nlri_safi = p.(*bgp.PathAttributeMpReachNLRI).SAFI

				log.WithFields(log.Fields{"Topic": "Bgpsec"}).Debug("prefix:", prefix_addr, prefix_len, nlri_afi, nlri_safi)
				nlri_processed = true
				log.Debug("received MP NLRI: %#v", nlri_processed)
			}
		}
	}

	log.Info("In Validation Function 3")

	px := &IPAddress{
		Version: 4,
		V4:      [16]byte{},
	}
	//pxip := prefix_addr
	//copy(px.Addr[:], pxip)
	//px.Pack(unsafe.Pointer(prefix2))

	cIpAddr := C.IPAddress{
		version: C.uint8_t(4),
		addr:    px.V4,
	}

	var prefix C.IPPrefix
	prefix.ip = cIpAddr
	prefix.length = 24

	log.Info("In Validation Function 4")

	var testing_1 C.ASSEGMENT

	var ASList PathList
	ASList.length = 1
	ASList.segments = testing_1
	ASList.asType = 2
	ASList.asRelationship = 0

	var testList C.SRxASPathList
	testList.length = 1
	testList.segments = &testing_1
	testList.asType = 1
	testList.asRelationship = 1

	var number1 C.uchar
	number1 = 1
	var number2 C.uint
	number2 = 1
	var go_bgpsec C.BGPSecData
	go_bgpsec.numberHops = 1
	go_bgpsec.asPath = &number2
	go_bgpsec.attr_length = 1
	go_bgpsec.afi = 1
	go_bgpsec.safi = 1
	go_bgpsec.reserved = 1
	go_bgpsec.local_as = 1
	go_bgpsec.bgpsec_path_attr = &number1

	log.Info("In Validation Function 6")

	C.verifyUpdate(&am.Proxy, 1, false, false, true, &defaultResult, &prefix, 65002, nil, testList)

	log.Info("In Validation Function 7")
}

func NewASPAManager(as uint32) (*aspaManager, error) {
	log.Info("+---------------------------------------+")
	log.Info("Creating New ASPA Manager. AS:")
	log.Info(as)
	log.Info("Trying to create an Proxy:")
	go_proxy := C.createSRxProxy(C.closure(C.ValEasyCallback), C.closure(C.SignatureEasyCallback), C.closure(C.SyncEasyCallback), C.closure(C.SrxCommEasyCallback), 0, C.uint(as), nil)
	srx_server_ip := C.CString("172.17.0.3")
	srx_server_port := C.int(17900)
	handshakeTimeout := C.int(100)
	connectionStatus := C.connectToSRx(go_proxy, srx_server_ip, srx_server_port, handshakeTimeout, true)
	log.Info("Connection Status:")
	log.Info(connectionStatus)
	am := &aspaManager{
		AS:               as,
		Proxy:            *go_proxy,
		ConnectionStatus: bool(connectionStatus),
	}
	return am, nil
}

// https://www.socketloop.com/tutorials/golang-convert-ipv4-address-to-packed-32-bit-binary-format
func ConvertIP(ipv4 string) C.IPv4Address {
	var result C.IPv4Address

	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes((net.ParseIP(ipv4)).To4())

	ipv4Decimal := IPv4Int.Int64()

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint32(ipv4Decimal))

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
	}
	result[0] = buf.Bytes()[0]
	result[1] = buf.Bytes()[1]
	result[2] = buf.Bytes()[2]
	result[3] = buf.Bytes()[3]
	return result
}
