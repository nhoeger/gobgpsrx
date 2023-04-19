package server

/*
#cgo CFLAGS: -I/opt/project/srx_test1/_inst/include/srx
#cgo LDFLAGS: -L/home/centos/Master/NIST-BGP-SRx/local-6.2.0/lib64/srx -lSRxProxy
#include <stdio.h>
#include <stdlib.h>
#include "/home/centos/Master/NIST-BGP-SRx/srx-server/src/client/srx_api.h"
#include "/usr/include/netinet/in.h"
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
bool isConnected(SRxProxy* proxy);
void setProxyLogger(ProxyLogger logger);
bool disconnectFromSRx(SRxProxy* proxy, uint16_t keepWindow);
bool processPackets(SRxProxy* proxy);
typedef void (*ProxyLogger)(int level, const char* fmt, va_list arguments);
typedef void (*SignaturesReady)(SRxUpdateID updId, BGPSecCallbackData* data, void* userPtr);

extern bool Go_ValidationReady(SRxUpdateID          updateID,
                                uint32_t	           localID,
                                ValidationResultType valType,
                                uint8_t              roaResult,
                                uint8_t              bgpsecResult,
                                uint8_t              aspaResult,
                                void* userPtr);
extern void signaturesReady(SRxUpdateID updId,
								BGPSecCallbackData* data,
                                void* userPtr);
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
	"strconv"
	"strings"
	"unsafe"

	//_ "github.com/osrg/gobgp/table"
	_ "os"

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

//export Go_ValidationReady
func Go_ValidationReady(updateID C.SRxUpdateID, localID C.uint32_t, valType C.ValidationResultType, roaResult C.uint8_t, bgpsecResult C.uint8_t, aspaResult C.uint8_t, userPtr unsafe.Pointer) C.bool {
	log.Info("Called Go_ValidationReady")
	SyncEasyCallback()
	return C.bool(false)
}

/*//export signaturesReady
func signaturesReady(updId C.SRxUpdateID, data &(C.BGPSecCallbackData), userPtr unsafe.Pointer) {
	log.Info("signature callback from srx proxy")
}*/

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
	// extracting the propagated prefix
	prefix_len := 0
	prefix_addr := net.ParseIP("0.0.0.0")
	for _, path := range e.PathList {
		path_string := path.String()
		words := strings.Fields(path_string)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmp_pref, _ := strconv.Atoi(word[j+1:])
					prefix_len = tmp_pref
					prefix_addr = net.ParseIP(word[:j])
				}
			}
		}
	}
	log.Info("Connection Status")
	log.Info(C.isConnected(&am.Proxy))

	// Preparing the proxy
	proxy := (*C.SRxProxy)(C.malloc(C.sizeof_SRxProxy))
	proxy = &am.Proxy

	// Preparing the defaultResult
	defaultResult := (*C.SRxDefaultResult)(C.malloc(C.sizeof_SRxDefaultResult))

	var Res C.SRxResultSource = 3
	var test C.SRxResult
	test.roaResult = 0
	test.bgpsecResult = 0
	test.aspaResult = 0
	defaultResult.resSourceROA = Res
	defaultResult.resSourceBGPSEC = Res
	defaultResult.resSourceASPA = Res
	defaultResult.result = test

	// Preparing the Prefix
	px := &IPAddress{
		Version: 4,
		V4:      [16]byte{},
	}

	prefix := (*C.IPPrefix)(C.malloc(C.sizeof_IPPrefix))

	pxip := prefix_addr
	copy(px.V4[:], pxip)
	px.Pack(unsafe.Pointer(prefix))
	px.V4[11] = 0
	px.V4[10] = 0

	prefix.ip.addr = [16]byte(px.V4)
	prefix.ip.version = C.uint8_t(px.Version)
	prefix.ip.version = C.uint8_t(prefix_len)

	// Preparing the asPathList
	as_int, _ := strconv.Atoi(e.PathList[0].GetAsString())
	var asPathList C.SRxASPathList
	working_path := e.PathList
	var testing_1 C.ASSEGMENT
	testing_1.asn = C.uint(as_int)
	asPathList.length = C.uchar((len(working_path)))
	asPathList.segments = &testing_1
	asPathList.asType = 2
	asPathList.asRelationship = 1

	// Preparing BGPSec data
	go_bgpsec := (*C.BGPSecData)(C.malloc(C.sizeof_BGPSecData))
	var number1 C.uchar = 1
	var number2 C.uint = 1
	go_bgpsec.numberHops = 1
	go_bgpsec.asPath = &number2
	go_bgpsec.attr_length = 1
	go_bgpsec.afi = 1
	go_bgpsec.safi = 1
	go_bgpsec.reserved = 1
	go_bgpsec.local_as = 1
	go_bgpsec.bgpsec_path_attr = &number1

	C.verifyUpdate(proxy, 0, true, true, true, defaultResult, prefix, C.uint(as_int), go_bgpsec, asPathList)

	//C.free(unsafe.Pointer(proxy))
	//C.free(unsafe.Pointer(defaultResult))
	//C.free(unsafe.Pointer(prefix))
	//C.free(unsafe.Pointer(go_bgpsec))
	//C.free(unsafe.Pointer(asPathList))
	//log.Info("Trying new things")
	//tt := C.processPackets(proxy)
}

//type ValidationReady func(updateID SRxUpdateID, localID uint32, valType ValidationResultType, roaResult uint8, bgpsecResult uint8, aspaResult uint8, userPtr unsafe.Pointer) bool

func NewASPAManager(as uint32) (*aspaManager, error) {
	log.Info("+---------------------------------------+")
	log.Info("Creating New ASPA Manager. AS:")
	log.Info(as)
	log.Info("AS would be used for Proxy Creation. Manually forcing differnt ASN")
	go_proxy := C.createSRxProxy(C.closure(C.Go_ValidationReady), C.closure(C.SyncEasyCallback), C.closure(C.SyncEasyCallback), C.closure(C.SrxCommEasyCallback), 1, C.uint(65001), nil)
	log.Info("Created Proxy:")
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

func (g *IPAddress) Pack(out unsafe.Pointer) {

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, g)
	l := buf.Len()
	o := (*[1 << 20]C.uchar)(out)

	for i := 0; i < l; i++ {
		b, _ := buf.ReadByte()
		o[i] = C.uchar(b)
	}
}

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
