package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

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

type rpkiManager struct {
	AS      int
	Proxy   Go_Proxy
	ID      int
	Updates []srx_update
}

func handleVerifyNotify(input string) {
	fmt.Println("Handling verify notify")
	result_type := input[2:4]
	result := input[8:10]
	if result_type == "87" {
		log.Info("Setting deault value for newest validation request.")
	}
	fmt.Println("Result Type: ", result_type)
	fmt.Println("Result: ", result)
}

func (rm *rpkiManager) SetAS(as uint32) error {
	log.WithFields(log.Fields{
		"new ASN": as,
		"old ASN": rm.AS,
	}).Debug("Changing RPKI Manager ASN")
	if rm.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	rm.AS = int(as)
	return nil
}

func (rm *rpkiManager) validate(e *fsmMsg, aspa bool, ascones bool) {
	output_string := "03"
	flags := "00"
	if aspa {
		flags = "84"
	} else {
		flags = "00"
	}
	origin_result_source := "03"
	path_result_source := "03"
	aspa_result_source := "03"
	reserved := "00"
	as_path_type := "02"
	as_relation_type := "01"
	length := "00000044"
	origin_default_result := "00"
	path_default_result := "00"
	aspa_default_result := "00"
	preifx_length := "18"
	request_token := "00000001"
	ipv4_address := "07030700"
	origin_as := "0000fdec"
	length_path_val_data := "00000008"
	num_of_hops := "0002"
	bgpsec_length := "0000"
	afi := "0000"
	safi := "00"
	pre_len := "00"
	ip_pre_add_byte_a := "00000000"
	ip_pre_add_byte_b := "00000000"
	ip_pre_add_byte_c := "00000000"
	ip_pre_add_byte_d := "00000000"
	local_as := "00000000"
	as_path_list := "00001dfc0000fded"
	log.Info("Validation")
	log.Info("Message: ", e)

	//log.Info("fsm: ", e.fsm)
	//log.Info("payload: ", e.payload)
	//log.Info("timestamp: ", e.timestamp)
	//log.Info("MsgData: ", e.MsgData)
	//log.Info("MsgSrc: ", e.MsgSrc)
	//log.Info("PathList: ", e.PathList)

	// start validation

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
	log.Debug("Prefix: ", prefix_addr, "/", prefix_len)
	// IP-Adresse in Hex-Wert umwandeln
	ipv4_address = fmt.Sprintf("%02x%02x%02x%02x", prefix_addr[0], prefix_addr[1], prefix_addr[2], prefix_addr[3])

	// Preparing the Prefix
	px := &IPAddress{
		Version: 4,
		V4:      [16]byte{},
	}

	pxip := prefix_addr
	copy(px.V4[:], pxip)
	px.V4[0] = px.V4[12]
	px.V4[1] = px.V4[13]
	px.V4[2] = px.V4[14]
	px.V4[11] = 0
	px.V4[10] = 0
	px.V4[12] = 0
	px.V4[13] = 0
	px.V4[14] = 0

	// Preparing the asPathList
	/*assegments := []ASSEGMENT{
		{asn: 65004},
		{asn: 65005},
	}

	cArray := (*C.ASSEGMENT)(C.malloc(C.size_t(len(assegments)) * C.sizeof_ASSEGMENT))
	//cArray = assegments

	for i, seg := range assegments {
		log.Info("Iterating...")
		ptr := (*C.ASSEGMENT)(unsafe.Pointer(uintptr(cArray) + uintptr(i)*C.sizeof_ASSEGMENT))
		*ptr = C.ASSEGMENT(seg)
	}*/ /*

		as_int, _ := strconv.Atoi(e.PathList[0].GetAsString())
		var asPathList C.SRxASPathList
		working_path := e.PathList
		var testing_1 C.ASSEGMENT
		testing_1.asn = C.uint(as_int)
		asPathList.length = C.uchar((len(working_path)))
		asPathList.segments = &testing_1
		asPathList.asType = 2
		asPathList.asRelationship = 1
		/*

			// allocate memory for the C array of ASSEGMENTs
			cArray := C.malloc(C.size_t(len(assegments)) * C.sizeof_ASSEGMENT)
			ptr := (*C.ASSEGMENT)(unsafe.Pointer(uintptr(cArray) + C.sizeof_ASSEGMENT))

			log.Info(cArray)
			log.Info((*C.ASSEGMENT)(cArray))
			// copy the Go ASSEGMENTs to the C array
			for i, seg := range assegments {
				log.Info("Iterating")
				log.Info(i)
				log.Info(seg)
				ptr = (*C.ASSEGMENT)(unsafe.Pointer(uintptr(cArray) + uintptr(i)*C.sizeof_ASSEGMENT))
				*ptr = C.ASSEGMENT(seg)
			}
			log.Info(cArray)
			log.Info((*C.ASSEGMENT)(cArray))

			pathList := C.SRxASPathList{
				length:         C.uchar(len(assegments)),
				segments:       (*C.ASSEGMENT)(cArray),
				asType:         2,
				asRelationship: 1,
			}
			log.Info("PathList:")
			log.Info(pathList.length)
			log.Info(pathList.segments)
			log.Info(pathList.segments.asn)
			log.Info(pathList.asType)
			log.Info(pathList.asRelationship)

			as_int, _ := strconv.Atoi(e.PathList[0].GetAsString())
			var asPathList C.SRxASPathList
			working_path := e.PathList
			testing_1 := (*C.ASSEGMENT)(C.malloc(C.sizeof_ASSEGMENT))
			testing_1.asn = C.uint(as_int)
			asPathList.length = C.uchar((len(working_path)))
			asPathList.segments = testing_1
			asPathList.asType = 2
			asPathList.asRelationship = 1*/

	// Preparing BGPSec data
	/*
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

		log.Info(prefix.ip.addr)
		log.Info(prefix.ip.version)
		log.Info(prefix.length)
		log.Info("-+-+-+")
		log.Info("Relationship")
		log.Info(asPathList.asRelationship)
		log.Info("ASType")
		log.Info(asPathList.asType)
		log.Info("ASN")
		log.Info(asPathList.segments.asn)
		log.Info("Length")
		log.Info(asPathList.length)
		log.Info("Segments")
		log.Info(asPathList.segments)

		if aspa {
			C.verifyUpdate(&rm.Proxy, C.uint(rm.ID), false, false, true, defaultResult, prefix, C.uint(as_int), go_bgpsec, asPathList)
		}

		/*if ascones {
			C.verifyUpdate(&rm.Proxy, C.uint(rm.ID), false, false, true, defaultResult, prefix, C.uint(as_int), go_bgpsec, asPathList)
		}*/
	/*
		update_test := NewSrxUpdate(rm.ID)
		rm.ID++
		rm.Updates = append(rm.Updates, update_test)
		C.free(unsafe.Pointer(defaultResult))
		C.free(unsafe.Pointer(prefix))
		C.free(unsafe.Pointer(go_bgpsec))
		log.Info("+---------------------------------------+")*/

	output_string += flags + origin_result_source + path_result_source + aspa_result_source
	output_string += reserved + as_path_type + as_relation_type + length + origin_default_result
	output_string += path_default_result + aspa_default_result + preifx_length + request_token
	output_string += ipv4_address + origin_as + length_path_val_data + num_of_hops + bgpsec_length
	output_string += afi + safi + pre_len + ip_pre_add_byte_a + ip_pre_add_byte_b + ip_pre_add_byte_c
	output_string += ip_pre_add_byte_d + local_as + as_path_list
	log.Debug(output_string)

	validate(rm.Proxy, output_string)
}

func NewRPKIManager(as uint32) (*rpkiManager, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	connection := connectToSrxServer()
	pr := Go_Proxy{
		con:        connection,
		ASN:        0,
		Identifier: 65001,
	}
	sendHello(pr)
	go proxyBackgroundThread(pr.con, &wg)

	rm := &rpkiManager{
		AS:      int(as),
		Proxy:   pr,
		ID:      0,
		Updates: make([]srx_update, 0),
	}
	return rm, nil
}
