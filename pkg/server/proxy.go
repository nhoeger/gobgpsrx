package server

import (
	"encoding/hex"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	//HelloMessage      = "01000300000000000000001000000001"
	GoodByeMessage    = "002"
	ValidationMessage = "003"
	SyncMessage       = "0a000000000000000000000c"
)

type VerifyMessage struct {
	PDU                   string
	Flags                 string
	OriginResultSoruce    string
	PathResultSoruce      string
	ASPAResultSoruce      string
	reserved              string
	ASPathType            string
	ASRelationType        string
	Length                string
	origin_default_result string
	path_default_result   string
	aspa_default_result   string
	prefix_len            string
	request_token         string
	prefix                string
	origin_AS             string
	length_path_val_data  string
	num_of_hops           string
	bgpsec_length         string
	afi                   string
	safi                  string
	prefix_len_bgpsec     string
	ip_pre_add_byte_a     string
	ip_pre_add_byte_b     string
	ip_pre_add_byte_c     string
	ip_pre_add_byte_d     string
	local_as              string
	as_path_list          string
	path_attribute        string
}

type HelloMessage struct {
	PDU              string
	Version          string
	reserved         string
	zero             string
	length           string
	proxy_identifier string
	ASN              string
}

type Go_Proxy struct {
	con          net.Conn
	ASN          int
	Identifier   int
	InputBuffer  []string
	OutputBuffer []string
	lastCall     time.Time
}

// send validation call to SRx-Server
func validate_call(proxy *Go_Proxy, input string) {
	connection := proxy.con
	bytes2, err := hex.DecodeString(input)
	_, err = connection.Write(bytes2)
	if err != nil {
		log.Fatal(err)
	}

}


// Sends Hello message to SRx-Server
// ASN becomes the identifier of the proxy 
func sendHello(proxy Go_Proxy) {
	hm := HelloMessage{
		PDU:              "00",
		Version:          "0003",
		reserved:         "00",
		zero:             "00000000",
		length:           "00000014",
		proxy_identifier: "00000001",
		ASN:              "0000" + strconv.FormatInt(int64(proxy.Identifier), 16),
	}
	hexString := structToString(hm)
	log.Info(hexString)
	bytes, _ := hex.DecodeString(hexString)
	_, err := proxy.con.Write(bytes)
	if err != nil {
		log.Fatal("Sending Hello Failed: ", err)
	}
}

// New Proxy instance 
func createSRxProxy(ip string) Go_Proxy {
	var wg sync.WaitGroup
	wg.Add(1)
	tmp := connectToSrxServer(ip)
	pr := Go_Proxy{
		con:        tmp,
		ASN:        0,
		Identifier: 65001,
	}
	sendHello(pr)
	return pr
}

// Establish a TCP connection with the SRx-Server
// If no IP is privided, the proxy tries to reach localhost:17900
func connectToSrxServer(ip string) net.Conn {
	log.Debug("SRxServer Address: ", ip)
	server := "localhost:17900"
	if len(ip) != 0 {
		server = ip + ":17900"
	}
	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatal("Connection to Server failed!")
	}
	return conn
}

func proxyBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info(err)
		}
		server_response := hex.EncodeToString(response[:n])
		wg.Add(1)
		processInput(rm, server_response, wg)
		log.Debug("Server Input: ", server_response)
	}
}

func senderBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
	startTime := time.Now()
	for {
		currentTime := time.Now()
		if currentTime.Sub(startTime) >= 2*time.Second {
			log.Info("Length:", len(rm.Proxy.InputBuffer))
			if len(rm.Proxy.InputBuffer) > 0 {
				bytes, err1 := hex.DecodeString(rm.Proxy.InputBuffer[0])
				_, err2 := con.Write(bytes)
				if err1 != nil {
					log.Fatal("Cannot Convert Message: ", err1)
				}
				if err2 != nil {
					log.Fatal("Cannot Write Bytes: ", err2)
				}
				rm.Proxy.InputBuffer = rm.Proxy.InputBuffer[1:]
			}
			startTime = currentTime
		}

	}
}

// process messages from the SRx-Server according to their PDU field 
func processInput(rm *rpkiManager, st string, wg *sync.WaitGroup) {
	defer wg.Done()
	elem := st
	if elem[:2] == "01" {
		log.Debug("Received Hello Response")
		if len(elem) > 32 {
			log.Debug("More than just the hello message")
			wg.Add(1)
			processInput(rm, elem[32:], wg)
		}
	}
	if elem[:2] == "0a" {
		log.Debug("Received Sync Request")
		rm.handleSyncCallback()
		if len(elem) > 24 {
			wg.Add(1)
			processInput(rm, elem[24:], wg)
		}
	}
	if elem[:2] == "06" {
		log.Debug("Processing Validation Input")
		if len(elem) > 40 {
			handleVerifyNotify(elem[:40], *rm)
			wg.Add(1)
			processInput(rm, elem[40:], wg)
		} else {
			handleVerifyNotify(elem, *rm)
		}
	}
}

func structToString(data interface{}) string {
	value := reflect.ValueOf(data)
	numFields := value.NumField()
	return_string := ""
	for i := 0; i < numFields; i++ {
		field := value.Field(i)
		return_string += field.String()
	}
	return return_string
}
