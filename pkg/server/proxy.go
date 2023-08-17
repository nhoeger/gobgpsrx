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

type GoSRxProxy struct {
	//client       *RPKIManager
	con                  net.Conn
	conStatus            bool
	ASN                  int
	InputBuffer          []string
	OutputBuffer         []string
	IP                   string
	VerifyNotifyCallback func(*VerifyNotify)
	SyncNotifyCallback   func()
}

// send validation call to SRx-Server
func validate_call(proxy *GoSRxProxy, input string) {
	connection := proxy.con
	bytes2, err := hex.DecodeString(input)
	_, err = connection.Write(bytes2)
	if err != nil {
		log.Fatal(err)
	}

}

// Sends Hello message to SRx-Server
// ASN becomes the identifier of the proxy
func sendHello(proxy GoSRxProxy) {
	hm := HelloMessage{
		PDU:              HelloPDU,
		Version:          "0003",
		reserved:         "00",
		zero:             "00000000",
		length:           "00000014",
		proxy_identifier: "00000001",
		ASN:              "0000" + strconv.FormatInt(int64(proxy.ASN), 16),
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
func createSRxProxy(AS int, ip string, VNC func(*VerifyNotify), SC func()) GoSRxProxy {
	var wg sync.WaitGroup
	wg.Add(1)
	pr := GoSRxProxy{
		ASN:                  AS,
		IP:                   ip,
		VerifyNotifyCallback: VNC,
		SyncNotifyCallback:   SC,
	}
	pr.connectToSrxServer(ip)
	sendHello(pr)
	return pr
}

// Establish a TCP connection with the SRx-Server
// If no IP is provided, the proxy tries to reach localhost:17900
func (proxy *GoSRxProxy) connectToSrxServer(ip string) {
	connectionCounter := 1
	server := "localhost:17900"
	log.Debug("Trying to connect to SRx-Server.")
	log.Debug("SRxServer Address: ", ip)
	if len(ip) != 0 {
		server = ip + ":17900"
	}
	var conn net.Conn
	var err error
	for connectionCounter < 4 {
		connectionCounter += 1
		conn, err = net.Dial("tcp", server)
		if err != nil {
			log.Debug("Connection to Server failed! Trying to connect...")
			time.Sleep(2 * time.Second)
		} else {
			log.Debug("TCP Connection Established")
			proxy.con = conn
			proxy.conStatus = true
			break
		}
	}
	if err != nil {
		log.Fatal("Connection Failed. Please ensure that the SRx-Server is running.")
	}
}

func (proxy *GoSRxProxy) proxyBackgroundThread(wg *sync.WaitGroup) {
	defer wg.Done()
	con := proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info("Lost TCP connection.")
			log.Info(err)
			wg.Add(1)
			proxy.connectToSrxServer(proxy.IP)
			err = nil
			return
		}
		serverResponse := hex.EncodeToString(response[:n])
		wg.Add(1)
		proxy.processInput(serverResponse, wg)
		log.Debug("Server Input: ", serverResponse)
	}
}

// process messages from the SRx-Server according to their PDU field
func (proxy *GoSRxProxy) processInput(st string, wg *sync.WaitGroup) {
	defer wg.Done()
	PDU := st[:2]
	if PDU == HelloRepsonsePDU {
		log.Debug("Received Hello Response")
		if len(st) > 32 {
			log.Debug("More than just the Hello message")
			wg.Add(1)
			proxy.processInput(st[32:], wg)
		}
	}
	if PDU == SyncMessagePDU {
		log.Debug("Received Sync Request")
		proxy.SyncNotifyCallback()
		if len(st) > 24 {
			wg.Add(1)
			proxy.processInput(st[24:], wg)
		}
	}
	if PDU == VerifyNotifyPDU {
		log.Debug("Processing Validation Input")
		if len(st) > 40 {
			proxy.verifyNotifyCallback(st[:40])
			wg.Add(1)
			proxy.processInput(st[40:], wg)
		} else {
			proxy.verifyNotifyCallback(st)
		}
	}
}

// Convert data structures to string before sending
func structToString(data interface{}) string {
	value := reflect.ValueOf(data)
	numFields := value.NumField()
	returnString := ""
	for i := 0; i < numFields; i++ {
		field := value.Field(i)
		returnString += field.String()
	}
	return returnString
}

// Convert the input string into VerifyNotify
// Parse VerifyNotify to RPKIManager
func (proxy *GoSRxProxy) verifyNotifyCallback(input string) {
	vn := VerifyNotify{
		PDU:              input[:2],
		ResultType:       input[2:4],
		OriginResult:     input[4:6],
		PathResult:       input[6:8],
		ASPAResult:       input[8:10],
		ASConesResult:    input[10:12],
		Zero:             input[12:16],
		Length:           input[16:24],
		RequestToken:     input[24:32],
		UpdateIdentifier: input[32:40],
	}
	proxy.VerifyNotifyCallback(&vn)
}
