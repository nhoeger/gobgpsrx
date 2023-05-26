package server

import (
	"encoding/hex"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	HelloMessage      = "01000300000000000000001000000001"
	GoodByeMessage    = "002"
	ValidationMessage = "003"
	SyncMessage       = "0a000000000000000000000c"
)

type Verification_Request struct {
	PDU [1]byte
	//TODO: extend
}

type Go_Proxy struct {
	con          net.Conn
	ASN          int
	Identifier   int
	InputBuffer  []string
	OutputBuffer []string
	lastCall     time.Time
}

func validate_call(proxy *Go_Proxy, input string) {
	proxy.InputBuffer = append(proxy.InputBuffer, input)
}

func (*Go_Proxy) setAS(proxy Go_Proxy, ASN int) {
	proxy.ASN = ASN
}

func connectToSrxServer() net.Conn {
	server := "172.17.0.3:17900"
	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatal("Connection to Server failed!")
	}
	return conn
}

func sendHello(proxy *Go_Proxy) {
	bytes, _ := hex.DecodeString("000003000000000000000014000000010000fde9" + strconv.FormatInt(int64(proxy.Identifier), 16))
	_, err := proxy.con.Write(bytes)
	if err != nil {
		log.Fatal("Sending Hello Failed: ", err)
	}
}

func createProxy() Go_Proxy {
	connection := connectToSrxServer()
	pr := Go_Proxy{
		con: connection,
	}
	return pr
}

func proxyBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	rm.Proxy.lastCall = time.Now()
	defer wg.Done()
	rm.Proxy.Identifier = rm.AS
	sendHello(&rm.Proxy)
	wg.Add(2)
	go senderBackgroundThread(rm, wg)
	go receiverBackgroundThread(rm, wg)
}

func senderBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
	startTime := time.Now()
	for {
		for _, elem := range rm.Proxy.InputBuffer {
			elapsed := time.Since(startTime)
			if elapsed >= 2*time.Second {
				bytes, _ := hex.DecodeString(elem)
				_, _ = con.Write(bytes)
				startTime = time.Now()
				rm.Proxy.InputBuffer = rm.Proxy.InputBuffer[1:]
			}
		}

	}
}

func receiverBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info(err)
		}
		server_response := hex.EncodeToString(response[:n])
		if server_response != "" {
			log.Info("Server:      ", server_response)
			rm.Proxy.OutputBuffer = append(rm.Proxy.OutputBuffer, server_response)
		}
		for len(rm.Proxy.OutputBuffer) > 0 {
			processInput(rm)
		}
		log.Debug("len: ", len(rm.Proxy.OutputBuffer))
	}
}

func processInput(rm *rpkiManager) {
	elem := rm.Proxy.OutputBuffer[0]
	if elem[:2] == "01" {
		log.Debug("Received Hello Response")
		if len(elem) > 32 {
			log.Debug("More than just the hello message")
			rm.Proxy.OutputBuffer[0] = elem[32:]
		} else {
			rm.Proxy.OutputBuffer = rm.Proxy.OutputBuffer[1:]
		}
	}
	if elem[:2] == "0a" {
		log.Debug("Received Sync Request")
		rm.handleSyncCallback()
		if len(elem) > 24 {
			log.Debug("More than just the Sync message")
			rm.Proxy.OutputBuffer[0] = elem[24:]
		} else {
			rm.Proxy.OutputBuffer = rm.Proxy.OutputBuffer[1:]
		}
	}
	if elem[:2] == "06" {
		log.Debug("Processing Validation Input")
		if len(elem) > 40 {
			handleVerifyNotify(elem[:40], *rm)
			rm.Proxy.OutputBuffer[0] = elem[40:]
		} else {
			handleVerifyNotify(elem, *rm)
			rm.Proxy.OutputBuffer = rm.Proxy.OutputBuffer[1:]
		}
	}
}
