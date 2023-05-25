package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
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
	con        net.Conn
	ASN        int
	Identifier int
	Buffer     []string
}

func CallbackForValidationResults(input string) {
	fmt.Println("Received a validation callback")
	fmt.Println(input)
}

func validate_call(proxy *Go_Proxy, input string) {
	//connection := proxy.con
	proxy.Buffer = append(proxy.Buffer, input) /*
		bytes, err := hex.DecodeString(input)
		_, err = connection.Write(bytes)
		if err != nil {
			log.Fatal(err)
		}*/
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
	//proxy.Buffer = append(proxy.Buffer, string(bytes))
}

func createProxy() Go_Proxy {
	connection := connectToSrxServer()
	pr := Go_Proxy{
		con: connection,
	}
	return pr
}

func proxyBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	rm.Proxy.Identifier = rm.AS
	sendHello(&rm.Proxy)
	con := rm.Proxy.con
	response := make([]byte, 1024)
	go senderBackgroundThread(rm, wg)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info(err)
		}
		server_response := hex.EncodeToString(response[:n])

		if strings.Contains(server_response, HelloMessage) {
			log.Debug("Received Hello Response")
		}

		if strings.Contains(server_response, SyncMessage) {
			log.Debug("Received Sync Request")
			rm.handleSyncCallback()
		}

		if server_response[:2] == "06" {
			handleMessage(server_response, rm)
		}
		log.Info("Server:", server_response)
	}
}

func senderBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
	startTime := time.Now()
	for {
		for _, elem := range rm.Proxy.Buffer {
			//log.Info("Buffer not empty")
			elapsed := time.Since(startTime)
			if elapsed >= 2*time.Second {
				//log.Info("Lenght of Buffer: ", len(rm.Proxy.Buffer))
				bytes, _ := hex.DecodeString(elem)
				//log.Info("Sending:          ", bytes)
				_, _ = con.Write(bytes)
				startTime = time.Now()
				rm.Proxy.Buffer = rm.Proxy.Buffer[1:]
			}
		}

	}
}

func handleMessage(input string, rm *rpkiManager) {
	if input[:2] == "06" {
		log.Info("Processing Validation Input")
		if len(input) > 40 {
			handleVerifyNotify(input[:40], *rm)
			handleMessage(input[40:], rm)
		} else {
			handleVerifyNotify(input, *rm)
		}
	}
}
