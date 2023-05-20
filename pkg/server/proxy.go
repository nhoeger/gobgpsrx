package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

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
}

func CallbackForValidationResults(input string) {
	fmt.Println("Received a validation callback")
	fmt.Println(input)
}

func validate(proxy Go_Proxy, input string) {
	connection := proxy.con
	bytes, err := hex.DecodeString(input)
	_, err = connection.Write(bytes)
	if err != nil {
		log.Fatal(err)
	}
}

func (*Go_Proxy) setAS(proxy Go_Proxy, ASN int) {
	proxy.ASN = ASN
}

func connectToSrxServer() net.Conn {
	server := "localhost:17900"
	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatal("Connection to Server failed!")
	}
	return conn
}

func sendHello(proxy Go_Proxy) {
	bytes, err := hex.DecodeString("000003000000000000000014000000010000fde9" + strconv.FormatInt(int64(proxy.ASN), 16))
	_, err = proxy.con.Write(bytes)
	if err != nil {
		log.Info(err)
	}
}

func proxyBackgroundThread(rm rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info(err)
		}
		server_response := hex.EncodeToString(response[:n])
		if strings.Contains(server_response, HelloMessage) {
			log.Info("Received Hello Response")
		}

		if strings.Contains(server_response, SyncMessage) {
			log.Info("Received Sync Request")
			rm.handleSyncCallback()
		}

		if server_response[:2] == "06" {
			log.Info("Received Verify Notify")
			rm.handleVerifyNotify(server_response)
		}
		//fmt.Println("Server:", server_response)
	}
}
