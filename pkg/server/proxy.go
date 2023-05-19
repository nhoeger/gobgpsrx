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
	SyncMessage       = "004"
)

type Go_Proxy struct {
	con        net.Conn
	ASN        int
	Identifier int
}

func CallbackForValidationResults(input string) {
	fmt.Println("Received a validation callback")
	fmt.Println(input)
}

func validate(proxy Go_Proxy) {
	connection := proxy.con
	bytes2, err := hex.DecodeString("0387030303000201000000410000001800000051000000000000000000000005000100010100010000000000000000000000000000000000000000010100000001")
	_, err = connection.Write(bytes2)
	if err != nil {
		log.Fatal(err)
	}
}

func createSRxProxy() Go_Proxy {
	var wg sync.WaitGroup
	wg.Add(1)
	tmp := connectToSrxServer()
	pr := Go_Proxy{
		con:        tmp,
		ASN:        0,
		Identifier: 65001,
	}
	sendHello(pr)
	go proxyBackgroundThread(pr.con, &wg)
	return pr
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

func proxyBackgroundThread(con net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
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

		if server_response[:2] == "06" {
			log.Info("Received Verify Notify")
			handleVerifyNotify(server_response)
		}
		fmt.Println("Server:", server_response)
	}
}
