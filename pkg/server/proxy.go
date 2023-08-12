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
func createSRxProxy(AS int, ip string) Go_Proxy {
	var wg sync.WaitGroup
	wg.Add(1)
	pr := Go_Proxy{
		ASN: AS,
		IP:  ip,
	}
	pr.connectToSrxServer(ip)
	sendHello(pr)
	return pr
}

// Establish a TCP connection with the SRx-Server
// If no IP is provided, the proxy tries to reach localhost:17900
func (proxy *Go_Proxy) connectToSrxServer(ip string) {
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

func (proxy *Go_Proxy) connectionStatus() bool {
	conn := proxy.con
	_, err := conn.Write([]byte("Ping"))
	if err != nil {
		log.Debug("Lost TCP Connection:", err)
		return false
	}
	log.Debug("TCP Connection still active.")
	return true
}

func (proxy *Go_Proxy) proxyBackgroundThread(rm *rpkiManager, wg *sync.WaitGroup) {
	defer wg.Done()
	con := rm.Proxy.con
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
		processInput(rm, serverResponse, wg)
		log.Debug("Server Input: ", serverResponse)
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
	PDU := st[:2]
	if PDU == HelloRepsonsePDU {
		log.Debug("Received Hello Response")
		if len(st) > 32 {
			log.Debug("More than just the hello message")
			wg.Add(1)
			processInput(rm, st[32:], wg)
		}
	}
	if PDU == SyncMessagePDU {
		log.Debug("Received Sync Request")
		rm.handleSyncCallback()
		if len(st) > 24 {
			wg.Add(1)
			processInput(rm, st[24:], wg)
		}
	}
	if PDU == VerifyNotifyPDU {
		log.Debug("Processing Validation Input")
		if len(st) > 40 {
			handleVerifyNotify(st[:40], *rm)
			wg.Add(1)
			processInput(rm, st[40:], wg)
		} else {
			handleVerifyNotify(st, *rm)
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
