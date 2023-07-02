package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	//_ "github.com/osrg/gobgp/table"
	_ "os"

	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
)

type rpkiManager struct {
	AS        int
	ID        int
	Proxy     Go_Proxy
	Server    *BgpServer
	Updates   []*srx_update
	StartTime time.Time
	Resets    int
}

// Callback function: The proxy can call this function when the SRx-Server sends a verify notify
// Input is a raw string containing the message from the server and a pointer to the rpkimanager
func handleVerifyNotify(input string, rm rpkiManager) {
	log.Debug(input)

	// result type (ASPA, AS-Cones, ..) from the SRx-Server
	result_type := input[2:4]

	// ID assigned by the SRx-Server
	update_identifer := input[len(input)-8:]

	// Token assigned by the RPKI manager
	request_token := input[len(input)-16 : len(input)-8]

	// Actual validation result 
	result := input[8:10]
	log.Debug("+----------------------------------------+")
	log.Debug("Update identifier: ", update_identifer)
	log.Debug("Request Token:     ", request_token)
	log.Debug("Cached Updates:    ", len(rm.Updates))
	log.Debug("Result before:     ", result)

	// Iterating through all stores updates to find the matching one 
	for i, update := range rm.Updates {
		log.Debug("ID:    ", update.local_id)
		log.Debug("SRx-ID:", update.srx_id)
		loc_ID := fmt.Sprintf("%08X", update.local_id)

		// Found the correct update -> set SRxID 
		if strings.ToLower(loc_ID) == strings.ToLower(request_token) {
			log.Debug("Path for Update:   ", update.fsmMsg.PathList)
			log.Debug("In if Statement")
			log.Debug("Changing Srx ID of update")
			update.srx_id = update_identifer
			log.Debug("srx ID:            ", update.srx_id)
			log.Debug("+----------------------------------------+")
			return
		}

		// Found the matching token -> process result
		if update.srx_id == update_identifer {
			log.Debug("Result for update: ", result)
			if result_type == "04" {
				log.Debug("Received new information for aspa validation.")
				num, err := strconv.ParseInt(result[1:], 10, 64)
				log.Debug("Time needed: ", time.Since(update.time))
				if err != nil {
					fmt.Println("Conversion error:", err)
					return
				}

				// Valid update
				if result == "00" {
					log.Debug("Adding Update")

					// Process the BGP update 
					rm.Server.ProcessValidUpdate(update.peer, update.fsmMsg, update.bgpMsg)
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					update.aspa = int(num)
					return
				} else {
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					return
				}
			}
		}

	}
}

// Server send Sync message and Proxy responds with all cached updates
func (rm *rpkiManager) handleSyncCallback() {
	log.Debug("in sync callback function")
	for _, Updates := range rm.Updates {
		log.Debug("Requesting Validation for Update ", Updates.local_id)
		rm.validate(Updates.peer, Updates.bgpMsg, Updates.fsmMsg)
	}
}

// Create a Validation message for an incoming BGP UPDATE message
// inputs: BGP peer, the message and messag data
func (rm *rpkiManager) validate(peer *peer, m *bgp.BGPMessage, e *fsmMsg) {
	var updates_to_send []string

	// Iterate through all paths inside the BGP UPDATE message
	for _, path := range e.PathList {
		// Create new SRxUpdate for each path
		update := srx_update{
			local_id: rm.ID,
			srx_id:   "",
			peer:     peer,
			fsmMsg:   e,
			bgpMsg:   m,
			path:     2,
			origin:   2,
			aspa:     2,
			ascones:  2,
			time:     time.Now(),
		}
		// Create new message for each path
		vm := VerifyMessage{
			PDU:                   "03",
			OriginResultSoruce:    "01",
			PathResultSoruce:      "01",
			ASPAResultSoruce:      "01",
			reserved:              "00",
			ASPathType:            "02",
			ASRelationType:        "04",
			Length:                "00000044",
			origin_default_result: "03",
			path_default_result:   "03",
			aspa_default_result:   "03",
			prefix_len:            "18",
			request_token:         fmt.Sprintf("%08X", update.local_id),
			prefix:                "00000000",
			origin_AS:             "0000fdec",
			length_path_val_data:  "00000008",
			bgpsec_length:         "0000",
			afi:                   "0000",
			safi:                  "00",
			prefix_len_bgpsec:     "00",
			ip_pre_add_byte_a:     "00000000",
			ip_pre_add_byte_b:     "00000000",
			ip_pre_add_byte_c:     "00000000",
			ip_pre_add_byte_d:     "00000000",
			local_as:              fmt.Sprintf("%08X", rm.AS),
			as_path_list:          "",
		}
		log.Info("Time since Start:", time.Since(rm.StartTime))
		if rm.Server.bgpConfig.Global.Config.ASPA {
			log.Debug("ASPA")
			vm.Flags = "84"
			vm.reserved = "00"
			vm.aspa_default_result = "03"
			vm.ASPAResultSoruce = "01"
		} else if rm.Server.bgpConfig.Global.Config.ASCONES {
			log.Debug("ASCones")
			vm.Flags = "88"
			vm.reserved = ""
			vm.aspa_default_result = "0303"
			vm.ASPAResultSoruce = "0101"

		}
		as_list := path.GetAsList()
		for _, asn := range as_list {
			hexValue := fmt.Sprintf("%08X", asn)
			vm.as_path_list += hexValue

		}
		prefix_len := 0
		prefix_addr := net.ParseIP("0.0.0.0")
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
		tmp := hex.EncodeToString(prefix_addr)
		vm.prefix = tmp[len(tmp)-8:]
		vm.prefix_len = strconv.FormatInt(int64(prefix_len), 16)
		vm.origin_AS = fmt.Sprintf("%08X", as_list[len(as_list)-1])
		vm.num_of_hops = fmt.Sprintf("%04X", path.GetAsPathLen())
		tmp_int := 4 * path.GetAsPathLen()
		//vm.Length = fmt.Sprintf("%08X", 61+tmp_int)
		vm.Length = fmt.Sprintf("%08X", 60+tmp_int)
		vm.length_path_val_data = fmt.Sprintf("%08X", tmp_int)
		vm.origin_AS = fmt.Sprintf("%08X", path.GetSourceAs())

		if log.GetLevel() == log.DebugLevel {
			printValMessage(vm)
		}
		updates_to_send = append(updates_to_send, structToString(vm))
		rm.Updates = append(rm.Updates, &update)
		rm.ID = (rm.ID % 10000) + 1

		log.Info("Total Updates:", rm.ID, "/", rm.Resets)
	}

	// call proxy function to send message to SRx-Server for each update path
	for _, str := range updates_to_send {
		validate_call(&rm.Proxy, str)
	}
}

// VS Code Test
// Create new RPKI manager instance 
// Input: pointer to BGPServer 
func NewRPKIManager(s *BgpServer) (*rpkiManager, error) {
	rm := &rpkiManager{
		AS:        int(s.bgpConfig.Global.Config.As),
		Server:    s,
		ID:        1,
		Updates:   make([]*srx_update, 0),
		StartTime: time.Now(),
		Resets:    0,
	}
	return rm, nil
}

func (rm *rpkiManager) SetServer(s *BgpServer) error {
	log.WithFields(log.Fields{
		"new Server": s,
	}).Debug("Changing RPKI Manager BGP Server")
	if rm.Server != nil {
		return fmt.Errorf("Server was already configured")
	}
	rm.Server = s
	return nil
}

// Parses the IP address of the SRx-Server
// Proxy can establish a connection with the SRx-Server and sends a hello message 
// Thread mandatory to keep proxy alive during runtime 
func (rm *rpkiManager) SetSRxServer(ip string) error {
	var wg sync.WaitGroup
	wg.Add(1)
	rm.Proxy = createSRxProxy(ip)
	go proxyBackgroundThread(rm, &wg)
	return nil
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

func printValMessage(vm VerifyMessage) {
	log.Debug("+----------------------------------+")
	log.Debug("PDU:                   ", vm.PDU)
	log.Debug("Flags:                 ", vm.Flags)
	log.Debug("OriginResultSoruce:    ", vm.OriginResultSoruce)
	log.Debug("PathResultSoruce:      ", vm.PathResultSoruce)
	log.Debug("ASPAResultSoruce:      ", vm.ASPAResultSoruce)
	log.Debug("reserved:              ", vm.reserved)
	log.Debug("ASPathType:            ", vm.ASPathType)
	log.Debug("ASRelationType:        ", vm.ASRelationType)
	log.Debug("Length:                ", vm.Length)
	log.Debug("origin_default_result: ", vm.origin_default_result)
	log.Debug("path_default_result:   ", vm.path_default_result)
	log.Debug("aspa_default_result:   ", vm.aspa_default_result)
	log.Debug("prefix_len:            ", vm.prefix_len)
	log.Debug("request_token:         ", vm.request_token)
	log.Debug("prefix:                ", vm.prefix)
	log.Debug("origin_AS:             ", vm.origin_AS)
	log.Debug("length_path_val_data:  ", vm.length_path_val_data)
	log.Debug("num_of_hops:           ", vm.num_of_hops)
	log.Debug("bgpsec_length:         ", vm.bgpsec_length)
	log.Debug("afi:                   ", vm.afi)
	log.Debug("safi:                  ", vm.safi)
	log.Debug("prefix_len_bgpsec:     ", vm.prefix_len_bgpsec)
	log.Debug("ip_pre_add_byte_a:     ", vm.ip_pre_add_byte_a)
	log.Debug("ip_pre_add_byte_b:     ", vm.ip_pre_add_byte_b)
	log.Debug("ip_pre_add_byte_c:     ", vm.ip_pre_add_byte_c)
	log.Debug("ip_pre_add_byte_d:     ", vm.ip_pre_add_byte_d)
	log.Debug("local_as:              ", vm.local_as)
	log.Debug("as_path_list:          ", vm.as_path_list)
	log.Debug("path_attribute:        ", vm.path_attribute)
	log.Debug("+----------------------------------+")
}
