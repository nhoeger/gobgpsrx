package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	//_ "github.com/osrg/gobgp/table"
	_ "os"

	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
)

type rpkiManager struct {
	AS      int
	ID      int
	Proxy   Go_Proxy
	Server  *BgpServer
	Updates []srx_update
}

func handleVerifyNotify(input string, rm rpkiManager) {
	log.Debug("+----------------------------------------+")
	log.Debug("In verification callback function.")
	log.Debug(input)
	result_type := input[2:4]
	update_identifer := input[len(input)-8:]
	request_token := input[len(input)-16 : len(input)-8]
	result := input[8:10]
	log.Debug("Update identifier: ", update_identifer)
	log.Debug("Request Token:     ", request_token)
	log.Debug("Cached Updates:    ", len(rm.Updates))
	for _, update := range rm.Updates {
		log.Debug("local ID (dez):    ", update.local_id)
		log.Debug("local ID (hex):    ", fmt.Sprintf("%08X", update.local_id))
		if fmt.Sprintf("%08X", update.local_id) == request_token {
			log.Debug("In if Statement")
			log.Debug("Changing Srx ID of update")
			update.srx_id = update_identifer
			log.Debug("srx ID:            ", update.srx_id)
		}
		if result_type == "04" {
			log.Debug("Received new information for aspa validation.")
			num, err := strconv.ParseInt(result[1:], 10, 64)
			if err != nil {
				fmt.Println("Conversion error:", err)
				return
			}
			update.aspa = int(num)
			//rm.Server.ProcessValidUpdate(update.peer, update.fsmMsg, update.bgpMsg)
		}
	}
	log.Debug("+----------------------------------------+")
}

// Server send Sync message and Proxy responds with all cached updates
func (rm *rpkiManager) handleSyncCallback() {
	log.Debug("in sync callback function")
	//TODO: Implementation
	for _, Updates := range rm.Updates {
		log.Info("Update: ", Updates.local_id)
	}
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

func (rm *rpkiManager) validate(peer *peer, m *bgp.BGPMessage, e *fsmMsg, aspa bool, ascones bool) {
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
	}
	rm.ID++

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
	as_relation_type := "00"
	length := "00000044"
	origin_default_result := "03"
	path_default_result := "03"
	aspa_default_result := "03"
	prefix_length := "18"
	request_token := fmt.Sprintf("%08X", update.local_id)
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
	as_path_list := ""

	for _, path := range e.PathList {
		as_list := path.GetAsList()
		for _, asn := range as_list {
			hexValue := fmt.Sprintf("%08X", asn)
			as_path_list += hexValue
			log.Debug("AS path list:   ", as_path_list)
		}

		num_of_hops = fmt.Sprintf("%04X", path.GetAsPathLen())
		tmp_int := 4 * path.GetAsPathLen()
		length = fmt.Sprintf("%08X", 60+tmp_int)
		length_path_val_data = fmt.Sprintf("%08X", tmp_int)
		origin_AS := fmt.Sprintf("%08X", path.GetSourceAs())
		log.Debug("number of hops: ", num_of_hops)
		log.Debug("Source AS:      ", origin_AS)
		log.Debug("length:         ", length)
		log.Debug("length val data:", length_path_val_data)
	}

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

	tmp := hex.EncodeToString(prefix_addr)
	ipv4_address = tmp[len(tmp)-8:]
	prefix_length = strconv.FormatInt(int64(prefix_len), 16)
	local_as = fmt.Sprintf("%08X", rm.AS)
	log.Debug("local AS:       ", local_as)
	log.Debug("address:        ", ipv4_address)
	log.Debug("size:           ", prefix_length)

	output_string += flags + origin_result_source + path_result_source + aspa_result_source
	output_string += reserved + as_path_type + as_relation_type + length + origin_default_result
	output_string += path_default_result + aspa_default_result + prefix_length + request_token
	output_string += ipv4_address + origin_as + length_path_val_data + num_of_hops + bgpsec_length
	output_string += afi + safi + pre_len + ip_pre_add_byte_a + ip_pre_add_byte_b + ip_pre_add_byte_c
	output_string += ip_pre_add_byte_d + local_as + as_path_list

	validate_call(rm.Proxy, output_string)
	rm.Updates = append(rm.Updates, update)
}

func NewRPKIManager(as uint32) (*rpkiManager, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	pr := createProxy(int(as))
	rm := &rpkiManager{
		AS:      int(as),
		Proxy:   pr,
		ID:      1,
		Updates: make([]srx_update, 0),
	}
	go proxyBackgroundThread(rm, &wg)
	return rm, nil
}

func (rm *rpkiManager) SetServer(s *BgpServer) {
	rm.Server = s
}
