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
	Updates []*srx_update
}

func handleVerifyNotify(input string, rm rpkiManager) {
	//log.Info("+----------------------------------------+")
	//log.Info("In verification callback function.")
	log.Info(input)
	result_type := input[2:4]
	update_identifer := input[len(input)-8:]
	request_token := input[len(input)-16 : len(input)-8]
	result := input[8:10]
	//	if result != "00" {
	//		log.Info("Not a valid update")
	//	return
	//}
	log.Info("+----------------------------------------+")
	log.Info("Update identifier: ", update_identifer)
	log.Info("Request Token:     ", request_token)
	log.Info("Cached Updates:    ", len(rm.Updates))
	log.Info("Result before:     ", result)
	for i, update := range rm.Updates {
		log.Info("ID:    ", update.local_id)
		log.Info("SRx-ID:", update.srx_id)
		loc_ID := fmt.Sprintf("%08X", update.local_id)

		//log.Debug("local ID (dez):    ", update.local_id)
		//log.Info("Reqeust Token:     ", request_token)
		//log.Info("local ID (hex):    ", fmt.Sprintf("%08X", update.local_id))
		if strings.ToLower(loc_ID) == strings.ToLower(request_token) {
			log.Info("Path for Update:   ", update.fsmMsg.PathList)
			log.Info("In if Statement")
			log.Info("Changing Srx ID of update")
			update.srx_id = update_identifer
			log.Info("srx ID:            ", update.srx_id)
			log.Info("+----------------------------------------+")
			return
		}
		//log.Info("BOOl 1", (request_token == "00000000"))
		//log.Info("BOOl 2", (update.srx_id == update_identifer))
		if request_token == "00000000" && update.srx_id == update_identifer {

			log.Info("Path for Update:   ", update.fsmMsg.PathList)
			log.Info("Result in if: ", result)
			if result_type == "04" {
				log.Debug("Received new information for aspa validation.")
				num, err := strconv.ParseInt(result[1:], 10, 64)
				if err != nil {
					fmt.Println("Conversion error:", err)
					return
				}
				if result == "00" {
					log.Debug("Adding Update")
					rm.Server.ProcessValidUpdate(update.peer, update.fsmMsg, update.bgpMsg)
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					log.Info("+----------------------------------------+")
					return
				}
				if result == "02" {
					log.Info("Invalid Update detected")
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					log.Info("+----------------------------------------+")
					return
				}
				update.aspa = int(num)
			}
		}

	}
	log.Info("+----------------------------------------+")
}

// Server send Sync message and Proxy responds with all cached updates
func (rm *rpkiManager) handleSyncCallback() {
	log.Debug("in sync callback function")
	for _, Updates := range rm.Updates {
		log.Debug("Requesting Validation for Update ", Updates.local_id)
		rm.validate(Updates.peer, Updates.bgpMsg, Updates.fsmMsg, true, false)
	}
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
	as_relation_type := "04"
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

	validate_call(&rm.Proxy, output_string)
	rm.Updates = append(rm.Updates, &update)
}

func NewRPKIManager(s *BgpServer) (*rpkiManager, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	rm := &rpkiManager{
		AS:      int(s.bgpConfig.Global.Config.As),
		Server:  s,
		Proxy:   createProxy(),
		ID:      1,
		Updates: make([]*srx_update, 0),
	}
	go proxyBackgroundThread(rm, &wg)
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
