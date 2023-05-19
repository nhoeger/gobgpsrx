package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	//_ "github.com/osrg/gobgp/table"
	_ "os"

	log "github.com/sirupsen/logrus"
)

type rpkiManager struct {
	AS      int
	Proxy   Go_Proxy
	ID      int
	Updates []srx_update
}

func handleVerifyNotify(input string) {
	fmt.Println("Handling verify notify")
	result_type := input[2:4]
	result := input[8:10]
	if result_type == "87" {
		log.Info("Setting deault value for newest validation request.")
	}
	fmt.Println("Result Type: ", result_type)
	fmt.Println("Result: ", result)
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

func (rm *rpkiManager) validate(e *fsmMsg, aspa bool, ascones bool) {
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
	as_relation_type := "01"
	length := "00000044"
	origin_default_result := "00"
	path_default_result := "00"
	aspa_default_result := "00"
	prefix_length := "18"
	request_token := "00000001"
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
	as_path_list := "00001dfc0000fded"
	log.Info("Validation")
	log.Info("Message: ", e)
	log.Info("Message Pathlist: ", e.PathList)

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
	log.Debug("Prefix: ", prefix_addr, "/", prefix_len)

	// IP-Adresse in Hex-Wert umwandeln
	ipv4_address = fmt.Sprintf("%02x%02x%02x%02x", prefix_addr[0], prefix_addr[1], prefix_addr[2], prefix_addr[3])
	prefix_length = strconv.FormatInt(int64(prefix_len), 16)

	local_as = strconv.FormatInt(int64(rm.AS), 16)

	// TODO: AS Path List
	// TODO: Request Token
	// TODO: Number of hops
	// TODO: Origin AS
	output_string += flags + origin_result_source + path_result_source + aspa_result_source
	output_string += reserved + as_path_type + as_relation_type + length + origin_default_result
	output_string += path_default_result + aspa_default_result + prefix_length + request_token
	output_string += ipv4_address + origin_as + length_path_val_data + num_of_hops + bgpsec_length
	output_string += afi + safi + pre_len + ip_pre_add_byte_a + ip_pre_add_byte_b + ip_pre_add_byte_c
	output_string += ip_pre_add_byte_d + local_as + as_path_list
	log.Debug(output_string)
	tmp_string := "0381010101000204000000440303031800000001070307000000fded000000080002000000000000000000000000000000000000000000000000000000001dfc0000fded"
	log.Debug(len(output_string), " und ", len(tmp_string))
	validate(rm.Proxy, tmp_string)

}

func NewRPKIManager(as uint32) (*rpkiManager, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	connection := connectToSrxServer()
	pr := Go_Proxy{
		con:        connection,
		ASN:        0,
		Identifier: 65001,
	}
	sendHello(pr)
	go proxyBackgroundThread(pr.con, &wg)

	rm := &rpkiManager{
		AS:      int(as),
		Proxy:   pr,
		ID:      0,
		Updates: make([]srx_update, 0),
	}
	return rm, nil
}
