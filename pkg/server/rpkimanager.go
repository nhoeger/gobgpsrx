package server

import "C"
import (
	"encoding/binary"
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

/**********************************************************************
/TODO: Change validate Function and integrate it into proxy
/TODO: Finish BGPsec validation and signature
/TODO: Add BGPsec and AS-Cones callback handling
***********************************************************************/

type RPKIManager struct {
	AS             int
	ID             int
	Proxy          GoSRxProxy
	Server         *BgpServer
	PendingUpdates []*srx_update
	Queue          []*VerifyNotify
	StartTime      time.Time
	Resets         int
	Ready          *bool
}

func hexToBinary(hexStr string) (string, error) {
	decimalValue, err := strconv.ParseInt(hexStr, 16, 64)
	if err != nil {
		return "", err
	}
	binaryStr := strconv.FormatInt(decimalValue, 2)
	for len(binaryStr) < 8 {
		binaryStr = "0" + binaryStr
	}
	return binaryStr, nil
}

func (rm *RPKIManager) resultsFor(vn *VerifyNotify) (bool, bool, bool, bool) {
	tmp, err := hexToBinary(vn.ResultType)
	if err != nil {
		log.Fatal("Conversion error!")
	}
	ROA := tmp[len(tmp)-1] == '1'
	BGPsec := tmp[len(tmp)-2] == '1'
	ASPA := tmp[len(tmp)-3] == '1'
	ASCones := tmp[len(tmp)-4] == '1'
	return ROA, BGPsec, ASPA, ASCones
}

func (rm *RPKIManager) findUpdateInstance(token string, SRxID string) (*srx_update, int) {
	for i, update := range rm.PendingUpdates {
		locId := fmt.Sprintf("%08X", update.local_id)
		if strings.ToLower(locId) == token || rm.PendingUpdates[i].srx_id == SRxID {
			if rm.PendingUpdates[i].srx_id == "" {
				rm.PendingUpdates[i].srx_id = SRxID
			}
			return rm.PendingUpdates[i], i
		}
	}
	return nil, 0
}

func (rm *RPKIManager) handleVerifyNotify(vn *VerifyNotify) {
	rm.Queue = append(rm.Queue, vn)
	if *rm.Ready {
		rm.handleVerifyNotifyBuffer(rm.Queue[0])
	}
}

// Callback function: The proxy can call this function when the SRx-Server sends a verify notify
// Input is a raw string containing the message from the server and a pointer to the rpkimanager
func (rm *RPKIManager) handleVerifyNotifyBuffer(vn *VerifyNotify) {
	*rm.Ready = false
	//invalid := false
	/*if log.GetLevel() == log.DebugLevel {
		printValRes(*vn)
	}*/

	// Find the matching Update instance + index
	update, i := rm.findUpdateInstance(vn.RequestToken, vn.UpdateIdentifier)
	if update == nil {
		//log.Fatal("Found no matching Update")
		*rm.Ready = true
		rm.Queue = rm.Queue[1:]
		return
	}

	// Identify which validation results are included in the verify notify message
	ROA, BGPsec, ASPA, ASCones := rm.resultsFor(vn)

	if ROA && vn.OriginResult != "03" {
		if vn.OriginResult == "00" {
			log.Debug("ROA validation result: Valid Update")
			update.origin = true
			rm.checkUpdate(i)
		} /*else {
			log.Debug("ROA validation result: Invalid Update")
			//rm.InvalidUpdates = append(rm.InvalidUpdates, rm.StoredUpdates[i])
			//rm.StoredUpdates = append(rm.StoredUpdates[:i], rm.StoredUpdates[i+1:]...)
			invalid = true
		}*/
	}
	if BGPsec && vn.PathResult != "03" {
		if vn.OriginResult == "00" {
			log.Debug("Path validation result: Valid Update")
			update.path = true
			rm.checkUpdate(i)
		} /*else {
			log.Debug("Path validation result: Invalid Update")
			rm.InvalidUpdates = append(rm.InvalidUpdates, rm.StoredUpdates[i])
			rm.StoredUpdates = append(rm.StoredUpdates[:i], rm.StoredUpdates[i+1:]...)
			invalid = true
		}*/
	}
	if ASPA && vn.ASPAResult != "03" {
		if vn.ASPAResult == "00" {
			log.Debug("ASPA validation result: Valid Update")
			update.aspa = true
			rm.checkUpdate(i)
		} /* else {
			log.Debug("ASPA validation result: Invalid Update")
			rm.InvalidUpdates = append(rm.InvalidUpdates, rm.StoredUpdates[i])
			rm.StoredUpdates = append(rm.StoredUpdates[:i], rm.StoredUpdates[i+1:]...)
			invalid = true
		}*/
	}
	if ASCones && vn.ASConesResult != "03" {
		if vn.ASConesResult == "00" {
			log.Debug("AS-Cones validation result: Valid Update")
			update.ascones = true
			rm.checkUpdate(i)
		} /*else {
			log.Debug("AS-Cones validation result: Invalid Update")
			rm.InvalidUpdates = append(rm.InvalidUpdates, rm.StoredUpdates[i])
			rm.StoredUpdates = append(rm.StoredUpdates[:i], rm.StoredUpdates[i+1:]...)
			invalid = true
		} */
	}
	rm.Queue = rm.Queue[1:]
	if len(rm.Queue) > 0 {
		rm.handleVerifyNotifyBuffer(rm.Queue[0])
	} else {
		*rm.Ready = true
	}
	log.Debug("+------------------------------------+")
	log.Debug("Current Stats:")
	//log.Debug("Current Update invalid: ", invalid)
	log.Debug("Pending Updates:        ", len(rm.PendingUpdates))
	log.Debug("+------------------------------------+")
}

// If all requested validations for an update return valid, the update is valid
// and the routing daemon can further process it
func (rm *RPKIManager) checkUpdate(i int) {
	update := rm.PendingUpdates[i]
	if update.origin && update.path && update.aspa && update.ascones {
		rm.Server.ProcessValidUpdate(update.peer, update.fsmMsg, update.bgpMsg)
		rm.PendingUpdates = append(rm.PendingUpdates[:i], rm.PendingUpdates[i+1:]...)
	}
}

// Server send Sync message and Proxy responds with all cached updates
func (rm *RPKIManager) handleSyncCallback() {
	log.Debug("In sync callback function!")
	for _, Updates := range rm.PendingUpdates {
		log.Debug("Requesting Validation for Update: ", Updates.local_id)
		rm.validate(Updates.peer, Updates.bgpMsg, Updates.fsmMsg)
	}
}

// TODO: Remove num hops and lenght path val data
// Create a Validation message for an incoming BGP UPDATE message
// inputs: BGP peer, the message and message data
func (rm *RPKIManager) validate(peer *peer, m *bgp.BGPMessage, e *fsmMsg) {
	var updatesToSend []string
	rm.debuggingProxyFunction(peer, m, e)
	// Iterate through all paths inside the BGP UPDATE message
	for _, path := range e.PathList {
		// Create new SRxUpdate for each path
		update := srx_update{
			local_id: rm.ID,
			srx_id:   "",
			peer:     peer,
			fsmMsg:   e,
			bgpMsg:   m,
			origin:   true,
			path:     true,
			aspa:     true,
			ascones:  true,
		}
		// Create new message for each path
		vm := VerifyMessage{
			PDU:                  "03",
			OriginResultSource:   "01",
			PathResultSource:     "01",
			ASPAResultSource:     "01",
			reserved:             "01",
			ASPathType:           "02",
			ASRelationType:       "04",
			Length:               "00000044",
			OriginDefaultResult:  "03",
			PathDefaultResult:    "03",
			ASPADefaultResult:    "03",
			prefix_len:           "18",
			request_token:        fmt.Sprintf("%08X", update.local_id) + "03",
			length_path_val_data: "00000008",
			bgpsec_length:        "0000",
			afi:                  "0000",
			safi:                 "00",
			prefix_len_bgpsec:    "00",
			ip_pre_add_byte_a:    "00000000",
			ip_pre_add_byte_b:    "00000000",
			ip_pre_add_byte_c:    "00000000",
			ip_pre_add_byte_d:    "00000000",
			local_as:             fmt.Sprintf("%08X", rm.AS),
			as_path_list:         "",
			bgpsec:               "",
		}
		tmpFlag := 128
		if rm.Server.bgpConfig.Global.Config.ROA {
			tmpFlag += 1
			update.origin = false
		}
		if peer.fsm.pConf.Config.BgpsecEnable {
			tmpFlag += 2

			//vm.bgpsec = rm.GenerateBGPSecFields(e)
			update.path = false
		}
		if rm.Server.bgpConfig.Global.Config.ASPA {
			tmpFlag += 4
			log.Debug("Generating ASPA Request")
			update.aspa = false
		}
		if rm.Server.bgpConfig.Global.Config.ASCONES {
			tmpFlag += 8
			log.Debug("Generating AS-Cones Request")
			update.ascones = false
		}
		vm.Flags = fmt.Sprintf("%02X", tmpFlag)

		asList := path.GetAsList()
		for _, asn := range asList {
			hexValue := fmt.Sprintf("%08X", asn)
			vm.as_path_list += hexValue

		}
		prefixLen := 0
		prefixAddr := net.ParseIP("0.0.0.0")
		pathString := path.String()
		words := strings.Fields(pathString)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmpPref, _ := strconv.Atoi(word[j+1:])
					prefixLen = tmpPref
					prefixAddr = net.ParseIP(word[:j])
				}
			}
		}
		tmp := hex.EncodeToString(prefixAddr)
		vm.prefix = tmp[len(tmp)-8:]
		vm.prefix_len = strconv.FormatInt(int64(prefixLen), 16)
		//vm.origin_AS = fmt.Sprintf("%08X", asList[len(asList)-1])
		vm.num_of_hops = fmt.Sprintf("%04X", path.GetAsPathLen())
		tmpInt := 4 * path.GetAsPathLen()
		vm.Length = fmt.Sprintf("%08X", 61+tmpInt)
		vm.length_path_val_data = fmt.Sprintf("%08X", tmpInt)
		vm.origin_AS = fmt.Sprintf("%08X", path.GetSourceAs())

		// Debug
		if log.GetLevel() == log.DebugLevel {
			printValReq(vm)
		}
		updatesToSend = append(updatesToSend, structToString(vm))
		rm.PendingUpdates = append(rm.PendingUpdates, &update)
		rm.ID = (rm.ID % 10000) + 1
	}

	// call proxy function to send message to SRx-Server for each update path
	for _, str := range updatesToSend {
		//validate_call(&rm.Proxy, str)
		log.Debug("Output ValidateCall:", str)
	}
}

func (rm *RPKIManager) debuggingProxyFunction(peer *peer, m *bgp.BGPMessage, e *fsmMsg) {
	for _, path := range e.PathList {
		var flag SRxVerifyFlag      // Done
		var token int               // Done
		var reqRes SRxDefaultResult // Done
		var prefix IPPrefix         // Done
		var ASN int                 // Done
		var ASlist ASPathList       // Tmp Done
		var BGPsec *BGPsecData      // TODO
		BGPsec = nil

		flag = 128
		if rm.Server.bgpConfig.Global.Config.ROA {
			flag += 1
		}
		if peer.fsm.pConf.Config.BgpsecEnable {
			flag += 2
		}
		if rm.Server.bgpConfig.Global.Config.ASPA {
			flag += 4
		}
		if rm.Server.bgpConfig.Global.Config.ASCONES {
			flag += 8
		}

		token = rm.ID
		rm.ID = (rm.ID % 10000) + 1

		reqRes.resSourceBGPsec = SRxRSUnknown
		reqRes.resSourceROA = SRxRSUnknown
		reqRes.resSourceASPA = SRxRSUnknown
		reqRes.resSourceASCones = SRxRSUnknown
		srxRes := SRxResult{
			ROAResult:     3,
			BGPsecResult:  3,
			ASPAResult:    3,
			ASConesResult: 3,
		}
		reqRes.result = srxRes

		prefixLen := 0
		prefixAddr := net.ParseIP("0.0.0.0")
		pathString := path.String()
		words := strings.Fields(pathString)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmpPref, _ := strconv.Atoi(word[j+1:])
					prefixLen = tmpPref
					prefixAddr = net.ParseIP(word[:j])
				}
			}
		}
		prefix.length = prefixLen
		prefix.version = 4
		prefix.address = prefixAddr

		ASN = rm.AS
		var array []int
		asList := path.GetAsList()
		for i, asn := range asList {
			ASlist.length = i
			ASlist.ASes = append(array, int(asn))

			// TODO: Add Custom Relationships
			ASlist.Relation = unknown
		}
		log.Debug("Finished loop")
		rm.Proxy.createV4Request(flag, token, reqRes, prefix, ASN, ASlist, BGPsec)
	}
}

func (rm *RPKIManager) validateBGPsecMessage(e *fsmMsg) {
	log.Debug("Handling BGPsec message")
	//bgpSecString := ""

	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)

	var nlriProcessed bool
	var prefixAddr net.IP
	var prefixLen uint8
	var nlriAfi uint16
	var nlriSafi uint8

	// find the position of bgpsec attribute
	//
	data := e.payload
	data = data[bgp.BGP_HEADER_LENGTH:]
	if update.WithdrawnRoutesLen > 0 {
		data = data[2+update.WithdrawnRoutesLen:]
	} else {
		data = data[2:]
	}

	data = data[2:]
	for pathlen := update.TotalPathAttributeLen; pathlen > 0; {
		p, _ := bgp.GetPathAttribute(data)
		p.DecodeFromBytes(data)

		pathlen -= uint16(p.Len())

		if bgp.BGPAttrType(data[1]) != bgp.BGP_ATTR_TYPE_BGPSEC {
			data = data[p.Len():]
		} else {
			break
		}
	}

	//
	// find nlri attribute first and extract prefix info for bgpsec validation
	//
	for _, path := range e.PathList {

		// find MP NLRI attribute first
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI) {
				log.Debug("received MP NLRI: %#v", path)
				prefixAddr = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Prefix
				prefixLen = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Length
				nlriAfi = p.(*bgp.PathAttributeMpReachNLRI).AFI
				nlriSafi = p.(*bgp.PathAttributeMpReachNLRI).SAFI

				log.WithFields(log.Fields{"Topic": "Bgpsec"}).Debug("prefix:", prefixAddr, prefixLen, nlriAfi, nlriSafi)
				nlriProcessed = true
				log.Debug("received MP NLRI: %#v", nlriProcessed)
			}
		}

		// find the BGPSec atttribute
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_BGPSEC) && nlriProcessed {
				log.Debug("bgpsec validation start ")
				myAS := rm.AS
				log.Debug("AS: ", myAS)

				var bs_path_attr_length uint16
				Flags := bgp.BGPAttrFlag(data[0])
				if Flags&bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
					bs_path_attr_length = binary.BigEndian.Uint16(data[2:4])
				} else {

					bs_path_attr_length = uint16(data[2])
				}

				bs_path_attr_length = bs_path_attr_length + 4 // flag(1) + length(1) + its own length octet (2)
				data = data[:bs_path_attr_length]

				log.Debug("bs_path_attr_length: ", bs_path_attr_length)

				bs_path_attr := data
				log.Debug("bspathattr", bs_path_attr)
				log.Debug("Prefix Data: ", nlriAfi, nlriSafi, prefixLen, prefixAddr)
			}
		}
	}
}

// NewRPKIManager Create new RPKI manager instance
// Input: pointer to BGPServer
func NewRPKIManager(s *BgpServer) (*RPKIManager, error) {
	rm := &RPKIManager{
		AS:             int(s.bgpConfig.Global.Config.As),
		Server:         s,
		ID:             1,
		PendingUpdates: make([]*srx_update, 0),
		StartTime:      time.Now(),
		Resets:         0,
		Ready:          new(bool),
		Queue:          make([]*VerifyNotify, 0),
	}
	*rm.Ready = true
	return rm, nil
}

// SetSRxServer Parses the IP address of the SRx-Server
// Proxy can establish a connection with the SRx-Server and sends a hello message
// Thread mandatory to keep proxy alive during runtime
func (rm *RPKIManager) SetSRxServer(ip string) error {
	var wg sync.WaitGroup
	wg.Add(1)
	rm.Proxy = createSRxProxy(rm.AS, ip, rm.handleVerifyNotify, rm.handleSyncCallback)
	go rm.Proxy.proxyBackgroundThread(&wg)
	return nil
}

func (rm *RPKIManager) SetAS(as uint32) error {
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

func printValReq(vm VerifyMessage) {
	log.Debug("+----------------------------------+")
	log.Debug("PDU:                   ", vm.PDU)
	log.Debug("Flags:                 ", vm.Flags)
	log.Debug("OriginResultSource:    ", vm.OriginResultSource)
	log.Debug("PathResultSource:      ", vm.PathResultSource)
	log.Debug("ASPAResultSource:      ", vm.ASPAResultSource)
	log.Debug("ASConesResultSource:   ", vm.ASConesResultSource)
	log.Debug("reserved:              ", vm.reserved)
	log.Debug("ASPathType:            ", vm.ASPathType)
	log.Debug("ASRelationType:        ", vm.ASRelationType)
	log.Debug("Length:                ", vm.Length)
	log.Debug("OriginDefaultResult:   ", vm.OriginDefaultResult)
	log.Debug("PathDefaultResult:     ", vm.PathDefaultResult)
	log.Debug("ASPADefaultResult:     ", vm.ASPADefaultResult)
	log.Debug("ASConesDefaultResult:  ", vm.ASConesDefaultResult)
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

func printValRes(vn VerifyNotify) {
	log.Debug("+----------------------------------+")
	log.Debug("PDU:               ", vn.PDU)
	log.Debug("ResultType:        ", vn.ResultType)
	log.Debug("OriginResult:      ", vn.OriginResult)
	log.Debug("PathResult:        ", vn.PathResult)
	log.Debug("ASPAResult:        ", vn.ASPAResult)
	log.Debug("ASConesResult:     ", vn.ASConesResult)
	log.Debug("Zero:              ", vn.Zero)
	log.Debug("Length:            ", vn.Length)
	log.Debug("RequestToken:      ", vn.RequestToken)
	log.Debug("UpdateIdentifier:  ", vn.UpdateIdentifier)
	log.Debug("+----------------------------------+")
}
