package server

import "C"
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

/**********************************************************************
/TODO: Change validate Function and integrate it into proxy
/TODO: Finish BGPsec validation and signature
/TODO: Add BGPsec and AS-Cones callback handling
***********************************************************************/

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
	log.Debug("Input: ", input)
	vn := VerifyNotify{
		PDU:              input[:2],
		ResultType:       input[2:4],
		OriginResult:     input[4:6],
		PathResult:       input[6:8],
		ASPAResult:       input[8:10],
		ASConesResult:    input[10:12],
		Zero:             input[12:16],
		Length:           input[16:24],
		RequestToken:     input[24:32],
		UpdateIdentifier: input[32:40],
	}

	if log.GetLevel() == log.DebugLevel {
		printValRes(vn)
	}

	// Iterating through all stores updates to find the matching one
	for i, update := range rm.Updates {
		loc_ID := fmt.Sprintf("%08X", update.local_id)

		// Found the correct update -> set SRxID
		if strings.ToLower(loc_ID) == strings.ToLower(vn.RequestToken) {
			update.srx_id = vn.UpdateIdentifier
			return
		}

		// Found the matching token -> process result
		if update.srx_id == vn.UpdateIdentifier {
			if vn.ResultType == "04" {
				// Valid update
				if vn.ASPAResult == "00" {
					// Process the BGP update
					rm.Server.ProcessValidUpdate(update.peer, update.fsmMsg, update.bgpMsg)
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					return
				} else {
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					return
				}
			}
			// ASCones Result
			if vn.ResultType == "08" {
				log.Debug("In If")
				// Valid update
				if vn.ASConesResult == "00" {

					log.Debug("In If2")
					// Process the BGP update
					rm.Server.ProcessValidUpdate(update.peer, update.fsmMsg, update.bgpMsg)
					rm.Updates = append(rm.Updates[:i], rm.Updates[i+1:]...)
					return
				} else {
					// Update invalid
					log.Debug("INVALID UPDATE")
					log.Debug("INVALID UPDATE")
					log.Debug("INVALID UPDATE")
					log.Debug("INVALID UPDATE")
					log.Debug("INVALID UPDATE")
					log.Debug("INVALID UPDATE")
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
// inputs: BGP peer, the message and message data
func (rm *rpkiManager) validate(peer *peer, m *bgp.BGPMessage, e *fsmMsg) {
	var updatesToSend []string

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
			prefix:               "00000000",
			origin_AS:            "0000fdec",
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
		log.Info("Time since Start:", time.Since(rm.StartTime))
		if rm.Server.bgpConfig.Global.Config.ASPA {
			log.Debug("ASPA")
			vm.Flags = "84"
			//vm.reserved = "00"
		} else if rm.Server.bgpConfig.Global.Config.ASCONES {
			log.Debug("ASCones")
			vm.Flags = "88"
			//vm.reserved = ""
		} else if peer.fsm.pConf.Config.BgpsecEnable {
			vm.bgpsec = rm.GenerateBGPSecFields(e)
		} else {
			log.Fatal("No Validation Possible.")
		}
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
		vm.origin_AS = fmt.Sprintf("%08X", asList[len(asList)-1])
		vm.num_of_hops = fmt.Sprintf("%04X", path.GetAsPathLen())
		tmpInt := 4 * path.GetAsPathLen()
		vm.Length = fmt.Sprintf("%08X", 61+tmpInt)
		//vm.Length = fmt.Sprintf("%08X", 60+tmpInt)
		vm.length_path_val_data = fmt.Sprintf("%08X", tmpInt)
		vm.origin_AS = fmt.Sprintf("%08X", path.GetSourceAs())

		if log.GetLevel() == log.DebugLevel {
			printValReq(vm)
		}
		updatesToSend = append(updatesToSend, structToString(vm))
		rm.Updates = append(rm.Updates, &update)
		rm.ID = (rm.ID % 10000) + 1

		log.Info("Total Updates:", rm.ID, "/", rm.Resets)
	}

	// call proxy function to send message to SRx-Server for each update path
	for _, str := range updatesToSend {
		validate_call(&rm.Proxy, str)
	}
}

func (rm *rpkiManager) GenerateBGPSecFields(e *fsmMsg) string {
	/*log.Debug("Generating BGPsec data.")
	bgpSecString := ""

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

				var myas uint32 = uint32(rm.AS)
				big2 := make([]byte, 4, 4)
				for i := 0; i < 4; i++ {
					u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&myas)) + uintptr(i)))
					big2 = append(big2, u8)
				}

				valData := C.SCA_BGPSecValidationData{
					myAS:             C.uint(binary.BigEndian.Uint32(big2[4:8])),
					status:           C.sca_status_t(0),
					bgpsec_path_attr: nil,
					nlri:             nil,
					hashMessage:      [2](*C.SCA_HashMessage){},
				}

				var bs_path_attr_length uint16
				Flags := bgp.BGPAttrFlag(data[0])
				if Flags&bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
					bs_path_attr_length = binary.BigEndian.Uint16(data[2:4])
				} else {

					bs_path_attr_length = uint16(data[2])
				}

				bs_path_attr_length = bs_path_attr_length + 4 // flag(1) + length(1) + its own length octet (2)
				data = data[:bs_path_attr_length]
				// signature  buffer handling
				//
				pa := C.malloc(C.ulong(bs_path_attr_length))
				defer C.free(pa)

				buf := &bytes.Buffer{}
				bs_path_attr := data

				//bm.bgpsec_path_attr = data
				//bm.bgpsec_path_attr_length = bs_path_attr_length

				binary.Write(buf, binary.BigEndian, bs_path_attr)
				bl := buf.Len()
				o := (*[1 << 20]C.uchar)(pa)

				for i := 0; i < bl; i++ {
					b, _ := buf.ReadByte()
					o[i] = C.uchar(b)
				}
				valData.bgpsec_path_attr = (*C.uchar)(pa)

				// prefix handling
				//
				prefix2 := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
				//defer C.free(unsafe.Pointer(prefix2))
				/*px := &Go_SCA_Prefix{
					Afi:    nlriAfi,
					Safi:   nlriSafi,
					Length: prefixLen,
					Addr:   [16]byte{},
				}*/

	//pxip := prefixAddr
	//copy(px.Addr[:], pxip)
	//px.Pack(unsafe.Pointer(prefix2))
	/* comment out for performance measurement
	C.PrintSCA_Prefix(*prefix2)
	*/ /*
		log.Debug("prefix2 : %#v", prefix2)

		valData.nlri = prefix2
		log.Debug("valData : %#v", valData)
		log.Debug("valData.bgpsec_path_attr : %#v", valData.bgpsec_path_attr)
		/* comment out for performance measurement
		C.printHex(C.int(bs_path_attr_length), valData.bgpsec_path_attr)
	*/ /*
					log.Debug("valData.nlri : %#v", *valData.nlri)

				}
			}
		}
		return bgpSecString*/
	return ""
}

// NewRPKIManager Create new RPKI manager instance
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

// SetSRxServer Parses the IP address of the SRx-Server
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

func printValReq(vm VerifyMessage) {
	log.Debug("+----------------------------------+")
	log.Debug("PDU:                   ", vm.PDU)
	log.Debug("Flags:                 ", vm.Flags)
	log.Debug("OriginResultSoruce:    ", vm.OriginResultSource)
	log.Debug("PathResultSoruce:      ", vm.PathResultSource)
	log.Debug("ASPAResultSoruce:      ", vm.ASPAResultSource)
	log.Debug("ASConesResultSoruce:   ", vm.ASConesResultSource)
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
