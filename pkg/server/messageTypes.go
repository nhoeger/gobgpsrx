package server

const (
	HelloPDU                 = "00"
	HelloRepsonsePDU         = "01"
	GoodByeMessagePDU        = "02"
	VerifyReqeustIPv4PDU     = "03"
	VerifyReqeustIPv6PDU     = "04"
	SignRequestPDU           = "05"
	VerifyNotifyPDU          = "06"
	SignatureNotificationPDU = "07"
	DeleteUpdatePDU          = "08"
	PeerChangePDU            = "09"
	SyncMessagePDU           = "0a"
	ErrorPacketPDU           = "0b"
)

type VerifyMessage struct {
	PDU                  string
	Flags                string
	OriginResultSource   string
	PathResultSource     string
	ASPAResultSource     string
	ASConesResultSource  string
	reserved             string
	ASPathType           string
	ASRelationType       string
	Length               string
	OriginDefaultResult  string
	PathDefaultResult    string
	ASPADefaultResult    string
	ASConesDefaultResult string
	prefix_len           string
	request_token        string
	prefix               string
	origin_AS            string
	length_path_val_data string
	num_of_hops          string
	bgpsec_length        string
	afi                  string
	safi                 string
	prefix_len_bgpsec    string
	ip_pre_add_byte_a    string
	ip_pre_add_byte_b    string
	ip_pre_add_byte_c    string
	ip_pre_add_byte_d    string
	local_as             string
	as_path_list         string
	path_attribute       string
	bgpsec               string
}

type VerifyNotify struct {
	PDU              string
	ResultType       string
	OriginResult     string
	PathResult       string
	ASPAResult       string
	ASConesResult    string
	Zero             string
	Length           string
	RequestToken     string
	UpdateIdentifier string
}

type BGPsecDate struct {
	lengthPathValData string
	numOfHops         string
	bgpsecLength      string
	afi               string
	safi              string
	prefixLenBgpsec   string
	ipPreAddByteA     string
	ipPreAddByteB     string
	ipPreAddByteC     string
	ipPreAddByteD     string
}

type HelloMessage struct {
	PDU              string
	Version          string
	reserved         string
	zero             string
	length           string
	proxy_identifier string
	ASN              string
}
