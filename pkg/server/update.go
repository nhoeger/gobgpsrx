package server

import (
	"time"

	"github.com/osrg/gobgp/pkg/packet/bgp"
)

type srx_update struct {
	srx_id   string
	local_id int
	peer     *peer
	fsmMsg   *fsmMsg
	bgpMsg   *bgp.BGPMessage
	path     bool
	origin   bool
	aspa     bool
	ascones  bool
	time     time.Time
}
