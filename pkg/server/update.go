package server

import (
	log "github.com/sirupsen/logrus"
)

type srx_update struct {
	update_id int
	path      bool
	origin    bool
	aspa      bool
	ascones   bool
}

func NewSrxUpdate(id int) srx_update {
	log.WithFields(log.Fields{
		"update id": id,
	}).Debug("Creating a new update")
	update := srx_update{
		update_id: id,
		path:      false,
		origin:    false,
		aspa:      false,
		ascones:   false,
	}
	return update
}

func set_path(input_bool bool, update srx_update) {
	update.path = input_bool
}

func set_origin(input_bool bool, update srx_update) {
	update.origin = input_bool
}

func set_aspa(input_bool bool, update srx_update) {
	update.aspa = input_bool
}

func set_ascones(input_bool bool, update srx_update) {
	update.ascones = input_bool
}
