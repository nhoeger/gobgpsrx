package server

import log "github.com/sirupsen/logrus"

type updateManager struct {
	Updates []srx_update
}

func createUpdateManager() updateManager {
	um := updateManager{
		Updates: make([]srx_update, 0),
	}
	return um
}

func addUpdate(um updateManager) {
	log.Info("Adding to manager")
	up := srx_update{}
	um.Updates = append(um.Updates, up)
	log.Info("length; ", len(um.Updates))
}

func getSize(um updateManager) int {
	return len(um.Updates)
}
