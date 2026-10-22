package main

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
)

// runAsService runs the core under the Windows service manager when it was started as a service
// (the root core enhanced mode needs, installed by the GUI as "ConnaioCore"), and reports whether it
// did. A service has no console, so the log goes to core.log in the data dir, where the GUI reads it.
func runAsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	if homeDir != "" {
		if f, err := os.OpenFile(filepath.Join(homeDir, "core.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
			log.SetOutput(f)
		}
	}
	_ = svc.Run("ConnaioCore", service{})
	return true
}

type service struct{}

// Execute runs the core and turns Stop and Shutdown into a close of stopSign, which run returns
// on, restoring routes and listeners as it does on SIGTERM.
func (s service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	done := make(chan struct{})
	go func() {
		run()
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-done:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				stop()
				<-done
				return false, 0
			}
		}
	}
}
