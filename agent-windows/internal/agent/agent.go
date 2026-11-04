package agent

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// AgentVersion is reported on every poll and compared by the controller
// against its configured target. Bump it on release.
const AgentVersion = "1.0.0"

// Status is what the local UI shows: plain data, no lock, so it can be
// copied and serialised freely. StatusHolder below owns the mutex --
// keeping them separate is what makes a snapshot safe to hand out.
type Status struct {
	Enrolled     bool      `json:"enrolled"`
	Hostname     string    `json:"hostname"`
	Controller   string    `json:"controller"`
	HostID       int       `json:"host_id"`
	Version      string    `json:"version"`
	LastPoll     time.Time `json:"last_poll"`
	LastPollOK   bool      `json:"last_poll_ok"`
	LastPollErr  string    `json:"last_poll_error"`
	CurrentJob   int       `json:"current_job"`
	CurrentStage string    `json:"current_stage"`
	PendingCount int       `json:"pending_updates"`
	AssessOK     bool      `json:"assess_ok"`
	AssessErr    string    `json:"assess_error"`
}

// StatusHolder guards one Status. The poll loop writes it and the UI
// server reads it from another goroutine, so every access is through
// set() or snapshot().
type StatusHolder struct {
	mu   sync.RWMutex
	data Status
}

var status = &StatusHolder{data: Status{Version: AgentVersion}}

// Only the process that runs the poll loop publishes status.json. The
// status window and the `status` command read that file; if they also
// wrote it, opening the window would overwrite the service's live status
// with a config-only snapshot -- no last poll, no pending count -- and
// then read its own clobbered write back. NewAgent turns this on, so the
// service, `run` and `once` publish and nothing else does.
var publishStatus atomic.Bool

// EnableStatusPublishing lets this process write status.json. Called by
// NewAgent, which every polling entry point constructs and no reader
// does.
func EnableStatusPublishing() { publishStatus.Store(true) }

func (h *StatusHolder) set(mutate func(*Status)) {
	h.mu.Lock()
	mutate(&h.data)
	published := h.data
	h.mu.Unlock()
	if publishStatus.Load() {
		persistStatus(published)
	}
}

func (h *StatusHolder) snapshot() Status {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.data
}

// Agent is the poll/execute/report loop. The controller drives the
// pipeline; this has no opinion about what stage comes next, only how to
// execute the one it is handed.
type Agent struct {
	cfg    *Config
	client *Client
	// Hash of the software list the controller last accepted, so the full
	// list is only sent when it changed. "" = send it.
	softwareSent string
	// Set when the reboot stage has asked Windows to restart: until it
	// does, the agent takes on no more work. Polling straight away would
	// hand it the same reboot stage again, whose restart would cancel
	// and replace the one counting down -- every few seconds, forever.
	restartAsked bool
	// The last stage run here and its result: see RunStage.
	last *stageResult
}

type stageResult struct {
	jobID          int
	stage          string
	status, output string
}

// restartWait is how long the agent waits for the restart it asked for
// before asking again.
var restartWait = 10 * time.Minute

func NewAgent(cfg *Config) *Agent {
	EnableStatusPublishing()
	status.set(func(s *Status) {
		s.Enrolled, s.Controller, s.HostID = true, cfg.ControllerURL, cfg.HostID
		if name, err := os.Hostname(); err == nil {
			s.Hostname = name
		}
	})
	return &Agent{cfg: cfg, client: NewClient(cfg)}
}

// Run polls until stopped. `stop` is closed by the service control
// handler, so a Windows "stop service" ends the loop rather than killing
// the process mid-stage.
func (a *Agent) Run(stop <-chan struct{}) {
	a.ResumePendingReboot()
	if checkNewBinary() {
		return
	}
	EnsureServiceRecovery()
	if note := a.PinControllerCA(); note != "" {
		Info("%s", note)
	}
	Info("polling %s every %ds (agent %s)", a.cfg.ControllerURL, a.cfg.PollInterval, AgentVersion)
	for {
		select {
		case <-stop:
			return // stopping: take on nothing new
		default:
		}
		instruction, selfUpdate, err := a.client.PollNext(a.cfg.AgentSecret, a.cfg.PollInterval)
		now := time.Now()
		if err != nil {
			status.set(func(s *Status) { s.LastPoll, s.LastPollOK, s.LastPollErr = now, false, err.Error() })
			Warn("poll failed: %v", err)
			if sleep(stop, time.Duration(a.cfg.ErrorBackoff)*time.Second) {
				return
			}
			continue
		}
		status.set(func(s *Status) { s.LastPoll, s.LastPollOK, s.LastPollErr = now, true, "" })
		newBinaryHealthy()

		if instruction != nil {
			a.RunStage(instruction)
			if a.restartAsked {
				// The restart stops this service; wait for it.
				if sleep(stop, restartWait) {
					return
				}
				a.restartAsked = false
				Warn("the machine hasn't restarted %s after it was asked to; asking again", restartWait)
			}
			continue // just did work, so check again rather than sleeping
		}
		if selfUpdate != "" && a.maybeSelfUpdate(selfUpdate) {
			// The restart stops this service; wait for it rather than starting work.
			if sleep(stop, 2*time.Minute) {
				return
			}
			continue
		}
		a.ReportInventory()
		Info("nothing pending, sleeping up to %ds", a.cfg.PollInterval)
		if sleep(stop, time.Duration(a.cfg.PollInterval)*time.Second) {
			return
		}
	}
}

// sleep waits, but wakes immediately if the service is stopping. Returns
// true when it is time to exit.
func sleep(stop <-chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return true
	case <-time.After(d):
		return false
	}
}

func (a *Agent) ReportInventory() {
	updates, sources := AssessAll()
	// The status window and the host-level flags track the OS source
	// specifically -- that is what "is this host patched" has always
	// meant here. Third-party sources are shown per-source rather than
	// folded into one verdict.
	osOK, osErr := true, ""
	for _, src := range sources {
		if src.Name == "os" {
			osOK, osErr = src.OK, src.Error
		}
		if !src.OK {
			Warn("%s assessment could not run: %s", src.Name, src.Error)
		}
	}
	status.set(func(s *Status) { s.PendingCount, s.AssessOK, s.AssessErr = len(updates), osOK, osErr })
	// Network facts come from Windows cmdlets; off Windows (tests, a dev
	// box) there is nothing to read, and none is sent.
	var network *Network
	var software *SoftwareReport
	if runtime.GOOS == "windows" {
		n := DiscoverNetwork()
		if !n.OK {
			Warn("network discovery could not run: %s", n.Error)
		}
		network = &n
		if items, err := CollectSoftware(); err != nil {
			Warn("software inventory could not run: %v", err)
		} else {
			software = softwareReport(items, a.softwareSent)
		}
	}
	resend, err := a.client.ReportInventory(a.cfg.AgentSecret, updates, sources, osOK, osErr, network, software)
	if err != nil {
		a.softwareSent = "" // it may not have landed: send the full list next time
		Warn("inventory report failed: %v", err)
		return
	}
	if software != nil {
		switch {
		case resend:
			a.softwareSent = ""
		case software.Items != nil:
			a.softwareSent = software.Hash
		}
	}
	Info("reported %d pending update(s) across %d source(s)", len(updates), len(sources))
}

// RunStage executes one stage and reports the result. A stage that panics
// or errors unexpectedly is still reported, because a job left running
// forever is worse than one that failed for a stated reason.
func (a *Agent) RunStage(in *Instruction) {
	status.set(func(s *Status) { s.CurrentJob, s.CurrentStage = in.JobID, in.StageName })
	defer status.set(func(s *Status) { s.CurrentJob, s.CurrentStage = 0, "" })

	// The controller hands out a stage until its report arrives. Given
	// the stage just run here again, the report was lost on the way:
	// send it again rather than run the stage twice.
	if l := a.last; l != nil && l.jobID == in.JobID && l.stage == in.StageName {
		Warn("job %d: stage %s already ran here and its report didn't arrive; sending it again", in.JobID, in.StageName)
		if err := a.client.ReportStage(a.cfg.AgentSecret, l.jobID, l.stage, l.status, l.output); err != nil {
			Error("could not report job %d stage %s: %v", l.jobID, l.stage, err)
		}
		return
	}

	Info("job %d: running stage %s", in.JobID, in.StageName)
	statusText, output := a.execute(in)
	if statusText == "deferred" {
		a.restartAsked = true
		return // the reboot stage reports itself after the host comes back
	}
	a.last = &stageResult{in.JobID, in.StageName, statusText, output}
	Info("job %d: stage %s -> %s", in.JobID, in.StageName, statusText)
	if err := a.client.ReportStage(a.cfg.AgentSecret, in.JobID, in.StageName, statusText, output); err != nil {
		Error("could not report job %d stage %s: %v", in.JobID, in.StageName, err)
	}
}

func (a *Agent) execute(in *Instruction) (status string, output string) {
	defer func() {
		if r := recover(); r != nil {
			status, output = "failed", fmt.Sprintf("unhandled agent error: %v", r)
		}
	}()
	// A controller-supplied script replaces this stage's built-in handler,
	// same as the Linux agent. Until this existed the field was parsed off
	// the wire and silently dropped, so a script uploaded for a win* family
	// was accepted by the controller and then never ran on the host.
	if in.CustomScript != "" {
		return a.runCustomScript(in)
	}

	switch in.StageName {
	case "preflight":
		return a.stagePreflight()
	case "excludes":
		return a.stageExcludes(in)
	case "patch":
		return a.stagePatch(in)
	case "reboot":
		return a.stageReboot(in)
	case "healthcheck":
		return a.stageHealthcheck()
	case "containers":
		// An OS-scope run still walks the containers stage. A Windows
		// host discovers no compose containers, so the selection is
		// empty and there is nothing to do -- which is a completed
		// stage, not a failure. Only a non-empty selection (which the
		// controller never produces for a host with no containers) is
		// something this agent genuinely cannot honour.
		if len(in.Containers) == 0 {
			return "done", "no containers on this host"
		}
		return "failed", "this agent does not manage containers"
	default:
		return "failed", "no handler for stage " + in.StageName
	}
}
