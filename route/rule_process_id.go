package route

import (
	F "github.com/sagernet/sing/common/format"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/warning"
	C "github.com/sagernet/sing-box/constant"
)

var warnProcessIDOnNonSupportedPlatform = warning.New(
	func() bool { return !(C.IsLinux || C.IsWindows || C.IsDarwin) },
	"rule item `process_name` is only supported on Linux, Windows and macOS",
)

var _ RuleItem = (*ProcessID)(nil)

type ProcessID struct {
	processesID  []uint32
	processIDMap map[uint32]bool
}

func NewProcessID(processIDList []uint32) *ProcessID {
	warnProcessNameOnNonSupportedPlatform.Check()
	rule := &ProcessID{
		processesID:  processIDList,
		processIDMap: make(map[uint32]bool),
	}
	for _, processName := range processIDList {
		rule.processIDMap[processName] = true
	}
	return rule
}

func (r *ProcessID) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.PID == 0 {
		return false
	}
	return r.processIDMap[metadata.ProcessInfo.PID]
}

func (r *ProcessID) String() string {
	var description string
	pLen := len(r.processesID)
	if pLen == 1 {
		description = "pid=" + strconv.FormatUint(uint64(r.processesID[0]), 10)
	} else {
		description = "process_name=[" + strings.Join(F.MapToString(r.processesID), " ") + "]"
	}
	return description
}
