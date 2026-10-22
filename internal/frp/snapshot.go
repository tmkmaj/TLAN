package frp

import (
	"github.com/private-radminlan/lanmesh/internal/netpolicy"
	"github.com/private-radminlan/lanmesh/internal/targetgateway"
)

type RuleRuntimeStatus struct {
	RuleID       string
	Name         string
	Type         string
	Enabled      bool
	State        string
	RemoteAddr   string
	Backend      string
	GatewayStats string
	ErrorCode    string
	ErrorDetail  string
}

type VisitorRuntimeStatus struct {
	VisitorID   string
	Name        string
	Type        string
	Enabled     bool
	State       string
	BindAddr    string
	BindPort    int
	ErrorDetail string
}

type GatewayRuntimeStatus struct {
	RuleID   string
	Protocol string
	Address  string
	Path     string
	State    string
	Stats    targetgateway.Stats
}

type Snapshot struct {
	Configured     bool
	Running        bool
	DesiredRunning bool
	CanStop        bool
	State          string
	CoreVersion    string
	CoreHash       string
	ProfileName    string
	ServerHost     string
	ServerPort     int
	Revision       uint64
	Authenticated  bool
	SharedToken    bool
	Rules          []RuleRuntimeStatus
	Visitors       []VisitorRuntimeStatus
	Gateways       []GatewayRuntimeStatus
	Endpoints      []EndpointRecord
	Observation    netpolicy.ObservationStatus
	LastError      string
	LastErrorCode  string
	Logs           []string
	LogStorage     LogStorageStatus
}
