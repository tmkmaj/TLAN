package frp

import (
	"errors"
	"fmt"
)

const (
	CodeServerUnreachable           = "FRP_SERVER_UNREACHABLE"
	CodeTLSUntrusted                = "FRP_TLS_UNTRUSTED"
	CodeAuthRejected                = "FRP_AUTH_REJECTED"
	CodeRemotePortDenied            = "FRP_REMOTE_PORT_DENIED"
	CodeRemotePortBusy              = "FRP_REMOTE_PORT_BUSY"
	CodeLocalListenBusy             = "FRP_LOCAL_LISTEN_BUSY"
	CodeBackendUnreachable          = "FRP_BACKEND_UNREACHABLE"
	CodeRouteConflict               = "ROUTE_CONFLICT"
	CodeRouteObservationUnavailable = "ROUTE_OBSERVATION_UNAVAILABLE"
	CodeMeshDependencyDown          = "MESH_DEPENDENCY_DOWN"
	CodeUnsupportedFeature          = "UNSUPPORTED_FRP_FEATURE"
	CodeCleanupIncomplete           = "CLEANUP_INCOMPLETE"
	CodeCoreInvalid                 = "FRP_CORE_INVALID"
	CodeProcessFailed               = "FRP_PROCESS_FAILED"
	CodeAdminUnauthorized           = "FRP_ADMIN_UNAUTHORIZED"
	CodeConfigurationInvalid        = "FRP_CONFIGURATION_INVALID"
)

// Error carries a stable user-facing code while retaining technical context.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func withCode(code string, err error) error {
	if err == nil {
		return nil
	}
	var coded *Error
	if errors.As(err, &coded) {
		return err
	}
	return &Error{Code: code, Err: err}
}

func codedError(code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

func unsupported(format string, args ...any) error {
	return codedError(CodeUnsupportedFeature, format, args...)
}

func ErrorCode(err error) string {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}
