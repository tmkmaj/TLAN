package clientapi

// HTTPError retains the response status so callers can distinguish revoked
// membership from a temporary outage without matching human-readable text.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string { return "server error: " + e.Message }

// AdminAPIError carries the stable admin error code and request ID returned by
// the public admin API envelope.
type AdminAPIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *AdminAPIError) Error() string {
	if e == nil {
		return "admin API error"
	}
	if e.RequestID != "" {
		return "admin API error: " + e.Message + " (request " + e.RequestID + ")"
	}
	return "admin API error: " + e.Message
}

func (e *AdminAPIError) ErrorCode() string {
	if e == nil {
		return ""
	}
	return e.Code
}
