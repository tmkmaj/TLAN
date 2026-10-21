package clientapi

// HTTPError retains the response status so callers can distinguish revoked
// membership from a temporary outage without matching human-readable text.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string { return "server error: " + e.Message }
