package platform

// Runner is the command boundary used by Windows resource setup and cleanup.
// Tests can inject a fake runner; production uses SystemRunner.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}
