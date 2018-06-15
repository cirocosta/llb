package llb

// Backend represents a target to receive L4 connections.
type Backend struct {
	// Address corresponds to the IPV4 address that the
	// connection should be made to.
	Address uint32
	// Port corresponds to the port to connect to.
	Port uint16
}
