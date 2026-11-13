// Package journal writes the relay's log: one JSON line per visitor
// connection, relay event and service message, in daily files.
package journal

// Entry is one journal line. Empty fields are left out.
type Entry struct {
	Time   string `json:"time,omitempty"` // RFC 3339, milliseconds, UTC
	Src    string `json:"src,omitempty"`  // share | front | relay | log
	Svc    string `json:"svc,omitempty"`  // share | enrolment | front
	IP     string `json:"ip,omitempty"`
	Host   string `json:"host,omitempty"`
	Act    string `json:"act,omitempty"` // pass | cut | close
	Reason string `json:"reason,omitempty"`
	Source string `json:"source,omitempty"`
	Ms     int64  `json:"ms,omitempty"`
	In     int64  `json:"in,omitempty"`
	Out    int64  `json:"out,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Status int    `json:"status,omitempty"`
	Event  string `json:"event,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Count  int64  `json:"count,omitempty"`
}
