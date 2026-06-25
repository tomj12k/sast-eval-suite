package main

import (
	"net/http"
	"os/exec"
)

// Run handles /ping?host=... with a planted command-injection sink.
func Run(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// VULN: user-controlled host interpolated into a shell command.
	out, _ := exec.Command("bash", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

func main() {}
