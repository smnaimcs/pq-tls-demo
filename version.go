package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Build metadata. Version may be overridden at link time:
//
//	go build -ldflags "-X main.Version=0.1.0 -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	Version   = "0.1.0"
	BuildTime = "unknown"
)

func init() {
	if BuildTime != "unknown" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.time" && s.Value != "" {
				BuildTime = s.Value
				return
			}
		}
	}
}

func formatVersionInfo() string {
	return fmt.Sprintf(
		"Application: pq-tls-demo\nVersion: %s\nGo: %s\nOS: %s\nArchitecture: %s\nBuildTime: %s\n",
		Version,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
		BuildTime,
	)
}
