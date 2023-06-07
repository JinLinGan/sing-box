//go:build debug

package main

import (
	"github.com/sagernet/sing-box/experimental"
	_ "net/http/pprof"
)

func init() {
	experimental.PprofServer("0.0.0.0:8964")
}
