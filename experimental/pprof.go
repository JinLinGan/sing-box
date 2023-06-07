package experimental

import (
	"encoding/json"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"runtime/debug"

	"github.com/sagernet/sing-box/common/badjson"
	"github.com/sagernet/sing-box/log"

	"github.com/dustin/go-humanize"
)

func PprofServer(addr string) {
	http.HandleFunc("/debug/gc", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
		go debug.FreeOSMemory()
	})
	http.HandleFunc("/debug/memory", func(writer http.ResponseWriter, request *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		var memObject badjson.JSONObject
		memObject.Put("heap", humanize.IBytes(memStats.HeapInuse))
		memObject.Put("stack", humanize.IBytes(memStats.StackInuse))
		memObject.Put("idle", humanize.IBytes(memStats.HeapIdle-memStats.HeapReleased))
		memObject.Put("goroutines", runtime.NumGoroutine())
		memObject.Put("rss", rusageMaxRSS())

		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		encoder.Encode(memObject)
	})
	go func() {
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			log.Debug(err)
		}
	}()
}
