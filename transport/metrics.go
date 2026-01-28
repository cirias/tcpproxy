package transport

import (
	"expvar"
)

var (
	metrics = expvar.NewMap("proxy")
	
	ConnActive = new(expvar.Int)
	ConnTotal  = new(expvar.Int)
	BytesTX    = new(expvar.Int)
	BytesRX    = new(expvar.Int)
	NetErrors  = new(expvar.Int)
)

func init() {
	metrics.Set("conn_active", ConnActive)
	metrics.Set("conn_total", ConnTotal)
	metrics.Set("bytes_tx", BytesTX)
	metrics.Set("bytes_rx", BytesRX)
	metrics.Set("net_errors", NetErrors)
}
