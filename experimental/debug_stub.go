//go:build !linux

package experimental

func rusageMaxRSS() float64 {
	return -1
}
