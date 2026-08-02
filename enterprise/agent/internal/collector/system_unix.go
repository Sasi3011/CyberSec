//go:build !windows

package collector

func windowsCPUPercent() float64  { return 0 }
func windowsRAMPercent() float64  { return 0 }
func windowsDiskPercent() float64 { return 0 }
