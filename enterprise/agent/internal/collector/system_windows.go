//go:build windows

package collector

import (
	"os/exec"
	"strconv"
	"strings"
)

func windowsCPUPercent() float64 {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average").Output()
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	return v
}

func windowsRAMPercent() float64 {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"$o=Get-CimInstance Win32_OperatingSystem; [math]::Round((1-$o.FreePhysicalMemory/$o.TotalVisibleMemorySize)*100,1)").Output()
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	return v
}

func windowsDiskPercent() float64 {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\"; if($d){[math]::Round(($d.Size-$d.FreeSpace)/$d.Size*100,1)}else{0}").Output()
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	return v
}
