//go:build windows

package tunnel

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSetupapi                              = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsW                 = modSetupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiDestroyDeviceInfoList         = modSetupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procSetupDiEnumDeviceInfo                = modSetupapi.NewProc("SetupDiEnumDeviceInfo")
	procSetupDiGetDeviceRegistryPropertyW    = modSetupapi.NewProc("SetupDiGetDeviceRegistryPropertyW")
	procSetupDiRemoveDevice                  = modSetupapi.NewProc("SetupDiRemoveDevice")
	procSetupDiGetDeviceInstanceIdW          = modSetupapi.NewProc("SetupDiGetDeviceInstanceIdW")
)

const (
	digcfPresent       = 0x02
	spdrpFriendlyName  = 0x0C
)

type devInfoData struct {
	CBSize    uint32
	ClassGUID [16]byte
	DevInst   uint32
	Reserved  uintptr
}

var guidDevclassNet = windows.GUID{
	Data1: 0x4D36E972,
	Data2: 0xE325,
	Data3: 0x11CE,
	Data4: [8]byte{0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18},
}

func setupDiGetClassDevs(classGuid *windows.GUID, flags uint32) (uintptr, error) {
	ret, _, err := procSetupDiGetClassDevsW.Call(
		uintptr(unsafe.Pointer(classGuid)),
		0, 0,
		uintptr(flags),
	)
	if ret == 0 || ret == ^uintptr(0) {
		return 0, fmt.Errorf("SetupDiGetClassDevs: %v", err)
	}
	return ret, nil
}

func setupDiDestroyDeviceInfoList(devInfoSet uintptr) {
	procSetupDiDestroyDeviceInfoList.Call(devInfoSet)
}

func setupDiEnumDeviceInfo(devInfoSet uintptr, index uint32) (*devInfoData, error) {
	var d devInfoData
	d.CBSize = uint32(unsafe.Sizeof(d))
	ret, _, err := procSetupDiEnumDeviceInfo.Call(
		uintptr(devInfoSet),
		uintptr(index),
		uintptr(unsafe.Pointer(&d)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("SetupDiEnumDeviceInfo: %v", err)
	}
	return &d, nil
}

func setupDiGetDeviceRegistryProperty(devInfoSet uintptr, d *devInfoData, property uint32) string {
	var dataType, requiredSize uint32
	procSetupDiGetDeviceRegistryPropertyW.Call(
		uintptr(devInfoSet),
		uintptr(unsafe.Pointer(d)),
		uintptr(property),
		0, 0, 0,
		uintptr(unsafe.Pointer(&requiredSize)),
		uintptr(unsafe.Pointer(&dataType)),
	)
	if requiredSize == 0 {
		return ""
	}
	buf := make([]byte, requiredSize)
	ret, _, _ := procSetupDiGetDeviceRegistryPropertyW.Call(
		uintptr(devInfoSet),
		uintptr(unsafe.Pointer(d)),
		uintptr(property),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&requiredSize)),
		uintptr(unsafe.Pointer(&dataType)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0])))
}

func setupDiRemoveDevice(devInfoSet uintptr, d *devInfoData) bool {
	ret, _, _ := procSetupDiRemoveDevice.Call(
		uintptr(devInfoSet),
		uintptr(unsafe.Pointer(d)),
	)
	return ret != 0
}

func setupDiGetDeviceInstanceId(devInfoSet uintptr, d *devInfoData) string {
	var requiredSize uint32
	procSetupDiGetDeviceInstanceIdW.Call(
		uintptr(devInfoSet),
		uintptr(unsafe.Pointer(d)),
		0, 0,
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if requiredSize == 0 {
		return ""
	}
	buf := make([]uint16, requiredSize)
	ret, _, _ := procSetupDiGetDeviceInstanceIdW.Call(
		uintptr(devInfoSet),
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

func removeDevice(devInfoSet uintptr, d *devInfoData, name string) {
	instanceID := setupDiGetDeviceInstanceId(devInfoSet, d)
	ok := setupDiRemoveDevice(devInfoSet, d)
	if ok {
		fmt.Printf("[cleanup] Removed zombie adapter: %s (instance: %s)\n", name, instanceID)
	} else {
		fmt.Printf("[cleanup] Failed to remove adapter: %s (instance: %s)\n", name, instanceID)
	}
}

func getActiveTunnelIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip != nil && ip.To4() != nil {
				ipStr := ip.String()
				if len(ipStr) >= 9 && ipStr[:9] == "172.16.0." {
					return ipStr
				}
			}
		}
	}
	return ""
}

func cleanupOldAdaptersViaSetupDi() {
	activeIP := getActiveTunnelIP()

	devInfoSet, err := setupDiGetClassDevs(&guidDevclassNet, digcfPresent)
	if err != nil {
		return
	}
	defer setupDiDestroyDeviceInfoList(devInfoSet)

	for i := uint32(0); ; i++ {
		d, err := setupDiEnumDeviceInfo(devInfoSet, i)
		if err != nil {
			break
		}

		name := setupDiGetDeviceRegistryProperty(devInfoSet, d, spdrpFriendlyName)
		if name != "Wintun Userspace Tunnel" && name != "Wintun Userspace Tunnel #2" && name != "WireGuard Tunnel" {
			continue
		}

		if activeIP != "" && name == "WireGuard Tunnel" {
			continue
		}

		removeDevice(devInfoSet, d, name)
	}
}

func cleanupOldAdapters() {
	cleanupOldAdaptersViaSetupDi()
}
