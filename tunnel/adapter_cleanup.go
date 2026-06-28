//go:build windows

package tunnel

import (
	"fmt"
	"strings"
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
	spdrpFriendlyName = 0x0C
	digcfAllClasses   = 0x04
)

type devInfoData struct {
	CBSize    uint32
	ClassGUID [16]byte
	DevInst   uint32
	Reserved  uintptr
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

func cleanupOldAdaptersViaSetupDi() {
	devInfoSet, err := setupDiGetClassDevs(nil, digcfAllClasses)
	if err != nil {
		return
	}
	defer setupDiDestroyDeviceInfoList(devInfoSet)

	for i := uint32(0); ; i++ {
		d, err := setupDiEnumDeviceInfo(devInfoSet, i)
		if err != nil {
			break
		}

		// Check by device instance ID (works for phantom/non-present devices too)
		instanceID := setupDiGetDeviceInstanceId(devInfoSet, d)
		if strings.HasPrefix(instanceID, "WINTUN\\") {
			removeDevice(devInfoSet, d, instanceID)
			continue
		}

		// Check by friendly name (works for present devices)
		name := setupDiGetDeviceRegistryProperty(devInfoSet, d, spdrpFriendlyName)
		if strings.HasPrefix(name, "Wintun") || name == "WireGuard Tunnel" {
			removeDevice(devInfoSet, d, name)
			continue
		}
	}
}

func cleanupOldAdapters() {
	cleanupOldAdaptersViaSetupDi()
}
