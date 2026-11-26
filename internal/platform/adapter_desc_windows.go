//go:build windows

package platform

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	defaultAdapterName        = "TLAN"
	defaultAdapterDescription = "TLAN Ethernet Adapter"
)

var (
	wintunTunnelTypeOnce sync.Once
	netAdapterClassGUID  = windows.GUID{
		Data1: 0x4D36E972,
		Data2: 0xE325,
		Data3: 0x11CE,
		Data4: [8]byte{0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18},
	}
)

func configureWintunTunnelType() {
	wintunTunnelTypeOnce.Do(func() {
		tun.WintunTunnelType = defaultAdapterName
	})
}

func createWintunTunnel(name string, requestedGUID *windows.GUID, mtu int) (tun.Device, error) {
	configureWintunTunnelType()
	device, err := tun.CreateTUNWithRequestedGUID(name, requestedGUID, mtu)
	if err != nil {
		return nil, err
	}
	if requestedGUID != nil {
		if err := setAdapterDescriptionWithRetry(requestedGUID.String(), defaultAdapterDescription); err != nil {
			_ = device.Close()
			return nil, fmt.Errorf("set Wintun adapter description: %w", err)
		}
	}
	return device, nil
}

func setAdapterDescriptionWithRetry(adapterGUID, description string) error {
	var lastErr error
	for range 20 {
		err := setAdapterDescriptionByGUID(adapterGUID, description)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

func setAdapterDescriptionByGUID(adapterGUID, description string) error {
	return visitAdapterByGUID(adapterGUID, registry.QUERY_VALUE|registry.SET_VALUE, func(devInfo windows.DevInfo, devData *windows.DevInfoData, key registry.Key) error {
		if err := key.SetStringValue("DriverDesc", description); err != nil {
			return fmt.Errorf("write DriverDesc: %w", err)
		}
		if err := devInfo.SetDeviceRegistryPropertyString(devData, windows.SPDRP_DEVICEDESC, description); err != nil {
			return fmt.Errorf("set SPDRP_DEVICEDESC: %w", err)
		}
		if err := devInfo.SetDeviceRegistryPropertyString(devData, windows.SPDRP_FRIENDLYNAME, description); err != nil {
			return fmt.Errorf("set SPDRP_FRIENDLYNAME: %w", err)
		}
		return nil
	})
}

func visitAdapterByGUID(adapterGUID string, samDesired uint32, fn func(windows.DevInfo, *windows.DevInfoData, registry.Key) error) error {
	target := normalizeAdapterGUID(adapterGUID)
	if target == "" {
		return errors.New("empty adapter GUID")
	}
	devInfo, err := windows.SetupDiGetClassDevsEx(&netAdapterClassGUID, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return err
	}
	defer devInfo.Close()

	for index := 0; ; index++ {
		devData, err := devInfo.EnumDeviceInfo(index)
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			return err
		}
		handle, err := devInfo.OpenDevRegKey(devData, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, samDesired)
		if err != nil {
			continue
		}
		key := registry.Key(handle)
		instanceID, _, idErr := key.GetStringValue("NetCfgInstanceId")
		if idErr != nil || normalizeAdapterGUID(instanceID) != target {
			_ = key.Close()
			continue
		}
		err = fn(devInfo, devData, key)
		_ = key.Close()
		return err
	}
	return fmt.Errorf("network adapter %s not found in PnP class", adapterGUID)
}

func normalizeAdapterGUID(value string) string {
	trimmed := strings.TrimSpace(strings.ToUpper(value))
	trimmed = strings.TrimPrefix(trimmed, "{")
	trimmed = strings.TrimSuffix(trimmed, "}")
	if trimmed == "" {
		return ""
	}
	return "{" + trimmed + "}"
}

// QueryAdapterDescription returns the Windows PnP/driver description configured
// for the named network adapter (reported by Get-NetAdapter InterfaceDescription
// and Windows Device Manager).
func QueryAdapterDescription(name string) (string, error) {
	guid, present, err := queryAdapterGUID(name)
	if err != nil {
		return "", err
	}
	if !present {
		return "", fmt.Errorf("adapter %q not found", name)
	}
	var desc string
	err = visitAdapterByGUID(guid, registry.QUERY_VALUE, func(devInfo windows.DevInfo, devData *windows.DevInfoData, key registry.Key) error {
		driverDesc, _, dErr := key.GetStringValue("DriverDesc")
		if dErr != nil {
			return fmt.Errorf("read DriverDesc: %w", dErr)
		}
		friendly, fErr := devInfo.DeviceRegistryProperty(devData, windows.SPDRP_FRIENDLYNAME)
		if fErr != nil {
			return fmt.Errorf("read SPDRP_FRIENDLYNAME: %w", fErr)
		}
		friendlyStr, _ := friendly.(string)
		if friendlyStr != driverDesc {
			return fmt.Errorf("description mismatch: DriverDesc=%q FriendlyName=%q", driverDesc, friendlyStr)
		}
		desc = friendlyStr
		return nil
	})
	return desc, err
}
