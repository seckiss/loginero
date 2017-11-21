package loginero

// Device represents a browser and not a physical device
// It may be for example WebPush subscription that is stable per (browser, domain)

type DeviceManager interface {
	GetDeviceForSession(sid string) (device interface{}, err error)
	SetDeviceForSession(sid string, device interface{}) error
}

type StandardDeviceManager struct {
	Store KeyValueStore
}

func (dm *StandardDeviceManager) GetDeviceForSession(sid string) (device interface{}, err error) {
	return dm.Store.Get(sid)
}
func (dm *StandardDeviceManager) SetDeviceForSession(sid string, device interface{}) error {
	return dm.Store.Set(sid, device)
}
