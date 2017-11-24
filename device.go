package loginero

// Device represents a browser and not a physical device
// It may be for example WebPush subscription that is stable per (browser, domain)

type Hasher interface {
	Hash() string
}

type DeviceManager interface {
	GetDeviceForSession(sid string) (device Hasher, err error)
	SetDeviceForSession(sid string, device Hasher) error
}

type StandardDeviceManager struct {
	Store KeyValueStore
}

func (dm *StandardDeviceManager) GetDeviceForSession(sid string) (device Hasher, err error) {
	k := "sid2device:" + sid
	value, err := dm.Store.Get(k)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	return value.(Hasher), err
}
func (dm *StandardDeviceManager) SetDeviceForSession(sid string, device Hasher) error {
	k := "sid2device:" + sid
	return dm.Store.Put(k, device)
}
