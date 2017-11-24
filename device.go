package loginero

import (
	"fmt"
)

// Device represents a browser and not a physical device
// It may be for example WebPush subscription that is stable per (browser, domain)

type Hasher interface {
	Hash() string
}

type DeviceManager interface {
	GetDeviceForSession(id string) (device Hasher, err error)
	SetDeviceForSession(session *Session, device Hasher) error
	DeleteDeviceForSession(sessionid string, device Hasher) error
	CurrentSessionForDevice(device Hasher) (id string, err error)
}

type StandardDeviceManager struct {
	Store KeyValueStore
}

// return empty string if session not found for device
func (dm *StandardDeviceManager) CurrentSessionForDevice(device Hasher) (id string, err error) {
	// first try to find named session id
	k := "device2sid:" + device.Hash()
	value, err := dm.Store.Get(k)
	if err != nil {
		return "", err
	}
	if value != nil {
		return value.(string), nil
	}
	// otherwise try to find anonymous session
	k = "device2bid:" + device.Hash()
	value, err = dm.Store.Get(k)
	if err != nil {
		return "", err
	}
	if value != nil {
		return value.(string), nil
	}
	return "", nil
}

func (dm *StandardDeviceManager) GetDeviceForSession(id string) (device Hasher, err error) {
	k := "id2device:" + id
	value, err := dm.Store.Get(k)
	fmt.Printf("2222\n")
	if err != nil {
		return nil, err
	}
	fmt.Printf("3333\n")
	if value == nil {
		return nil, nil
	}
	fmt.Printf("44444\n")
	device = value.(Hasher)
	// on a single device multiple sessions could have been created
	// return the device only when this is a device for its CURRENT session
	deviceSessionId, err := dm.CurrentSessionForDevice(device)
	fmt.Printf("devcieSeessionid=%+v\n", deviceSessionId)
	if err != nil {
		return nil, err
	}
	fmt.Printf("55555\n")
	fmt.Printf("dsid=%+v\n", deviceSessionId)
	fmt.Printf("  id=%+v\n", id)
	if deviceSessionId == id {
		fmt.Printf("666666\n")
		return device, nil
	}
	fmt.Printf("777777\n")
	return nil, nil
}

func (dm *StandardDeviceManager) SetDeviceForSession(session *Session, device Hasher) error {
	id := session.ID
	k := "id2device:" + id
	err := dm.Store.Put(k, device)
	if err != nil {
		return err
	}
	//save last session id that the device was attached to
	if session.Anon {
		k = "device2bid:" + device.Hash()
	} else {
		k = "device2sid:" + device.Hash()
	}
	return dm.Store.Put(k, id)
}

func (dm *StandardDeviceManager) DeleteDeviceForSession(sessionid string, device Hasher) error {
	k := "id2device:" + sessionid
	err := dm.Store.Delete(k)
	if err != nil {
		return err
	}
	dhash := device.Hash()
	err = dm.Store.Delete("device2bid:" + dhash)
	if err != nil {
		return err
	}
	err = dm.Store.Delete("device2sid:" + dhash)
	if err != nil {
		return err
	}
	return nil
}
