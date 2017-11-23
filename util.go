package loginero

import (
	"sync"
)

type KeyValueStore interface {
	Get(k string) (v interface{}, err error)
	Put(k string, v interface{}) error
	Delete(k string) error
	// Get arbitrary item from the KV store, necessary for store houskeeping
	// eg. deleting expired sessions and related devices
	GetArbitrary() (k string, v interface{}, err error)
}

// Universal API key-value store
type RamStore struct {
	Map      map[string]interface{}
	MapMutex sync.RWMutex
}

func NewRamStore() *RamStore {
	return &RamStore{
		Map: make(map[string]interface{}),
	}
}

func (ss *RamStore) Get(k string) (interface{}, error) {
	ss.MapMutex.RLock()
	defer ss.MapMutex.RUnlock()
	v := ss.Map[k]
	return v, nil
}

func (ss *RamStore) Put(k string, v interface{}) error {
	ss.MapMutex.Lock()
	defer ss.MapMutex.Unlock()
	ss.Map[k] = v
	return nil
}

func (ss *RamStore) Delete(k string) error {
	ss.MapMutex.Lock()
	defer ss.MapMutex.Unlock()
	delete(ss.Map, k)
	return nil
}

func (ss *RamStore) GetArbitrary() (k string, v interface{}, err error) {
	//TODO implement
	return "", nil, nil
}
