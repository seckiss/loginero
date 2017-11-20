package loginero

import (
	"sync"
)

type KeyValueStore interface {
	Get(k string) (v interface{}, err error)
	Set(k string, v interface{}) error
	Delete(k string) error
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

func (ss *RamStore) Set(k string, v interface{}) error {
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
