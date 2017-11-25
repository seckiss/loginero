package loginero

import (
	"strings"
	"sync"
)

type TypeKeyValueStore interface {
	Get(typ string, key string) (v interface{}, err error)
	Put(typ string, key string, v interface{}) error
	Delete(typ string, key string) error
	// Get arbitrary item from the KV store, necessary for store houskeeping
	// eg. deleting expired sessions and related devices
	GetArbitrary() (typ string, key string, v interface{}, err error)
}

func (o StoreAdapter) Get(typ string, key string) (v interface{}, err error) {
	return o.KVStore.Get(typ + ":" + key)
}
func (o StoreAdapter) Put(typ string, key string, v interface{}) error {
	return o.KVStore.Put(typ+":"+key, v)
}
func (o StoreAdapter) Delete(typ string, key string) error {
	return o.KVStore.Delete(typ + ":" + key)
}
func (o StoreAdapter) GetArbitrary() (typ string, key string, v interface{}, err error) {
	tk, v, err := o.KVStore.GetArbitrary()
	ind := strings.Index(tk, ":")
	if ind <= 0 {
		return "", tk, v, err
	} else {
		return tk[:ind], tk[ind+1:], v, err
	}
}

type StoreAdapter struct {
	KVStore KeyValueStore
}

func New(kvstore KeyValueStore) TypeKeyValueStore {
	return StoreAdapter{kvstore}
}

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
