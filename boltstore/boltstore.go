package boltstore

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"fmt"
	"github.com/boltdb/bolt"
)

type BoltStore struct {
	db *bolt.DB
}

var (
	// ErrBadValue is returned when the value supplied to the Put method is nil
	ErrBadValue = errors.New("skv: bad value")

	bucketName = []byte("kv")
)

// Open a key-value store. "path" is the full path to the database file, any
// leading directories must have been created already. File is created with
// mode 0640 if needed.
//
// Because of BoltDB restrictions, only one process may open the file at a
// time. Attempts to open the file from another process will fail with a
// timeout error.
func Open(path string) (*BoltStore, error) {
	opts := &bolt.Options{
		Timeout: 50 * time.Millisecond,
	}
	if db, err := bolt.Open(path, 0640, opts); err != nil {
		return nil, err
	} else {
		err := db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(bucketName)
			return err
		})
		if err != nil {
			return nil, err
		} else {
			return &BoltStore{db: db}, nil
		}
	}
}

func (kvs *BoltStore) Put(key string, value interface{}) error {
	if value == nil {
		return ErrBadValue
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&value); err != nil {
		return err
	}
	return kvs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(key), buf.Bytes())
	})
}

func (kvs *BoltStore) Get(key string) (interface{}, error) {
	var p interface{}
	err := kvs.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		if k, v := c.Seek([]byte(key)); k == nil || string(k) != key {
			return nil
		} else {
			d := gob.NewDecoder(bytes.NewReader(v))
			return d.Decode(&p)
		}
	})
	return p, err
}

func (kvs *BoltStore) Delete(key string) error {
	return kvs.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		if k, _ := c.Seek([]byte(key)); k == nil || string(k) != key {
			return nil
		} else {
			return c.Delete()
		}
	})
}

func (kvs *BoltStore) GetArbitrary() (k string, v interface{}, err error) {
	//TODO implement
	return "", nil, nil
}

func (kvs *BoltStore) DumpStore() (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := kvs.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			key := string(k)
			var p interface{}
			d := gob.NewDecoder(bytes.NewReader(v))
			err := d.Decode(&p)
			if err != nil {
				return err
			}
			m[key] = p
			fmt.Printf("key=%s, value=%s\n", k, p)
		}
		return nil
	})
	return m, err
}

// Close closes the key-value store file.
func (kvs *BoltStore) Close() error {
	return kvs.db.Close()
}
