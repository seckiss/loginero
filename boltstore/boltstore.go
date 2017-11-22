package boltstore

import (
	"bytes"
	"encoding/gob"
)

var network bytes.Buffer // Stand-in for the network.
var enc = gob.NewEncoder(&network)
var dec = gob.NewDecoder(&network)

func Put(p interface{}) error {
	// The encode will fail unless the concrete type has been
	// registered. We registered it in the calling function.

	// Pass pointer to interface so Encode sees (and hence sends) a value of
	// interface type. If we passed p directly it would see the concrete type instead.
	// See the blog post, "The Laws of Reflection" for background.
	return enc.Encode(&p)
}

func Get() (interface{}, error) {
	// The decode will fail unless the concrete type on the wire has been
	// registered. We registered it in the calling function.
	var p interface{}
	err := dec.Decode(&p)
	return p, err
}
