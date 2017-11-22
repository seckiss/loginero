package main

import (
	"../../boltstore"
	"encoding/gob"
	"fmt"
)

type Point struct {
	X, Y int
}

func main() {
	gob.Register(Point{})
	_ = gob.Register

	bs, err := boltstore.Open("/tmp/kvtest.db")
	if err != nil {
		panic(err)
	}

	err = bs.Put("key1", Point{X: 3, Y: 7})
	if err != nil {
		panic(err)
	}
	res, err := bs.Get("key1")
	if err != nil {
		panic(err)
	}

	fmt.Printf("res=%+v\n", res)

	bs.Close()
}
