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

	//boltstore.Put("eeee")
	err := boltstore.Put(Point{X: 3, Y: 7})
	if err != nil {
		panic(err)
	}
	res, err := boltstore.Get()
	if err != nil {
		panic(err)
	}

	fmt.Printf("res=%+v\n", res)
}
