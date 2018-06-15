package main

import (
	"testing"
	"time"
)

func TestHash_Stringash_String1(t *testing.T) {
	array_origin := make([]int, 100000)
	for i := 0; i < 100000; i++ {
		array_origin[i] = i + 1
	}

	array := make([]int, 100000)
	copy(array, array_origin)

	ti:= time.Now()
	for i := 0; i < 100000; i++ {
		if len(array) > 0{
			for j := len(array)-1; j < len(array)-1; j++ {
				array[j] = array[j+1]
			}
			array = array[:len(array)-1]

		}
	}

	t.Log(len(array),time.Now().Sub(ti))
}
func TestHash_Stringash_String(t *testing.T) {

	//index := 50000
	array_origin := make([]int, 100000)
	for i := 0; i < 100000; i++ {
		array_origin[i] = i + 1
	}

	array := make([]int, 100000)
	copy(array, array_origin)
	ti:= time.Now()
	for i := 0; i < 100000; i++ {
		for j := 0; j < len(array); j++ {
			if len(array)-1 == j {
				array = append(array[:j], array[j+1:]...)
				break
			}
		}

		t.Log(len(array))
	}

	t.Log(len(array),time.Now().Sub(ti))


}
