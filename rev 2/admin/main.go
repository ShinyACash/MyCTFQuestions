package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"runtime"
)

func deriveMagic() uint32 {
	a := uint32(0x6334) << 16  
	b := uint32(0x7363)        
	c := uint32(runtime.NumCPU()) * 0 
	return (a | b) + c
}

func junkWorker(wg *sync.WaitGroup, in <-chan byte, out chan<- byte, noiseSeed byte) {
	defer wg.Done()
	for b := range in {
		// Looks like real transform logic but output is discarded
		out <- b ^ noiseSeed ^ 0xAB
	}
	close(out)
}

func transformWorker(in <-chan byte, out chan<- byte) {
	m := deriveMagic()
	i := 0
	for b := range in {
		shift := uint((i % 4) * 8)
		mask := byte((m >> shift) & 0xFF)
		out <- b ^ mask
		i++
	}
	close(out)
}

func checkWorker(in <-chan byte, result chan<- bool) {
	expected := []byte{0x57, 0x3F, 0x78, 0x3C, 0x53, 0x05, 0x07, 0x11}

	i := 0
	ok := true
	for b := range in {
		if i >= len(expected) || b != expected[i] {
			ok = false
		}
		i++
	}
	if i != len(expected) {
		ok = false
	}
	result <- ok
}

type lengthChecker interface {
	check(s string) bool
}

type exactLength struct{ n int }

func (e exactLength) check(s string) bool { return len(s) == e.n }

func main() {
	fmt.Print("Enter all 3 shards (space separated): ")

	var s1, s2, s3 string
	fmt.Fscan(os.Stdin, &s1, &s2, &s3)
	s1 = strings.TrimSpace(s1)
	s2 = strings.TrimSpace(s2)
	s3 = strings.TrimSpace(s3)

	var lc lengthChecker = exactLength{n: 12}  // HTB{c4r_k3ys
	lc2 := exactLength{n: 10}                  // _sc4tt3r3d
	lc3 := exactLength{n: 8}                   // 4LL_0v3r
	if !lc.check(s1) || !lc2.check(s2) || !lc3.check(s3) {
		fmt.Println("Wrong.")
		os.Exit(1)
	}

	rawCh     := make(chan byte, 8)
	xformedCh := make(chan byte, 8)
	resultCh  := make(chan bool, 1)

	junkIn1  := make(chan byte, 8)
	junkOut1 := make(chan byte, 8)
	junkIn2  := make(chan byte, 8)
	junkOut2 := make(chan byte, 8)

	var wg sync.WaitGroup
	wg.Add(2)
	go junkWorker(&wg, junkIn1, junkOut1, 0x13)
	go junkWorker(&wg, junkIn2, junkOut2, 0x37)

	go transformWorker(rawCh, xformedCh)
	go checkWorker(xformedCh, resultCh)

	go func() {
		for i := 0; i < len(s3); i++ {
			junkIn1 <- s3[i]
			junkIn2 <- s3[i]
		}
		close(junkIn1)
		close(junkIn2)
	}()
	go func() { for range junkOut1 {} }()
	go func() { for range junkOut2 {} }()

	for i := 0; i < len(s3); i++ {
		rawCh <- s3[i]
	}
	close(rawCh)

	wg.Wait()

	if <-resultCh {
		revealFlag(s1, s2, s3)
	} else {
		fmt.Println("Wrong.")
	}
}

func revealFlag(shard1, shard2, shard3 string) {
	combined := shard1 + shard2 + shard3
	var seed uint32 = 2166136261 
	for i := 0; i < len(combined); i++ {
		seed ^= uint32(combined[i])
		seed *= 16777619 
	}

	cbytes := []byte(combined)
	for i := range cbytes { cbytes[i] = 0 }
	runtime.KeepAlive(cbytes)

	pad := []byte{
		0x28, 0xDD, 0xD6, 0x6E, 0x1E, 0xF6, 0x76, 0x19,
		0xB0, 0x5A, 0xF1, 0xF7, 0xE2, 0x43, 0x52, 0xE8,
		0x87, 0x01, 0x71, 0xFF, 0xDC, 0x83, 0x56, 0x93,
		0xF5, 0x52, 0x6E, 0x26, 0xCE, 0x79, 0x51, 0xD8,
		0x17, 0xC9, 0x67, 0xFE, 0xAC, 0x5D, 0x48, 0x10,
		0xE6, 0x31, 0x3C, 0x4C,
	}

	state := seed
	tail := make([]byte, len(pad))
	for i := range pad {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		tail[i] = byte(state&0xFF) ^ pad[i]
	}

	fmt.Printf("Correct! Shard 3: _%s%s\n", shard3, tail)

	for i := range tail { tail[i] = 0 }
	for i := range pad  { pad[i]  = 0 }
	runtime.KeepAlive(tail)
	runtime.KeepAlive(pad)
}