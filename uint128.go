package cityhash

import (
	"encoding/binary"
)

type Uint128 [2]uint64

func (unit *Uint128) setLower64(l uint64) {
	unit[0] = l
}

func (unit *Uint128) setHigher64(h uint64) {
	unit[1] = h
}

func (unit Uint128) Lower64() uint64 {
	return unit[0]
}

func (unit Uint128) Higher64() uint64 {
	return unit[1]
}

func (unit Uint128) Bytes() []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, unit[0])
	binary.LittleEndian.PutUint64(b[8:], unit[1])
	return b
}
