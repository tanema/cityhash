package cityhash

import (
	"encoding/binary"
	"hash"
)

const (
	k0 uint64 = 0xc3a5c85c97cb3127
	k1 uint64 = 0xb492b66fbe98f273
	k2 uint64 = 0x9ae16a3b2f90404f
)

type Hash64 struct {
	s []byte
}

func Sum64(s []byte) uint64 {
	h := New64()
	h.Write(s)
	return h.Sum64()
}

func New64() hash.Hash64 {
	return &Hash64{}
}

func (city *Hash64) Sum(b []byte) []byte {
	b2 := make([]byte, 8)
	binary.BigEndian.PutUint64(b2, city.Sum64())
	b = append(b, b2...)
	return b
}

func (city *Hash64) Sum64() uint64 {
	s := city.s
	length := uint32(len(s))

	if length <= 16 {
		return hashLen0to16(s)
	} else if length <= 32 {
		return hashLen17to32(s)
	} else if length <= 64 {
		return hashLen33to64(s)
	}

	x := fetch64(s[length-40:])
	y := fetch64(s[length-16:]) + fetch64(s[length-56:])
	z := hashLen16(fetch64(s[length-48:])+uint64(length), fetch64(s[length-24:]))
	v := weakHashLen32WithSeeds3(s[length-64:], uint64(length), z)
	w := weakHashLen32WithSeeds3(s[length-32:], y+k1, x)
	x = x*k1 + fetch64(s)

	for i := (length - 1) & ^uint32(63); i > 0; i -= 64 {
		x = rotate64(x+y+v.Lower64()+fetch64(s[8:]), 37) * k1
		y = rotate64(y+v.Higher64()+fetch64(s[48:]), 42) * k1
		x ^= w.Higher64()
		y += v.Lower64() + fetch64(s[40:])
		z = rotate64(z+w.Lower64(), 33) * k1
		v = weakHashLen32WithSeeds3(s, v.Higher64()*k1, x+w.Lower64())
		w = weakHashLen32WithSeeds3(s[32:], z+w.Higher64(), y+fetch64(s[16:]))
		z, x = x, z
		s = s[64:]
	}

	return hashLen16(hashLen16(v.Lower64(), w.Lower64())+shiftMix(y)*k1+z, hashLen16(v.Higher64(), w.Higher64())+x)
}

func (city *Hash64) Reset() {
	city.s = city.s[0:0]
}

func (city *Hash64) BlockSize() int {
	return 64
}

func (city *Hash64) Write(s []byte) (n int, err error) {
	city.s = append(city.s, s...)
	return len(s), nil
}

func (city *Hash64) Size() int {
	return 8
}

func rotate64(val uint64, shift uint32) uint64 { // Avoid shifting by 64: doing so yields an undefined result.
	return ((val >> shift) | (val << (64 - shift)))
}

func fetch64(p []byte) uint64 {
	return binary.LittleEndian.Uint64(p)
}

func shiftMix(val uint64) uint64 {
	return val ^ (val >> 47)
}

func hash128to64(x Uint128) uint64 { // Murmur-inspired hashing.
	const mul uint64 = 0x9ddfea08eb382d69
	a := (x.Lower64() ^ x.Higher64()) * mul
	a ^= (a >> 47)
	b := (x.Higher64() ^ a) * mul
	b ^= (b >> 47)
	b *= mul
	return b
}

func weakHashLen32WithSeeds3(s []byte, a, b uint64) Uint128 {
	w, x, y, z := fetch64(s), fetch64(s[8:]), fetch64(s[16:]), fetch64(s[24:])
	a += w
	b = rotate64(b+a+z, 21)
	c := a
	a += x
	a += y
	b += rotate64(a, 44)
	return Uint128{a + z, b + c}
}

func hashLen16(u, v uint64) uint64 {
	return hash128to64(Uint128{u, v})
}

func hashLen163(u, v, mul uint64) uint64 { // Murmur-inspired hashing.
	a := (u ^ v) * mul
	a ^= (a >> 47)
	b := (v ^ a) * mul
	b ^= (b >> 47)
	b *= mul
	return b
}

func hashLen17to32(s []byte) uint64 {
	length := uint32(len(s))
	mul := k2 + uint64(length)*2
	a := fetch64(s) * k1
	b := fetch64(s[8:])
	c := fetch64(s[length-8:]) * mul
	d := fetch64(s[length-16:]) * k2
	return hashLen163(rotate64(a+b, 43)+rotate64(c, 30)+d, a+rotate64(b+k2, 18)+c, mul)
}

func hashLen0to16(s []byte) uint64 {
	length := uint32(len(s))
	if length >= 8 {
		mul := k2 + uint64(length)*2
		a := fetch64(s) + k2
		b := fetch64(s[length-8:])
		c := rotate64(b, 37)*mul + a
		d := (rotate64(a, 25) + b) * mul
		return hashLen163(c, d, mul)
	}

	if length >= 4 {
		mul := k2 + uint64(length)*2
		a := uint64(fetch32(s))
		return hashLen163(uint64(length)+(a<<3), uint64(fetch32(s[length-4:])), mul)
	}

	if length > 0 {
		a := uint8(s[0])
		b := uint8(s[length>>1])
		c := uint8(s[length-1])
		y := uint32(a) + (uint32(b) << 8)
		z := length + (uint32(c) << 2)
		return shiftMix(uint64(y)*k2^uint64(z)*k0) * k2
	}

	return k2
}

func bswap64(x uint64) uint64 { // Copied from netbsd's bswap64.c
	return ((x << 56) & 0xff00000000000000) |
		((x << 40) & 0x00ff000000000000) |
		((x << 24) & 0x0000ff0000000000) |
		((x << 8) & 0x000000ff00000000) |
		((x >> 8) & 0x00000000ff000000) |
		((x >> 24) & 0x0000000000ff0000) |
		((x >> 40) & 0x000000000000ff00) |
		((x >> 56) & 0x00000000000000ff)
}

func hashLen33to64(s []byte) uint64 {
	length := uint32(len(s))
	mul := k2 + uint64(length)*2
	a := fetch64(s) * k2
	b := fetch64(s[8:])
	c := fetch64(s[length-24:])
	d := fetch64(s[length-32:])
	e := fetch64(s[16:]) * k2
	f := fetch64(s[24:]) * 9
	g := fetch64(s[length-8:])
	h := fetch64(s[length-16:]) * mul
	u := rotate64(a+g, 43) + (rotate64(b, 30)+c)*9
	v := ((a + g) ^ d) + f + 1
	w := bswap64((u+v)*mul) + h
	x := rotate64(e+f, 42) + c
	y := (bswap64((v+w)*mul) + g) * mul
	z := e + f + c
	a = bswap64((x+z)*mul+y) + b
	b = shiftMix((z+a)*mul+d+h) * mul
	return b + x
}
