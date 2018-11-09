package cityhash

import (
	"encoding/binary"
	"hash"
)

const (
	c1 uint32 = 0xcc9e2d51
	c2 uint32 = 0x1b873593
	c3 uint32 = 0xe6546b64
)

type Hash32 struct {
	s []byte
}

func Sum32(s []byte) uint32 {
	h := New32()
	h.Write(s)
	return h.Sum32()
}

func New32() hash.Hash32 {
	return &Hash32{}
}

func (city *Hash32) Sum(b []byte) []byte {
	b2 := make([]byte, 4)
	binary.BigEndian.PutUint32(b2, city.Sum32())
	b = append(b, b2...)
	return b
}

func (city *Hash32) Sum32() uint32 {
	s := city.s
	length := uint32(len(s))

	if length <= 4 {
		return hash32Len0to4(s, length)
	} else if length <= 12 {
		return hash32Len5to12(s, length)
	} else if length <= 24 {
		return hash32Len13to24(s, length)
	}

	a0 := rotate32(fetch32(s[length-4:])*c1, 17) * c2
	a1 := rotate32(fetch32(s[length-8:])*c1, 17) * c2
	a2 := rotate32(fetch32(s[length-16:])*c1, 17) * c2
	a3 := rotate32(fetch32(s[length-12:])*c1, 17) * c2
	a4 := rotate32(fetch32(s[length-20:])*c1, 17) * c2

	h := rotate32(length^a0, 19)*5 + c3
	h = rotate32(h^a2, 19)*5 + c3
	g := rotate32((c1*length)^a1, 19)*5 + c3
	g = rotate32(g^a3, 19)*5 + c3
	f := rotate32((c1*length)+a4, 19)*5 + c3

	for i := (length - 1) / 20; i > 0; i-- {
		a0 := rotate32(fetch32(s)*c1, 17) * c2
		a1 := fetch32(s[4:])
		a2 := rotate32(fetch32(s[8:])*c1, 17) * c2
		a3 := rotate32(fetch32(s[12:])*c1, 17) * c2
		a4 := fetch32(s[16:])
		h = rotate32(h^a0, 18)*5 + c3
		f = rotate32(f+a1, 19) * c1
		g = rotate32(g+a2, 18)*5 + c3
		h = rotate32(h^(a3+a1), 19)*5 + c3
		g = bswap32(g^a4) * 5
		h = bswap32(h + (a4 * 5))
		f += a0
		f, h, g = g, f, h
		s = s[20:]
	}

	g = rotate32(g, 11) * c1
	g = rotate32(g, 17) * c1
	f = rotate32(f, 11) * c1
	f = rotate32(f, 17) * c1
	h = rotate32(h+g, 19)
	h = rotate32(h*5+c3, 17) * c1
	h = rotate32(h+f, 19)
	h = rotate32(h*5+c3, 17) * c1
	return h

}

func (city *Hash32) Reset() {
	city.s = city.s[0:0]
}

func (city *Hash32) BlockSize() int {
	return 32
}

func (city *Hash32) Write(s []byte) (n int, err error) {
	city.s = append(city.s, s...)
	return len(s), nil
}

func (city *Hash32) Size() int {
	return 4
}

func bswap32(x uint32) uint32 { // Copied from netbsd's bswap32.c
	return ((x << 24) & 0xff000000) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | ((x >> 24) & 0x000000ff)
}

func fmix(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

func rotate32(val uint32, shift uint32) uint32 { // Avoid shifting by 32: doing so yields an undefined result.
	return ((val >> shift) | (val << (32 - shift)))
}

func mur(a, h uint32) uint32 {
	a = rotate32(a*c1, 17) * c2
	return rotate32(h^a, 19)*5 + c3
}

func fetch32(p []byte) uint32 {
	return binary.LittleEndian.Uint32(p)
}

func hash32Len13to24(s []byte, length uint32) uint32 {
	a := fetch32(s[(length>>1)-4:])
	b := fetch32(s[4:])
	c := fetch32(s[length-8:])
	d := fetch32(s[(length >> 1):])
	e := fetch32(s)
	f := fetch32(s[length-4:])
	h := length
	return fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))))
}

func hash32Len0to4(s []byte, length uint32) uint32 {
	var b, c uint32 = 0, 9
	tmp := s[:length]
	for _, v := range tmp {
		b = uint32(int64(b)*int64(c1) + int64(int8(v)))
		c ^= b
	}
	return fmix(mur(b, mur(length, c)))
}

func hash32Len5to12(s []byte, length uint32) uint32 {
	a := length + fetch32(s)
	b := length*5 + fetch32(s[length-4:])
	c := 9 + fetch32(s[((length>>1)&4):])
	return fmix(mur(c, mur(b, mur(a, length*5))))
}
