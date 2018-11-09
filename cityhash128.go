package cityhash

func cityMurmur(s []byte, length uint32, seed Uint128) Uint128 {
	a := seed.Lower64()
	b := seed.Higher64()
	var c, d uint64
	l := int32(length) - 16

	if l <= 0 { // len <= 16
		a = shiftMix(a*k1) * k1
		c = b*k1 + hashLen0to16(s, length)

		if length >= 8 {
			d = shiftMix(a + fetch64(s))
		} else {
			d = shiftMix(a + c)
		}
	} else { // len > 16
		c = hashLen16(fetch64(s[length-8:])+k1, a)
		d = hashLen16(b+uint64(length), c+fetch64(s[length-16:]))
		a += d

		for {
			a ^= shiftMix(fetch64(s)*k1) * k1
			a *= k1
			b ^= a
			c ^= shiftMix(fetch64(s[8:])*k1) * k1
			c *= k1
			d ^= c
			s = s[16:]
			l -= 16

			if l <= 0 {
				break
			}
		}
	}

	a = hashLen16(a, c)
	b = hashLen16(d, b)
	return Uint128{a ^ b, hashLen16(b, a)}
}

func CityHash128(s []byte) Uint128 {
	length := uint32(len(s))
	seed := Uint128{k0, k1}

	if length >= 16 {
		seed = Uint128{fetch64(s), fetch64(s[8:length]) + k0}
		s = s[16:length]
		length = length - 16
	}

	if length < 128 {
		return cityMurmur(s, length, seed)
	}

	origLength := length
	t := s

	// We expect length >= 128 to be the common case.  Keep 56 bytes of state:
	// v, w, x, y, and z.
	var v, w Uint128
	x := seed.Lower64()
	y := seed.Higher64()
	z := uint64(length) * k1

	v.setLower64(rotate64(y^k1, 49)*k1 + fetch64(s))
	v.setHigher64(rotate64(v.Lower64(), 42)*k1 + fetch64(s[8:]))
	w.setLower64(rotate64(y+z, 35)*k1 + x)
	w.setHigher64(rotate64(x+fetch64(s[88:]), 53) * k1)

	for {
		x = rotate64(x+y+v.Lower64()+fetch64(s[8:]), 37) * k1
		y = rotate64(y+v.Higher64()+fetch64(s[48:]), 42) * k1
		x ^= w.Higher64()
		y += v.Lower64() + fetch64(s[40:])
		z = rotate64(z+w.Lower64(), 33) * k1
		v = weakHashLen32WithSeeds3(s, v.Higher64()*k1, x+w.Lower64())
		w = weakHashLen32WithSeeds3(s[32:], z+w.Higher64(), y+fetch64(s[16:]))
		z, x = x, z
		s = s[64:]
		x = rotate64(x+y+v.Lower64()+fetch64(s[8:]), 37) * k1
		y = rotate64(y+v.Higher64()+fetch64(s[48:]), 42) * k1
		x ^= w.Higher64()
		y += v.Lower64() + fetch64(s[40:])
		z = rotate64(z+w.Lower64(), 33) * k1
		v = weakHashLen32WithSeeds3(s, v.Higher64()*k1, x+w.Lower64())
		w = weakHashLen32WithSeeds3(s[32:], z+w.Higher64(), y+fetch64(s[16:]))
		z, x = x, z
		s = s[64:]
		length -= 128

		if length < 128 {
			break
		}
	}

	x += rotate64(v.Lower64()+z, 49) * k0
	y = y*k0 + rotate64(w.Higher64(), 37)
	z = z*k0 + rotate64(w.Lower64(), 27)
	w.setLower64(w.Lower64() * 9)
	v.setLower64(v.Lower64() * k0)

	// If 0 < length < 128, hash up to 4 chunks of 32 bytes each from the end of s.
	var tail_done uint32
	for tail_done = 0; tail_done < length; {
		tail_done += 32
		y = rotate64(x+y, 42)*k0 + v.Higher64()
		w.setLower64(w.Lower64() + fetch64(t[origLength-tail_done+16:]))
		x = x*k0 + w.Lower64()
		z += w.Higher64() + fetch64(t[origLength-tail_done:])
		w.setHigher64(w.Higher64() + v.Lower64())
		v = weakHashLen32WithSeeds3(t[origLength-tail_done:], v.Lower64()+z, v.Higher64())
		v.setLower64(v.Lower64() * k0)
	}

	// At this point our 56 bytes of state should contain more than
	// enough information for a strong 128-bit hash.  We use two
	// different 56-byte-to-8-byte hashes to get a 16-byte final result.
	x = hashLen16(x, v.Lower64())
	y = hashLen16(y+z, w.Lower64())

	return Uint128{hashLen16(x+v.Higher64(), w.Higher64()) + y, hashLen16(x+w.Higher64(), y+v.Higher64())}
}
