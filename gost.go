/*
	gost.go:  GOST algorithm implementation in Go.

	Copyright (C) 2018 by Piotr Pszczółkowski (piotr@beesoft.pl)
	
	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
	If you require this code under a license other than LGPL, please ask.
*/

package gost

import (
	"log"
)

type Gost struct {
	k   [8]uint32 // key - 256 bit
	k87 [256]byte
	k65 [256]byte
	k43 [256]byte
	k21 [256]byte
}

func New(key []byte) *Gost {
	if (8 * len(key)) != 256 {
		log.Printf("Gost error. Invalid key length. Is %d bit, should be 256 bit.\n", 8*len(key))
		return nil
	}

	k8 := [16]byte{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}
	k7 := [16]byte{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}
	k6 := [16]byte{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}
	k5 := [16]byte{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}
	k4 := [16]byte{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}
	k3 := [16]byte{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}
	k2 := [16]byte{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}
	k1 := [16]byte{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}

	gost := new(Gost)

	for i := 0; i < 256; i++ {
		p1 := i >> 4
		p2 := i & 15
		gost.k87[i] = (k8[p1] << 4) | k7[p2]
		gost.k65[i] = (k6[p1] << 4) | k5[p2]
		gost.k43[i] = (k4[p1] << 4) | k3[p2]
		gost.k21[i] = (k2[p1] << 4) | k1[p2]
	}
	for i := 0; i < 8; i++ {
		idx := i * 4
		gost.k[i] = bytes2word(key[idx:(idx + 4)])
	}

	return gost
}

func (gost *Gost) f(x uint32) uint32 {
	w0 := uint32(gost.k87[(x>>24)&255]) << 24
	w1 := uint32(gost.k65[(x>>16)&255]) << 16
	w2 := uint32(gost.k43[(x>>8)&255]) << 8
	w3 := uint32(gost.k21[x&255])
	x = w0 | w1 | w2 | w3
	return (x << 11) | (x >> (32 - 11))
}

func (gost *Gost) EncryptOneBlock(d []uint32) {
	n1 := d[0]
	n2 := d[1]

	n2 ^= gost.f(n1 + gost.k[0])
	n1 ^= gost.f(n2 + gost.k[1])
	n2 ^= gost.f(n1 + gost.k[2])
	n1 ^= gost.f(n2 + gost.k[3])
	n2 ^= gost.f(n1 + gost.k[4])
	n1 ^= gost.f(n2 + gost.k[5])
	n2 ^= gost.f(n1 + gost.k[6])
	n1 ^= gost.f(n2 + gost.k[7])

	n2 ^= gost.f(n1 + gost.k[0])
	n1 ^= gost.f(n2 + gost.k[1])
	n2 ^= gost.f(n1 + gost.k[2])
	n1 ^= gost.f(n2 + gost.k[3])
	n2 ^= gost.f(n1 + gost.k[4])
	n1 ^= gost.f(n2 + gost.k[5])
	n2 ^= gost.f(n1 + gost.k[6])
	n1 ^= gost.f(n2 + gost.k[7])

	n2 ^= gost.f(n1 + gost.k[0])
	n1 ^= gost.f(n2 + gost.k[1])
	n2 ^= gost.f(n1 + gost.k[2])
	n1 ^= gost.f(n2 + gost.k[3])
	n2 ^= gost.f(n1 + gost.k[4])
	n1 ^= gost.f(n2 + gost.k[5])
	n2 ^= gost.f(n1 + gost.k[6])
	n1 ^= gost.f(n2 + gost.k[7])

	n2 ^= gost.f(n1 + gost.k[7])
	n1 ^= gost.f(n2 + gost.k[6])
	n2 ^= gost.f(n1 + gost.k[5])
	n1 ^= gost.f(n2 + gost.k[4])
	n2 ^= gost.f(n1 + gost.k[3])
	n1 ^= gost.f(n2 + gost.k[2])
	n2 ^= gost.f(n1 + gost.k[1])
	n1 ^= gost.f(n2 + gost.k[0])

	d[0] = n2
	d[1] = n1
}

func (gost *Gost) DecryptOneBlock(d []uint32) {
	n1 := d[0]
	n2 := d[1]

	n2 ^= gost.f(n1 + gost.k[0])
	n1 ^= gost.f(n2 + gost.k[1])
	n2 ^= gost.f(n1 + gost.k[2])
	n1 ^= gost.f(n2 + gost.k[3])
	n2 ^= gost.f(n1 + gost.k[4])
	n1 ^= gost.f(n2 + gost.k[5])
	n2 ^= gost.f(n1 + gost.k[6])
	n1 ^= gost.f(n2 + gost.k[7])

	n2 ^= gost.f(n1 + gost.k[7])
	n1 ^= gost.f(n2 + gost.k[6])
	n2 ^= gost.f(n1 + gost.k[5])
	n1 ^= gost.f(n2 + gost.k[4])
	n2 ^= gost.f(n1 + gost.k[3])
	n1 ^= gost.f(n2 + gost.k[2])
	n2 ^= gost.f(n1 + gost.k[1])
	n1 ^= gost.f(n2 + gost.k[0])

	n2 ^= gost.f(n1 + gost.k[7])
	n1 ^= gost.f(n2 + gost.k[6])
	n2 ^= gost.f(n1 + gost.k[5])
	n1 ^= gost.f(n2 + gost.k[4])
	n2 ^= gost.f(n1 + gost.k[3])
	n1 ^= gost.f(n2 + gost.k[2])
	n2 ^= gost.f(n1 + gost.k[1])
	n1 ^= gost.f(n2 + gost.k[0])

	n2 ^= gost.f(n1 + gost.k[7])
	n1 ^= gost.f(n2 + gost.k[6])
	n2 ^= gost.f(n1 + gost.k[5])
	n1 ^= gost.f(n2 + gost.k[4])
	n2 ^= gost.f(n1 + gost.k[3])
	n1 ^= gost.f(n2 + gost.k[2])
	n2 ^= gost.f(n1 + gost.k[1])
	n1 ^= gost.f(n2 + gost.k[0])

	d[0] = n2
	d[1] = n1
}

func bytes2word(data []byte) uint32 {
	v := uint32(0)
	v = (v << 8) + uint32(data[3])
	v = (v << 8) + uint32(data[2])
	v = (v << 8) + uint32(data[1])
	v = (v << 8) + uint32(data[0])
	return v
}
