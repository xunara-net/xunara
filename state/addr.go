package state

import (
	"encoding/binary"
	"math/big"
	"net/netip"
)

// addrAtOffset returns the address offset positions after the start of prefix.
//
// Addresses are allocated from the first host address of the range, so offset 1
// is the first usable address.
func addrAtOffset(prefix netip.Prefix, offset uint32) (netip.Addr, bool) {
	masked := prefix.Masked()
	base := masked.Addr()

	var addr netip.Addr
	if base.Is4() {
		b := base.As4()
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], binary.BigEndian.Uint32(b[:])+offset)
		addr = netip.AddrFrom4(out)
	} else {
		b := base.As16()
		v := new(big.Int).SetBytes(b[:])
		v.Add(v, new(big.Int).SetUint64(uint64(offset)))

		var out [16]byte
		v.FillBytes(out[:])
		addr = netip.AddrFrom16(out)
	}

	if !masked.Contains(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}
