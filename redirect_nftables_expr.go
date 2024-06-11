//go:build linux

package tun

import (
	"net/netip"
	"unsafe"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing/common"

	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

func nftablesIfname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

func nftablesRuleHijackDNS(family nftables.TableFamily, dnsServerAddress netip.Addr) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyNFPROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{uint8(family)},
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_UDP},
		},
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        2,
			Len:           2,
		}, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(53),
		}, &expr.Immediate{
			Register: 1,
			Data:     dnsServerAddress.AsSlice(),
		}, &expr.NAT{
			Type:       expr.NATTypeDestNAT,
			Family:     uint32(family),
			RegAddrMin: 1,
		},
	}
}

func ipSetHas4(setList []*netipx.IPSet) bool {
	/*return common.Any(setList, func(it *netipx.IPSet) bool {
		mySet := (*myIPSet)(unsafe.Pointer(it))
		return common.Any(mySet.rr, func(it myIPRange) bool {
			return it.from.Is4()
		})
	})*/
	return common.Any(setList, func(it *netipx.IPSet) bool {
		mySet := (*myIPSet)(unsafe.Pointer(it))
		return mySet.rr[0].from.Is4()
	})
}

func ipSetHas6(setList []*netipx.IPSet) bool {
	/*return common.Any(setList, func(it *netipx.IPSet) bool {
		mySet := (*myIPSet)(unsafe.Pointer(it))
		return common.Any(mySet.rr, func(it myIPRange) bool {
			return it.from.Is6()
		})
	})*/
	return common.Any(setList, func(it *netipx.IPSet) bool {
		mySet := (*myIPSet)(unsafe.Pointer(it))
		return mySet.rr[len(mySet.rr)-1].from.Is6()
	})
}

func nftablesRuleDestinationIPSet(id uint32, name string, family nftables.TableFamily, invert bool, exprs []expr.Any) []expr.Any {
	var newExprs []expr.Any
	newExprs = append(newExprs,
		&expr.Meta{
			Key:      expr.MetaKeyNFPROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(family)},
		},
	)
	if family == nftables.TableFamilyIPv4 {
		newExprs = append(newExprs,
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
			},
		)
	} else {
		newExprs = append(newExprs,
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        24,
				Len:           16,
			},
		)
	}
	newExprs = append(newExprs, &expr.Lookup{
		SourceRegister: 1,
		SetID:          id,
		SetName:        name,
		Invert:         invert,
	})
	newExprs = append(newExprs, exprs...)
	return newExprs
}

func nftablesCreateIPSet(nft *nftables.Conn, table *nftables.Table, id uint32, name string, family nftables.TableFamily, setList []*netipx.IPSet, prefixList []netip.Prefix, invert bool, update bool) error {
	ipSets := make([]*myIPSet, 0, len(setList))
	var rangeLen int
	for _, set := range setList {
		mySet := (*myIPSet)(unsafe.Pointer(set))
		ipSets = append(ipSets, mySet)
		rangeLen += len(mySet.rr)
	}
	setElements := make([]nftables.SetElement, 0, len(prefixList)+rangeLen)
	for _, mySet := range ipSets {
		for _, rr := range mySet.rr {
			if (family == nftables.TableFamilyIPv4) != rr.from.Is4() {
				continue
			}

			setElements = append(setElements, nftables.SetElement{
				Key: rr.from.AsSlice(),
			})
			setElements = append(setElements, nftables.SetElement{
				Key:         rr.to.Next().AsSlice(),
				IntervalEnd: true,
			})
		}
	}
	if invert && len(setElements) == 0 && len(prefixList) == 0 {
		if family == nftables.TableFamilyIPv4 {
			prefixList = append(prefixList, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		} else {
			prefixList = append(prefixList, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
		}
	}
	for _, prefix := range prefixList {
		rangeOf := netipx.RangeOfPrefix(prefix)
		setElements = append(setElements, nftables.SetElement{
			Key: rangeOf.From().AsSlice(),
		})
		endAddr := rangeOf.To().Next()
		if !endAddr.IsValid() {
			endAddr = rangeOf.From()
		}
		setElements = append(setElements, nftables.SetElement{
			Key:         endAddr.AsSlice(),
			IntervalEnd: true,
		})
	}
	var keyType nftables.SetDatatype
	if family == nftables.TableFamilyIPv4 {
		keyType = nftables.TypeIPAddr
	} else {
		keyType = nftables.TypeIP6Addr
	}
	mySet := &nftables.Set{
		Table:    table,
		ID:       id,
		Name:     name,
		Interval: true,
		KeyType:  keyType,
	}
	if update {
		nft.FlushSet(mySet)
	} else {
		err := nft.AddSet(mySet, nil)
		if err != nil {
			return err
		}
	}
	for len(setElements) > 0 {
		toAdd := setElements
		if len(toAdd) > 1000 {
			toAdd = toAdd[:1000]
		}
		setElements = setElements[len(toAdd):]
		err := nft.SetAddElements(mySet, toAdd)
		if err != nil {
			return err
		}
		err = nft.Flush()
		if err != nil {
			return err
		}
	}
	return nil
}

type myIPSet struct {
	rr []myIPRange
}

type myIPRange struct {
	from netip.Addr
	to   netip.Addr
}
