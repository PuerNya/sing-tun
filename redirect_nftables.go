//go:build linux

package tun

import (
	"net/netip"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

// TODO: reimplement `strict_route` via fwmark
func (r *autoRedirect) setupNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()

	table := nft.AddTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftables.TableFamilyINet,
	})

	routeAddressSet := *r.routeAddressSet
	routeExcludeAddressSet := *r.routeExcludeAddressSet
	err = nftablesCreateIPSet(nft, table, 1, "inet4_route_address_set", nftables.TableFamilyIPv4, routeAddressSet, r.tunOptions.Inet4RouteAddress, true, false)
	if err != nil {
		return err
	}
	err = nftablesCreateIPSet(nft, table, 2, "inet6_route_address_set", nftables.TableFamilyIPv6, routeAddressSet, r.tunOptions.Inet6RouteAddress, true, false)
	if err != nil {
		return err
	}
	err = nftablesCreateIPSet(nft, table, 3, "inet4_route_exclude_address_set", nftables.TableFamilyIPv4, routeExcludeAddressSet, r.tunOptions.Inet4RouteExcludeAddress, false, false)
	if err != nil {
		return err
	}
	err = nftablesCreateIPSet(nft, table, 4, "inet6_route_exclude_address_set", nftables.TableFamilyIPv6, routeExcludeAddressSet, r.tunOptions.Inet6RouteExcludeAddress, false, false)
	if err != nil {
		return err
	}
	redirectToPorts := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(r.redirectPort()),
		}, &expr.Redir{
			RegisterProtoMin: 1,
			// NF_NAT_RANGE_PROTO_SPECIFIED
			Flags: 2,
		},
	}
	chainOutput := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeNAT,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOutput,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     nftablesIfname(r.tunOptions.Name),
			},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})
	routeReject := []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(r.tunOptions.AutoRedirectFWMark),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
		&expr.Verdict{
			Kind: expr.VerdictReturn,
		},
	}
	if r.enableIPv4 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainOutput,
			Exprs: nftablesRuleDestinationIPSet(1, "inet4_route_address_set", nftables.TableFamilyIPv4, true, routeReject),
		})
	}
	if r.enableIPv6 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainOutput,
			Exprs: nftablesRuleDestinationIPSet(2, "inet6_route_address_set", nftables.TableFamilyIPv6, true, routeReject),
		})
	}
	if r.enableIPv4 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainOutput,
			Exprs: nftablesRuleDestinationIPSet(3, "inet4_route_exclude_address_set", nftables.TableFamilyIPv4, false, routeReject),
		})
	}
	if r.enableIPv6 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainOutput,
			Exprs: nftablesRuleDestinationIPSet(4, "inet6_route_exclude_address_set", nftables.TableFamilyIPv6, false, routeReject),
		})
	}
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOutput,
		Exprs: redirectToPorts,
	})

	chainPreRouting := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeNAT,
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPreRouting,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     nftablesIfname(r.tunOptions.Name),
			},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})

	if len(r.tunOptions.IncludeInterface) > 0 {
		if len(r.tunOptions.IncludeInterface) > 1 {
			// TODO: support it by nftables set
			return E.New("`include_interface` > 1 is not supported")
		}
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.IncludeInterface[0]),
				},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		})
	}

	for _, name := range r.tunOptions.ExcludeInterface {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     nftablesIfname(name),
				},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		})
	}

	if len(r.tunOptions.IncludeUID) > 0 {
		if len(r.tunOptions.IncludeUID) > 1 {
			return E.New("`include_uid` > 1 is not supported")
		}
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
				&expr.Range{
					Op:       expr.CmpOpNeq,
					Register: 1,
					FromData: binaryutil.BigEndian.PutUint32(r.tunOptions.IncludeUID[0].Start),
					ToData:   binaryutil.BigEndian.PutUint32(r.tunOptions.IncludeUID[0].End),
				},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		})
	}

	for _, uidRange := range r.tunOptions.ExcludeUID {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
				&expr.Range{
					Op:       expr.CmpOpNeq,
					Register: 1,
					FromData: binaryutil.BigEndian.PutUint32(uidRange.Start),
					ToData:   binaryutil.BigEndian.PutUint32(uidRange.End),
				},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		})
	}

	if !r.tunOptions.EXP_DisableDNSHijack {
		dnsServer4 := common.Find(r.tunOptions.DNSServers, func(it netip.Addr) bool {
			return it.Is4()
		})
		dnsServer6 := common.Find(r.tunOptions.DNSServers, func(it netip.Addr) bool {
			return it.Is6()
		})
		if r.enableIPv4 && !dnsServer4.IsValid() {
			dnsServer4 = r.tunOptions.Inet4Address[0].Addr().Next()
		}
		if r.enableIPv6 && !dnsServer6.IsValid() {
			dnsServer6 = r.tunOptions.Inet6Address[0].Addr().Next()
			if r.enableIPv4 {
				nft.AddRule(&nftables.Rule{
					Table: table,
					Chain: chainPreRouting,
					Exprs: nftablesRuleHijackDNS(nftables.TableFamilyIPv4, dnsServer4),
				})
			}
			if r.enableIPv6 {
				nft.AddRule(&nftables.Rule{
					Table: table,
					Chain: chainPreRouting,
					Exprs: nftablesRuleHijackDNS(nftables.TableFamilyIPv6, dnsServer6),
				})
			}
		}
	}

	if r.enableIPv4 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleDestinationIPSet(1, "inet4_route_address_set", nftables.TableFamilyIPv4, true, routeReject),
		})
	}
	if r.enableIPv6 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleDestinationIPSet(2, "inet6_route_address_set", nftables.TableFamilyIPv6, true, routeReject),
		})
	}
	if r.enableIPv4 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleDestinationIPSet(3, "inet4_route_exclude_address_set", nftables.TableFamilyIPv4, false, routeReject),
		})
	}
	if r.enableIPv6 {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleDestinationIPSet(4, "inet6_route_exclude_address_set", nftables.TableFamilyIPv6, false, routeReject),
		})
	}
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPreRouting,
		Exprs: append([]expr.Any{
			&expr.Fib{
				Register:       1,
				FlagDADDR:      true,
				ResultADDRTYPE: true,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL),
			},
		}, routeReject...),
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPreRouting,
		Exprs: redirectToPorts,
	})

	err = r.configureFW4(nft, false)
	if err != nil {
		return err
	}

	return nft.Flush()
}

func (r *autoRedirect) nftablesUpdateRouteAddressSet() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	table, err := nft.ListTableOfFamily(r.tableName, nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	routeAddressSet := *r.routeAddressSet
	routeExcludeAddressSet := *r.routeExcludeAddressSet
	err = nftablesCreateIPSet(nft, table, 1, "inet4_route_address_set", nftables.TableFamilyIPv4, routeAddressSet, r.tunOptions.Inet4RouteAddress, true, true)
	if err != nil {
		return err
	}
	err = nftablesCreateIPSet(nft, table, 2, "inet6_route_address_set", nftables.TableFamilyIPv6, routeAddressSet, r.tunOptions.Inet6RouteAddress, true, true)
	if err != nil {
		return err
	}
	err = nftablesCreateIPSet(nft, table, 3, "inet4_route_exclude_address_set", nftables.TableFamilyIPv4, routeExcludeAddressSet, r.tunOptions.Inet4RouteExcludeAddress, false, true)
	if err != nil {
		return err
	}
	err = nftablesCreateIPSet(nft, table, 4, "inet6_route_exclude_address_set", nftables.TableFamilyIPv6, routeExcludeAddressSet, r.tunOptions.Inet6RouteExcludeAddress, false, true)
	if err != nil {
		return err
	}
	return nil
}

func (r *autoRedirect) cleanupNFTables() {
	nft, err := nftables.New()
	if err != nil {
		return
	}
	nft.DelTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftables.TableFamilyINet,
	})
	common.Must(r.configureFW4(nft, true))
	_ = nft.Flush()
	_ = nft.CloseLasting()
}

func (r *autoRedirect) configureFW4(nft *nftables.Conn, undo bool) error {
	tableFW4, err := nft.ListTableOfFamily("fw4", nftables.TableFamilyINet)
	if err != nil {
		return nil
	}
	if !undo {
		ruleIif := &nftables.Rule{
			Table: tableFW4,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyIIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.Name),
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}
		ruleOif := &nftables.Rule{
			Table: tableFW4,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyOIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.Name),
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}
		chainForward := &nftables.Chain{
			Name: "forward",
		}
		ruleIif.Chain = chainForward
		ruleOif.Chain = chainForward
		nft.InsertRule(ruleOif)
		nft.InsertRule(ruleIif)
		chainInput := &nftables.Chain{
			Name: "input",
		}
		ruleIif.Chain = chainInput
		ruleOif.Chain = chainInput
		nft.InsertRule(ruleOif)
		nft.InsertRule(ruleIif)
		return nil
	}
	for _, chainName := range []string{"input", "forward"} {
		var rules []*nftables.Rule
		rules, err = nft.GetRules(tableFW4, &nftables.Chain{
			Name: chainName,
		})
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if len(rule.Exprs) != 3 {
				continue
			}
			exprMeta, isMeta := rule.Exprs[0].(*expr.Meta)
			if !isMeta {
				continue
			}
			if exprMeta.Key != expr.MetaKeyIIFNAME && exprMeta.Key != expr.MetaKeyOIFNAME {
				continue
			}
			exprCmp, isCmp := rule.Exprs[1].(*expr.Cmp)
			if !isCmp {
				continue
			}
			if !slices.Equal(exprCmp.Data, nftablesIfname(r.tunOptions.Name)) {
				continue
			}
			err = nft.DelRule(rule)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
