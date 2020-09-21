// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

package dhcpd

import (
	"bytes"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
)

func notify6(flags uint32) {
}

func TestV6StaticLeaseAddRemove(t *testing.T) {
	conf := V6ServerConf{
		Enabled:    true,
		RangeStart: "2001::1",
		notify:     notify6,
	}
	s, err := v6Create(conf)
	assert.True(t, err == nil)

	ls := s.GetLeases(LeasesStatic)
	assert.Equal(t, 0, len(ls))

	// add static lease
	l := Lease{}
	l.IP = net.ParseIP("2001::1")
	l.HWAddr, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")
	assert.True(t, s.AddStaticLease(l) == nil)

	// try to add static lease - fail
	assert.True(t, s.AddStaticLease(l) != nil)

	// check
	ls = s.GetLeases(LeasesStatic)
	assert.Equal(t, 1, len(ls))
	assert.Equal(t, "2001::1", ls[0].IP.String())
	assert.Equal(t, "aa:aa:aa:aa:aa:aa", ls[0].HWAddr.String())
	assert.True(t, ls[0].Expiry.Unix() == leaseExpireStatic)

	// try to remove static lease - fail
	l.IP = net.ParseIP("2001::2")
	l.HWAddr, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")
	assert.True(t, s.RemoveStaticLease(l) != nil)

	// remove static lease
	l.IP = net.ParseIP("2001::1")
	l.HWAddr, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")
	assert.True(t, s.RemoveStaticLease(l) == nil)

	// check
	ls = s.GetLeases(LeasesStatic)
	assert.Equal(t, 0, len(ls))
}

func TestV6StaticLeaseAddReplaceDynamic(t *testing.T) {
	conf := V6ServerConf{
		Enabled:    true,
		RangeStart: "2001::1",
		notify:     notify6,
	}
	sIface, err := v6Create(conf)
	s := sIface.(*v6Server)
	assert.True(t, err == nil)

	// add dynamic lease
	ld := Lease{}
	ld.IP = net.ParseIP("2001::1")
	ld.HWAddr, _ = net.ParseMAC("11:aa:aa:aa:aa:aa")
	s.addLease(&ld)

	// add dynamic lease
	{
		ld := Lease{}
		ld.IP = net.ParseIP("2001::2")
		ld.HWAddr, _ = net.ParseMAC("22:aa:aa:aa:aa:aa")
		s.addLease(&ld)
	}

	// add static lease with the same IP
	l := Lease{}
	l.IP = net.ParseIP("2001::1")
	l.HWAddr, _ = net.ParseMAC("33:aa:aa:aa:aa:aa")
	assert.True(t, s.AddStaticLease(l) == nil)

	// add static lease with the same MAC
	l = Lease{}
	l.IP = net.ParseIP("2001::3")
	l.HWAddr, _ = net.ParseMAC("22:aa:aa:aa:aa:aa")
	assert.True(t, s.AddStaticLease(l) == nil)

	// check
	ls := s.GetLeases(LeasesStatic)
	assert.Equal(t, 2, len(ls))

	assert.Equal(t, "2001::1", ls[0].IP.String())
	assert.Equal(t, "33:aa:aa:aa:aa:aa", ls[0].HWAddr.String())
	assert.True(t, ls[0].Expiry.Unix() == leaseExpireStatic)

	assert.Equal(t, "2001::3", ls[1].IP.String())
	assert.Equal(t, "22:aa:aa:aa:aa:aa", ls[1].HWAddr.String())
	assert.True(t, ls[1].Expiry.Unix() == leaseExpireStatic)
}

func TestV6GetLease(t *testing.T) {
	conf := V6ServerConf{
		Enabled:    true,
		RangeStart: "2001::1",
		notify:     notify6,
	}
	sIface, err := v6Create(conf)
	s := sIface.(*v6Server)
	assert.True(t, err == nil)
	s.conf.dnsIPAddrs = []net.IP{net.ParseIP("2000::1")}
	s.sid = dhcpv6.Duid{
		Type:   dhcpv6.DUID_LLT,
		HwType: iana.HWTypeEthernet,
	}
	s.sid.LinkLayerAddr, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")

	l := Lease{}
	l.IP = net.ParseIP("2001::1")
	l.HWAddr, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")
	assert.True(t, s.AddStaticLease(l) == nil)

	// "Solicit"
	mac, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	req, _ := dhcpv6.NewSolicit(mac)
	msg, _ := req.GetInnerMessage()
	resp, _ := dhcpv6.NewAdvertiseFromSolicit(msg)
	assert.True(t, s.process(msg, req, resp))
	resp.AddOption(dhcpv6.OptServerID(s.sid))

	// check "Advertise"
	assert.Equal(t, dhcpv6.MessageTypeAdvertise, resp.Type())
	oia := resp.Options.OneIANA()
	oiaAddr := oia.Options.OneAddress()
	assert.Equal(t, "2001::1", oiaAddr.IPv6Addr.String())
	assert.Equal(t, s.conf.leaseTime.Seconds(), oiaAddr.ValidLifetime.Seconds())

	// "Request"
	req, _ = dhcpv6.NewRequestFromAdvertise(resp)
	msg, _ = req.GetInnerMessage()
	resp, _ = dhcpv6.NewReplyFromMessage(msg)
	assert.True(t, s.process(msg, req, resp))

	// check "Reply"
	assert.Equal(t, dhcpv6.MessageTypeReply, resp.Type())
	oia = resp.Options.OneIANA()
	oiaAddr = oia.Options.OneAddress()
	assert.Equal(t, "2001::1", oiaAddr.IPv6Addr.String())
	assert.Equal(t, s.conf.leaseTime.Seconds(), oiaAddr.ValidLifetime.Seconds())

	dnsAddrs := resp.Options.DNS()
	assert.Equal(t, 1, len(dnsAddrs))
	assert.Equal(t, "2000::1", dnsAddrs[0].String())

	// check lease
	ls := s.GetLeases(LeasesStatic)
	assert.Equal(t, 1, len(ls))
	assert.Equal(t, "2001::1", ls[0].IP.String())
	assert.Equal(t, "aa:aa:aa:aa:aa:aa", ls[0].HWAddr.String())
}

func TestV6GetDynamicLease(t *testing.T) {
	conf := V6ServerConf{
		Enabled:    true,
		RangeStart: "2001::2",
		notify:     notify6,
	}
	sIface, err := v6Create(conf)
	s := sIface.(*v6Server)
	assert.True(t, err == nil)
	s.conf.dnsIPAddrs = []net.IP{net.ParseIP("2000::1")}
	s.sid = dhcpv6.Duid{
		Type:   dhcpv6.DUID_LLT,
		HwType: iana.HWTypeEthernet,
	}
	s.sid.LinkLayerAddr, _ = net.ParseMAC("aa:aa:aa:aa:aa:aa")

	// "Solicit"
	mac, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	req, _ := dhcpv6.NewSolicit(mac)
	msg, _ := req.GetInnerMessage()
	resp, _ := dhcpv6.NewAdvertiseFromSolicit(msg)
	assert.True(t, s.process(msg, req, resp))
	resp.AddOption(dhcpv6.OptServerID(s.sid))

	// check "Advertise"
	assert.Equal(t, dhcpv6.MessageTypeAdvertise, resp.Type())
	oia := resp.Options.OneIANA()
	oiaAddr := oia.Options.OneAddress()
	assert.Equal(t, "2001::2", oiaAddr.IPv6Addr.String())

	// "Request"
	req, _ = dhcpv6.NewRequestFromAdvertise(resp)
	msg, _ = req.GetInnerMessage()
	resp, _ = dhcpv6.NewReplyFromMessage(msg)
	assert.True(t, s.process(msg, req, resp))

	// check "Reply"
	assert.Equal(t, dhcpv6.MessageTypeReply, resp.Type())
	oia = resp.Options.OneIANA()
	oiaAddr = oia.Options.OneAddress()
	assert.Equal(t, "2001::2", oiaAddr.IPv6Addr.String())

	dnsAddrs := resp.Options.DNS()
	assert.Equal(t, 1, len(dnsAddrs))
	assert.Equal(t, "2000::1", dnsAddrs[0].String())

	// check lease
	ls := s.GetLeases(LeasesDynamic)
	assert.Equal(t, 1, len(ls))
	assert.Equal(t, "2001::2", ls[0].IP.String())
	assert.Equal(t, "aa:aa:aa:aa:aa:aa", ls[0].HWAddr.String())

	assert.True(t, !ip6InRange(net.ParseIP("2001::2"), net.ParseIP("2001::1")))
	assert.True(t, !ip6InRange(net.ParseIP("2001::2"), net.ParseIP("2002::2")))
	assert.True(t, ip6InRange(net.ParseIP("2001::2"), net.ParseIP("2001::2")))
	assert.True(t, ip6InRange(net.ParseIP("2001::2"), net.ParseIP("2001::3")))
}

func TestRA(t *testing.T) {
	ra := icmpv6RA{
		managedAddressConfiguration: false,
		otherConfiguration:          true,
		mtu:                         1500,
		prefix:                      net.ParseIP("1234::"),
		recursiveDNSServer:          net.ParseIP("fe80::800:27ff:fe00:0"),
		sourceLinkLayerAddress:      []byte{0x0a, 0x00, 0x27, 0x00, 0x00, 0x00},
	}
	data := createICMPv6RouterAdvertisementPacket(ra)
	dataCorrect := []byte{
		0x86, 0x00, 0x04, 0x15, 0x40, 0x40, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x00, 0x00,
		0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x01, 0x01, 0x0a, 0x00, 0x27, 0x00, 0x00, 0x00,
		0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x27, 0xff, 0xfe, 0x00, 0x00, 0x00,
	}
	assert.True(t, bytes.Equal(data, dataCorrect))
}
