package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type NSStruct struct {
	NS    string   `json:"ns"`
	IPv4s []string `json:"ipv4s"`
	IPv6s []string `json:"ipv6s"`
}
type ZoneNSStruct struct {
	Zone string     `json:"zone"`
	NSes []NSStruct `json:"nses"`
}

var (
	handleSendL *pcap.Handle
	errL        error
	ttlL        = 3600 * 24 * 7
	ZoneNSMapL  = make(map[string][]NSStruct)
)

func initZoneNSMap(file string) {
	srcFile, err := os.Open(file)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	reader := bufio.NewReader(srcFile)

	for {
		inReadBytes, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		inReadBytes = bytes.TrimRight(inReadBytes, "\n")

		var zoneNS ZoneNSStruct
		err = json.Unmarshal(inReadBytes, &zoneNS)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}

		ZoneNSMapL[zoneNS.Zone] = zoneNS.NSes
	}
}

func dnsResponseL(
	srcMac string, dstMac string, srcIP string, srcPort layers.UDPPort, dstIP string, dstPort layers.UDPPort,
	qname string, qtype layers.DNSType, txid uint16, ttl uint32,
) {

	fmt.Printf(
		"%s : fm %s:%d to %s:%d query %s %s\n", time.Now().Format(time.ANSIC), dstIP, dstPort, srcIP, srcPort, qname,
		qtype.String(),
	)

	srcMacB, _ := net.ParseMAC(srcMac)
	dstMacB, _ := net.ParseMAC(dstMac)
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacB,
		DstMAC:       dstMacB,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPort),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	errP := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if errP != nil {
		fmt.Println("errPor: ", errP)
		os.Exit(1)
	}

	qnameByte := []byte(qname)
	if qname == "." {
		qnameByte = []byte{}
	}
	AAFlag := false
	QDCount := 1
	ANCount := 0
	NSCount := 0
	ARCount := 0
	QDRRs := []layers.DNSQuestion{
		{
			Name:  qnameByte,
			Type:  qtype,
			Class: layers.DNSClassIN,
		},
	}
	ANRRs := make([]layers.DNSResourceRecord, 0)
	NSRRs := make([]layers.DNSResourceRecord, 0)
	ARRRs := make([]layers.DNSResourceRecord, 0)

	zone := strings.ToLower(qname)

	if qtype == layers.DNSTypeNS {
		AAFlag = true

		for _, ns := range ZoneNSMapL[zone] {
			rr := layers.DNSResourceRecord{
				Name:  qnameByte,
				Type:  layers.DNSTypeNS,
				Class: layers.DNSClassIN,
				TTL:   ttl,
				NS:    []byte(ns.NS),
			}
			ANRRs = append(ANRRs, rr)
			ANCount += 1

			for _, ipv4 := range ns.IPv4s {
				rr := layers.DNSResourceRecord{
					Name:  []byte(ns.NS),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipv4),
				}
				ARRRs = append(ARRRs, rr)
				ARCount += 1
			}

			for _, ipv6 := range ns.IPv6s {
				rr := layers.DNSResourceRecord{
					Name:  []byte(ns.NS),
					Type:  layers.DNSTypeAAAA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipv6),
				}
				ARRRs = append(ARRRs, rr)
				ARCount += 1
			}
		}
	} else {
		for _, ns := range ZoneNSMapL[zone] {
			rr := layers.DNSResourceRecord{
				Name:  qnameByte,
				Type:  layers.DNSTypeNS,
				Class: layers.DNSClassIN,
				TTL:   ttl,
				NS:    []byte(ns.NS),
			}
			NSRRs = append(NSRRs, rr)
			NSCount += 1

			for _, ipv4 := range ns.IPv4s {
				rr := layers.DNSResourceRecord{
					Name:  []byte(ns.NS),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipv4),
				}
				ARRRs = append(ARRRs, rr)
				ARCount += 1
			}

			for _, ipv6 := range ns.IPv6s {
				rr := layers.DNSResourceRecord{
					Name:  []byte(ns.NS),
					Type:  layers.DNSTypeAAAA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipv6),
				}
				ARRRs = append(ARRRs, rr)
				ARCount += 1
			}
		}
	}

	dnsLayer := &layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           txid,
		QR:           true,
		OpCode:       0,
		AA:           AAFlag,
		TC:           false,
		RD:           false,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      uint16(QDCount),
		ANCount:      uint16(ANCount),
		NSCount:      uint16(NSCount),
		ARCount:      uint16(ARCount),
		Questions:    QDRRs,
		Answers:      ANRRs,
		Authorities:  NSRRs,
		Additionals:  ARRRs,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	errP = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if errP != nil {
		fmt.Println("errPor: ", errP)
		os.Exit(1)
	}

	outgoingPacket := buffer.Bytes()

	errP = handleSendL.WritePacketData(outgoingPacket)
	if errP != nil {
		fmt.Println("errPor: ", errP)
		os.Exit(1)
	}

	fmt.Printf(
		"%s : from %s:%d to %s:%d with %s %s %d\n", time.Now().Format(time.ANSIC), srcIP, srcPort, dstIP, dstPort,
		qname, qtype.String(), ttl,
	)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: ./local_authority_server <network-interface> <zone-file>")
		os.Exit(1)
	}

	fmt.Printf("%s : %s\n", time.Now().Format(time.ANSIC), "Local authority DNS server starts")

	deviceL := os.Args[1]
	file := os.Args[2]

	initZoneNSMap(file)

	handleSendL, errL = pcap.OpenLive(deviceL, 1024, false, 0*time.Second)
	if errL != nil {
		fmt.Println("Error: ", errL)
		os.Exit(1)
	}
	defer handleSendL.Close()

	handleRecv, errP := pcap.OpenLive(deviceL, 1024, false, time.Nanosecond)
	if errP != nil {
		fmt.Println("Error: ", errP)
		os.Exit(1)
	}
	defer handleRecv.Close()

	var filter = fmt.Sprintf("udp dst port 53")
	errP = handleRecv.SetBPFFilter(filter)
	if errP != nil {
		fmt.Println("Error: ", errP)
		os.Exit(1)
	}

	errP = handleRecv.SetDirection(pcap.DirectionIn)
	if errP != nil {
		fmt.Println("Error: ", errP)
		os.Exit(1)
	}

	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)

	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())
	packetChan := packetSource.Packets()

	for packet := range packetChan {
		if errP := parser.DecodeLayers(packet.Data(), &decoded); errP != nil {
			continue
		}

		if len(dns_.Questions) <= 0 {
			continue
		}

		qname := string(dns_.Questions[0].Name)
		if strings.HasPrefix(qname, "_.") {
			qname = qname[2:]
		}
		if qname == "" {
			qname = "."
		}
		zone := strings.ToLower(qname)
		if _, ok := ZoneNSMapL[zone]; !ok {
			continue
		}

		srcMac := eth.DstMAC.String()
		dstMac := eth.SrcMAC.String()
		srcIP := ipv4.DstIP.String()
		srcPort := udp.DstPort
		dstIP := ipv4.SrcIP.String()
		dstPort := udp.SrcPort

		qtype := dns_.Questions[0].Type
		txid := dns_.ID
		ttl := ttlL

		go dnsResponseL(srcMac, dstMac, srcIP, srcPort, dstIP, dstPort, qname, qtype, txid, uint32(ttl))
	}
}
