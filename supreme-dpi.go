package main

//fatal error: pcap.h: No such file or directory compilation terminated.
//requires sudo apt-get install libpcap0.8-dev

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile string = "/home/vincent/go/src/github.com/VincentRenotte/supreme-dpi/files/s7comm_varservice_libnodavedemo.pcap"
)

func main() {

	//To remove
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(dir)

	//from https://godoc.org/github.com/google/gopacket/pcap
	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		i := 1
		for packet := range packetSource.Packets() {
			fmt.Println(i)
			//fmt.Println(packet)
			i += 1
			handlePacket(packet) // Do something with a packet here.
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	// MAC Layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
	}

	// IP Layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
	}
	// if packet.Layer(layers.LayerTypeTCP) != nil {
	// 	fmt.Println("TCP layer")

	// S7 Communication
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		//fmt.Printf("%x\n", payload)

		protocolId := payload[7]
		fmt.Printf("Protocol Id is %d\n", protocolId)
		//Analyze packet only if s7comm
		if protocolId == 50 {
			// COTP
			// TPKTVersion := payload[0]
			// fmt.Printf("TPKT Version = %x\n", TPKTVersion)
			// TPKTReserved := payload[1]
			// fmt.Printf("TPKT Reserved = %x\n", TPKTReserved)
			// TPKTLength := int(payload[3])
			// fmt.Printf("TPKT Length = %d\n", TPKTLength)

			// HEADER
			ROSCTR := payload[8]
			fmt.Printf("ROSCTR is %d -> ", ROSCTR)

			offset := 0
			if ROSCTR == 1 {
				fmt.Println("Job")
			} else if ROSCTR == 3 {
				fmt.Println("Ack Data")
				offset = 2
				//If packet is ack data, we have Error Class and Error Code field
			}

			protocolDataUnitRef := payload[12+offset]
			fmt.Printf("ProtocolDataUnitRef is %d\n", protocolDataUnitRef)

			s7ParamLen := int(payload[14+offset])
			fmt.Printf("Parameter length is %d\n", s7ParamLen)

			s7DataLen := int(payload[16+offset])
			fmt.Printf("Data length is %d\n", s7DataLen)

			// PARAMETER
			s7Function := int(payload[17+offset])
			fmt.Printf("Function ID is %d -> Function is ", s7Function)
			if s7Function == 5 {
				fmt.Println("Write Var")
			} else if s7Function == 4 {
				fmt.Println("Read Var")
			} else if s7Function == 0 {
				fmt.Println("Setup communication")
			}

			//s7ItemCount := int(payload[18+offset])
			//fmt.Printf("There are %d item(s)\n", s7ItemCount)

			// ITEM

			// Search for a string inside the payload
			if strings.Contains(string(payload), "HTTP") {
				fmt.Println("HTTP found!")
			}
		}

		// Iterate over all layers, printing out each layer type
		// fmt.Println("All packet layers:")
		// for _, layer := range packet.Layers() {
		// 	fmt.Println("- ", layer.LayerType())
		// }

	}
}
