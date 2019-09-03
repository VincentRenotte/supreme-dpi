package main

//fatal error: pcap.h: No such file or directory compilation terminated.
//requires sudo apt-get install libpcap0.8-dev

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

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
		fmt.Printf("src %s ----> %s\n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
	}

	// IP Layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("src %s ----> %s\n", ip.SrcIP, ip.DstIP)
	}
	// if packet.Layer(layers.LayerTypeTCP) != nil {
	// 	fmt.Println("TCP layer")

	// S7 Communication
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		//fmt.Printf("%x\n", payload)
		fmt.Println("Application layer")
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
				// -> data
			} else if ROSCTR == 3 {
				fmt.Println("Ack Data")
				offset = 2
				// -> no data
				//If packet is ack data, we have Error Class and Error Code field
			}

			protocolDataUnitRef := payload[12]
			fmt.Printf("ProtocolDataUnitRef is %d\n", protocolDataUnitRef)

			s7ParamLen := int(payload[14])
			fmt.Printf("Parameter length is %d\n", s7ParamLen)

			s7DataLen := int(payload[16])
			fmt.Printf("Data length is %d\n", s7DataLen)

			// PARAMETER
			s7Function := payload[17+offset]
			handleParam(payload, s7Function, offset)

			// s7ItemCount := int(payload[18+offset])
			// fmt.Printf("There are %d item(s)\n", s7ItemCount)

			// // DATA
			// // ITEM

			// returnCode := int(payload[19+offset+s7ParamLen])
			// fmt.Printf("Return code is %d \n", returnCode)
			// if returnCode == 255 {
			// 	fmt.Println("Success (0xff)")
			// } else if returnCode == 18 {
			// 	fmt.Println("Reserved (0x00)")

			// 	data := payload[23+offset : 23+offset+s7DataLen]
			// 	fmt.Printf("data is %q", data)
			// }

			// // Search for a string inside the payload
			// if strings.Contains(string(payload), "HTTP") {
			// 	fmt.Println("HTTP found!")
			// }
		}

		// Iterate over all layers, printing out each layer type
		// fmt.Println("All packet layers:")
		// for _, layer := range packet.Layers() {
		// 	fmt.Println("- ", layer.LayerType())
		// }

	}
	fmt.Print("\n----------------------\n\n")
}

func handleParam(payload []byte, s7Function byte, offset int) {
	fmt.Printf("Function ID is %x -> Function is ", s7Function)
	if s7Function == 0x05 {
		fmt.Println("Write Var")

	} else if s7Function == 0x04 {
		fmt.Println("Read Var")

	} else if s7Function == 0xf0 {
		fmt.Println("Setup communication")
		PDULength := getInt(payload[23+offset : 25+offset])
		fmt.Printf("PDU Length is %d \n", PDULength)
	}
}

func getInt(s []byte) int {
	var b [8]byte
	copy(b[8-len(s):], s)
	return int(binary.BigEndian.Uint64(b[:]))
}
