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
			fmt.Println("Packet #", i)
			//fmt.Println(packet)
			i += 1
			handlePacket(packet)
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	// ------------------------------------------- //
	// ---------------- MAC LAYER ---------------- //
	// ------------------------------------------- //
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("\nETHERNET LAYER")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("src %s ----> %s\n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
	}

	// ------------------------------------------- //
	// ---------------- IPv4 LAYER --------------- //
	// ------------------------------------------- //
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("\nIPv4 LAYER")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("src %s ----> %s\n", ip.SrcIP, ip.DstIP)
	}

	// ------------------------------------------- //
	// ------------ APPLICATION LAYER ------------ //
	// ------------------------------------------- //
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		//fmt.Printf("%x\n", payload)
		fmt.Println("\nAPPLICATION LAYER")
		protocolId := payload[7]
		fmt.Printf("Protocol Id is %#x\n", protocolId)
		//Analyze packet only if s7comm
		if protocolId == 0x32 {
			// ------------ HEADER ------------ //
			//MSG Type
			ROSCTR := payload[8]
			fmt.Printf("Message Type is %d -> ", ROSCTR)

			offset := 0
			if ROSCTR == 1 {
				fmt.Println("Job")
				// -> data
			} else if ROSCTR == 3 {
				fmt.Println("Ack Data")
				errorClass := payload[17]
				errorCode := payload[18]
				fmt.Printf("errorClass is %d\n", errorClass)
				fmt.Printf("errorCode is %d\n", errorCode)
				offset = 2
				// -> no data
				//If packet is ack data, we have Error Class and Error Code field
			}

			//PDU Ref
			protocolDataUnitRef := getInt(payload[11:13])
			fmt.Printf("ProtocolDataUnitRef is %d\n", protocolDataUnitRef)

			//Param Length
			s7ParamLen := getInt(payload[13:15])
			fmt.Printf("Parameter length is %d\n", s7ParamLen)

			//Data Length
			s7DataLen := getInt(payload[15:17])
			fmt.Printf("Data length is %d\n", s7DataLen)

			// ------------ PARAMETER ----------- //
			handleParam(payload, offset)

			// -------------- DATA -------------- //
			handleData(payload, offset)
		}
	}
	fmt.Print("\n----------------------\n\n")
}

func handleParam(payload []byte, offset int) {
	s7Function := payload[17+offset]
	fmt.Printf("Function ID is %x -> Function is ", s7Function)

	if s7Function == 0x05 {
		fmt.Println("Write Var")
		s7ItemCount := int(payload[18+offset])
		fmt.Printf("There are %d item(s)\n", s7ItemCount)
		//if job
		if offset != 2 {
			variableSpecification := payload[19+offset]
			addressSpecificationLen := payload[20+offset]
			syntaxId := payload[21+offset]
			transportSize := payload[22+offset]
			itemLen := getInt(payload[23+offset : 25+offset])
			DBnumber := getInt(payload[25+offset : 27+offset])
			area := payload[27+offset]
			address := payload[28+offset : 30+offset]
			fmt.Printf("variableSpecification is %#x\n", variableSpecification)
			fmt.Printf("addressSpecificationLen is %d\n", addressSpecificationLen)
			fmt.Printf("syntaxId is %#x\n", syntaxId)
			fmt.Printf("transportSize is %d\n", transportSize)
			fmt.Printf("itemLen is %d\n", itemLen)
			fmt.Printf("DBnumber is %d\n", DBnumber)
			fmt.Printf("area is %#x\n", area)
			fmt.Printf("address is %#x\n", address)
		}

	} else if s7Function == 0x04 {
		fmt.Println("Read Var")
		s7ItemCount := int(payload[18+offset])
		fmt.Printf("There are %d item(s)\n", s7ItemCount)
		if offset != 2 {
			variableSpecification := payload[19+offset]
			addressSpecificationLen := payload[20+offset]
			syntaxId := payload[21+offset]
			transportSize := payload[22+offset]
			itemLen := getInt(payload[23+offset : 25+offset])
			DBnumber := getInt(payload[25+offset : 27+offset])
			area := payload[27+offset]
			address := payload[28+offset : 30+offset]
			fmt.Printf("variableSpecification is %#x\n", variableSpecification)
			fmt.Printf("addressSpecificationLen is %d\n", addressSpecificationLen)
			fmt.Printf("syntaxId is %#x\n", syntaxId)
			fmt.Printf("transportSize is %d\n", transportSize)
			fmt.Printf("itemLen is %d\n", itemLen)
			fmt.Printf("DBnumber is %d\n", DBnumber)
			fmt.Printf("area is %#x\n", area)
			fmt.Printf("address is %#x\n", address)
		}

	} else if s7Function == 0xf0 {
		fmt.Println("Setup communication")
		PDULength := getInt(payload[23+offset : 25+offset])
		fmt.Printf("PDU Length is %d \n", PDULength)
	}
}

func handleData(payload []byte, offset int) {
	s7DataLen := int(payload[16])
	s7ParamLen := int(payload[14])

	if s7DataLen == 0 {
		fmt.Println("No data")
	} else if s7DataLen == 1 {
		returnCode := payload[17+offset+s7ParamLen]
		fmt.Printf("Return code is %#x \n", returnCode)
	} else {
		returnCode := int(payload[17+offset+s7ParamLen])
		fmt.Printf("Return code is %d \n", returnCode)
		fmt.Printf("Data is : %#X\n", payload[offset+s7ParamLen+21:])
	}
}

func getInt(s []byte) int {
	var b [8]byte
	copy(b[8-len(s):], s)
	return int(binary.BigEndian.Uint64(b[:]))
}
