package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	//pcapFile string = os.Getenv("GOPATH") + "/src/github.com/VincentRenotte/supreme-dpi/files/s7comm_varservice_libnodavedemo_bench.pcap"
	pcapFile string = os.Getenv("GOPATH") + "/src/github.com/VincentRenotte/supreme-dpi/files/s7comm_varservice_libnodavedemo.pcap"
)

func main() {
	// Slice that we are going to fill with operations
	data := [][]string{}

	//from https://godoc.org/github.com/google/gopacket/pcap
	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			operation := handlePacket(packet)
			if operation != nil {
				data = append(data, operation)
			}
		}
	}

	// Printing the slice in a readable way
	fmt.Println(
		"ROSCTR    |",
		"PDU Ref   |",
		"Para len  |",
		"Data len  |",
		"Function  |",
		"Var Type  |",
		"DB Number |",
		"Area      |",
		"Address   |",
		"Rtrn Code |",
		"Data      |",
	)
	for _, y := range data {
		for _, z := range y {
			fmt.Printf("%-10v| ", z)
		}
		fmt.Println("")
	}
}

//Takes a packet and returns a slice that will be added to data
func handlePacket(packet gopacket.Packet) []string {
	// ------------------------------------------- //
	// ---------------- MAC LAYER ---------------- //
	// ------------------------------------------- //
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		//ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		//fmt.Printf("src %s ----> %s\n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
	}

	// ------------------------------------------- //
	// ---------------- IPv4 LAYER --------------- //
	// ------------------------------------------- //
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//ip, _ := ipLayer.(*layers.IPv4)
		//fmt.Printf("src %s ----> %s\n", ip.SrcIP, ip.DstIP)
	}

	// ------------------------------------------- //
	// ------------ APPLICATION LAYER ------------ //
	// ------------------------------------------- //
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		protocolId := payload[7]

		//Analyze packet only if s7comm
		if protocolId == 0x32 {

			//New s7Operation
			var s7Operation []string

			// ------------ HEADER ------------ //
			//MSG Type
			ROSCTR := payload[8]
			offset := 0
			if ROSCTR == 0x01 {
				s7Operation = append(s7Operation, "Job Rqst")
			} else if ROSCTR == 0x03 {
				s7Operation = append(s7Operation, "Ack-Data")
				//errorClass := payload[17]
				//errorCode := payload[18]
				offset = 2
				//If packet is ack data, we have Error Class and Error Code field
			} else if ROSCTR == 0x02 {
				s7Operation = append(s7Operation, "Ack")
			} else if ROSCTR == 0x07 {
				s7Operation = append(s7Operation, "Userdata")
			}

			//PDU Ref
			protocolDataUnitRef := getInt(payload[11:13])
			s7Operation = append(s7Operation, strconv.Itoa(protocolDataUnitRef))

			//Param Length
			s7ParamLen := getInt(payload[13:15])
			s7Operation = append(s7Operation, strconv.Itoa(s7ParamLen))

			//Data Length
			s7DataLen := getInt(payload[15:17])
			s7Operation = append(s7Operation, strconv.Itoa(s7DataLen))

			// ------------ PARAMETER ----------- //
			s7Operation = handleParam(payload, offset, s7Operation)

			// -------------- DATA -------------- //
			s7Operation = handleData(payload, offset, s7Operation)
			return s7Operation

		}
	}
	return nil
}

// Handles the "Parameters" part of the S7 layer
func handleParam(payload []byte, offset int, s7Operation []string) []string {
	s7Function := payload[17+offset]
	//fmt.Printf("Function ID is %x -> Function is ", s7Function)

	//Function is Setup communication
	if s7Function == 0xf0 {
		s7Operation = append(s7Operation, "Setup com.")
		//PDULength := getInt(payload[23+offset : 25+offset])

		//no variableType, DBNumber, area and address
		s7Operation = append(s7Operation, "N/A", "N/A", "N/A", "N/A")

		//Function is Write or Read Variable
	} else {
		if s7Function == 0x05 {
			//fmt.Println("Write Var")
			s7Operation = append(s7Operation, "Write Var")
		} else if s7Function == 0x04 {
			s7Operation = append(s7Operation, "Read Var")
		}
		//s7ItemCount := int(payload[18+offset])

		// If job, we have additionnal fields
		if offset != 2 {
			// variableSpecification := payload[19+offset]
			// addressSpecificationLen := payload[20+offset]
			// syntaxId := payload[21+offset]

			// Type of the variable
			transportSize := payload[22+offset]
			variableType := ""
			if transportSize == 2 {
				variableType = "BYTE"
			}
			// the length of the rest of this item.
			//itemLen := getInt(payload[23+offset : 25+offset])

			// the address of the database,
			DBnumber := getInt(payload[25+offset : 27+offset])
			// memory area of the addressed variable
			area := payload[27+offset]
			// offset of the addressed variable in the selected memory area
			address := payload[28+offset : 30+offset]

			s7Operation = append(s7Operation, variableType)
			s7Operation = append(s7Operation, strconv.Itoa(DBnumber))
			s7Operation = append(s7Operation, fmt.Sprintf("%#x", area))
			s7Operation = append(s7Operation, fmt.Sprintf("%#x", address))
		} else {
			//no variableType, DBNumber, area and address
			s7Operation = append(s7Operation, "N/A", "N/A", "N/A", "N/A")
		}
	}

	return s7Operation
}

// Handle the "Data" part of the S7 layer
func handleData(payload []byte, offset int, s7Operation []string) []string {
	s7DataLen := int(payload[16])
	s7ParamLen := int(payload[14])

	if s7DataLen == 0 {
		//fmt.Println("No data")
		s7Operation = append(s7Operation, "N/A", "N/A")

	} else if s7DataLen == 1 {
		returnCode := payload[17+offset+s7ParamLen]
		//Convert hex to string and add it
		s7Operation = append(s7Operation, itemResponse(returnCode))
		s7Operation = append(s7Operation, "N/A")
	} else {
		returnCode := payload[17+offset+s7ParamLen]
		s7Operation = append(s7Operation, itemResponse(returnCode))
		data := payload[offset+s7ParamLen+21:]
		s7Operation = append(s7Operation, fmt.Sprintf("%x", data))
	}
	return s7Operation
}

func getInt(s []byte) int {
	var b [8]byte
	copy(b[8-len(s):], s)
	return int(binary.BigEndian.Uint64(b[:]))
}

func itemResponse(b byte) string {
	status := ""
	switch b {
	case 0x00:
		status = "Reserved"
	case 0x01:
		status = "Hardware fault"
	case 0x03:
		status = "Accessing the object not allowed"
	case 0x05:
		status = "Address out of range"
	case 0x06:
		status = "Data type not supported"
	case 0x07:
		status = "Data type inconsistent"
	case 0x0a:
		status = "Object does not exist"
	default:
		status = "unknown"
	}
	return status
}
