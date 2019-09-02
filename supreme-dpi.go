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
			fmt.Println(packet)
			i += 1
			handlePacket(packet) // Do something with a packet here.
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	//Check if the packet is llayer ethernet
	if packet.Layer(layers.LayerTypeEthernet) != nil {
		fmt.Println("Ethernet layer")
	}
	if packet.Layer(layers.LayerTypeIPv4) != nil {
		fmt.Println("IPv4 layer")
	}
	if packet.Layer(layers.LayerTypeTCP) != nil {
		fmt.Println("TCP layer")
	}
	if packet.ApplicationLayer() != nil {
		fmt.Println("Application layer Payload found.")
		payload := packet.ApplicationLayer().Payload()
		fmt.Printf("%x\n", payload)
		fmt.Printf("%#x\n", payload)
		fmt.Printf("%o\n", payload)

		// Search for a string inside the payload
		if strings.Contains(string(payload), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}
}
