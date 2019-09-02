package main

//fatal error: pcap.h: No such file or directory compilation terminated.
//requires sudo apt-get install libpcap0.8-dev

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(dir)

	//from https://godoc.org/github.com/google/gopacket/pcap
	if handle, err := pcap.OpenOffline("/home/vincent/go/src/github.com/VincentRenotte/supreme-dpi/files/s7comm_varservice_libnodavedemo.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			print(packet)
			//handlePacket(packet) // Do something with a packet here.
		}
	}
}
