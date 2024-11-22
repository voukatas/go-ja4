package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/voukatas/go-ja4/internal/tcp"
)

func main() {

	// If too much memory is used change to 1600
	handle, err := pcap.OpenLive("enp0s3", 65535, true, pcap.BlockForever)
	//handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//err = handle.SetBPFFilter("tcp port 443")
	err = handle.SetBPFFilter("tcp")
	if err != nil {
		log.Fatal(err)
	}

	// Till here is normal flow
	streamFactory := &tcp.StreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	// Open pcap files
	//handle, err := pcap.OpenOffline("pcap/badcurveball.pcap")
	//handle, err := pcap.OpenOffline("pcap/ipv6.pcapng")
	//handle, err := pcap.OpenOffline("pcap/tls-handshake.pcapng")
	//handle, err := pcap.OpenOffline("pcap/tls12.pcap") // SYN packet is missing, gopacket requires the syn packet for the frame reassembly
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer handle.Close()
	// End of pcap files

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("DLT: ", handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			//fmt.Println("Received a Packet")

			if packet == nil {
				return
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				//fmt.Println("Processing a TCP packet")
				tcp := tcpLayer.(*layers.TCP)
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				// Process UDP packet for QUIC/UDP
			}
		case <-ticker.C:
			// Avoid resource leak by cleaning up
			cutoff := time.Now().Add(-2 * time.Minute)
			flushedConn, closedConn := assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: false, T: cutoff})
			fmt.Printf("FlushWithOptions - flushedConn: %v closedConn: %v\n", flushedConn, closedConn)
		}
	}
}
