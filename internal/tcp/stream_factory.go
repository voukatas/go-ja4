package tcp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type StreamFactory struct{}

func (s *StreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	//fmt.Printf("New stream from %v to %v\n", net.Src(), net.Dst())
	go processStream(&r, net)
	return &r
}
