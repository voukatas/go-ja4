package tcp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/voukatas/go-ja4/internal/model"
)

type StreamFactory struct {
	JA4Map  map[string]*model.FingerprintRecord
	JA4SMap map[string]*model.FingerprintRecord
}

func (s *StreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	//fmt.Printf("New stream from %v to %v\n", net.Src(), net.Dst())
	go processStream(&r, net, s.JA4Map, s.JA4SMap)
	return &r
}
