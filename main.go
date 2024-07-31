package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/sync/errgroup"
)

func main() {
	server := flag.Bool("server", false, "Run as server")
	addr := flag.String("addr", "localhost:8080", "Address to listen on or connect to")
	duration := flag.Duration("duration", 10*time.Second, "Time to run the experiment")
	flag.Parse()

	if *server {
		if err := serve(*addr); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := connect(*addr, *duration); err != nil {
		log.Fatal(err)
	}
}

func serve(addr string) error {
	tlsConfig := generateTLSConfig()
	listener, err := quic.ListenAddr(addr, tlsConfig, generateQUICConfig())
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		log.Println("got connection")
		go func() {
			b, err := handle(conn)
			if err != nil {
				log.Printf("conn handle error: %v", err)
				conn.CloseWithError(0, "conn err")
			}
			log.Printf("received total: %v responses", len(b))
			for i, r := range b {
				log.Printf("response %v len: %v", i, len(r))
			}
		}()
	}
}

func handle(conn quic.Connection) ([][]byte, error) {
	results := [][]byte{}
	resCh := make(chan []byte)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				resCh <- nil
				return
			}
			log.Printf("got stream %v", stream.StreamID())
			res := []byte{}
			buf := make([]byte, 64_000)
			for {
				n, err := stream.Read(buf)
				res = append(res, buf[:n]...)
				if err != nil {
					log.Printf("stream read error: %v", err)
					resCh <- res
					return
				}
				log.Printf("received %v bytes on stream %v", n, stream.StreamID())
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resCh)
	}()
	for res := range resCh {
		results = append(results, res)
	}
	return results, nil
}

func connect(addr string, duration time.Duration) error {
	tlsConfig := generateTLSConfig()
	tlsConfig.InsecureSkipVerify = true
	conn, err := quic.DialAddr(context.Background(), addr, tlsConfig, generateQUICConfig())
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "bye")
	g := new(errgroup.Group)
	for i := 0; i < 2; i++ {
		g.Go(func() error {
			stream, err := conn.OpenUniStream()
			if err != nil {
				return err
			}
			stream.SetPriority(uint32(0))
			stream.SetIncremental(false)
			sum := 0
			buf := make([]byte, 100e6)
			//end := time.Now().Add(duration)
			//for time.Now().Before(end) {
			for j := 0; j < 1; j++ {
				_, err = rand.Read(buf)
				if err != nil {
					return err
				}
				n, err := stream.Write(buf)
				if err != nil {
					return err
				}
				sum += n
				log.Printf("sent %v bytes on stream %v with priority %v", n, stream.StreamID(), i)
			}
			if err := stream.Close(); err != nil {
				return err
			}
			log.Printf("sent total: %v bytes on stream %v with priority %v", sum, stream.StreamID(), i)
			return nil
		})
	}
	return g.Wait()
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		GetConfigForClient:             nil,
		Versions:                       nil,
		HandshakeIdleTimeout:           0,
		MaxIdleTimeout:                 0,
		TokenStore:                     nil,
		InitialStreamReceiveWindow:     quicvarint.Max,
		MaxStreamReceiveWindow:         quicvarint.Max,
		InitialConnectionReceiveWindow: quicvarint.Max,
		MaxConnectionReceiveWindow:     quicvarint.Max,
		AllowConnectionWindowIncrease:  nil,
		MaxIncomingStreams:             0,
		MaxIncomingUniStreams:          0,
		KeepAlivePeriod:                0,
		InitialPacketSize:              0,
		DisablePathMTUDiscovery:        false,
		Allow0RTT:                      false,
		EnableDatagrams:                true,
		Tracer:                         qlog.DefaultConnectionTracer,
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
