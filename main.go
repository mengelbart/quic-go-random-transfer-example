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
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
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
			log.Printf("received total: %v bytes", len(b))
		}()
	}
}

func handle(conn quic.Connection) ([]byte, error) {
	res := []byte{}
	buf := make([]byte, 64_000)
	stream, err := conn.AcceptUniStream(context.Background())
	if err != nil {
		return res, err
	}
	log.Println("got stream")
	for {
		n, err := stream.Read(buf)
		res = append(res, buf[:n]...)
		if err != nil {
			log.Printf("stream read error: %v", err)
			return res, err
		}
		log.Printf("received %v bytes", n)
	}
}

func connect(addr string, duration time.Duration) error {
	tlsConfig := generateTLSConfig()
	tlsConfig.InsecureSkipVerify = true
	conn, err := quic.DialAddr(context.Background(), addr, tlsConfig, generateQUICConfig())
	if err != nil {
		return err
	}
	stream, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	sum := 0
	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		buf := make([]byte, 64_000)
		_, err = rand.Read(buf)
		if err != nil {
			return err
		}
		n, err := stream.Write(buf)
		if err != nil {
			return err
		}
		sum += n
		log.Printf("sent %v bytes", n)
	}
	if err := stream.Close(); err != nil {
		return err
	}
	log.Printf("sent total: %v bytes", sum)
	return conn.CloseWithError(0, "bye")
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		Tracer:          qlog.DefaultConnectionTracer,
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
