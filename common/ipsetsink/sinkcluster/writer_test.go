package sinkcluster

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

type writerStub struct {
	io.Writer
}

func (w writerStub) Sync() error {
	return nil
}

func TestSinkWriter(t *testing.T) {
	t.Parallel()

	buffer := bytes.NewBuffer(nil)
	writerStubInst := &writerStub{buffer}
	var key [32]byte
	if n, err := rand.Read(key[:]); (n < 32) || (err != nil) {
		t.Fatalf("rand.Read: read %d bytes: %v", n, err)
	}
	clusterWriter := NewClusterWriter(map[string]WriteSyncer{
		"demo": writerStubInst,
	}, key, time.Minute)
	clusterWriter.AddIPToSet("demo", "1")
	clusterWriter.WriteIPSetToDisk()
	if buffer.Len() == 0 {
		t.Error("WriteIPSetToDisk wrote nothing")
	}
}
