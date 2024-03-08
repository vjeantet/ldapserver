package ldapserver

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"testing"
)

func TestReadFailTagAndLength(t *testing.T) {

	var (
		in   = bufio.NewReader(bytes.NewReader([]byte{0x31}))
		data = make([]byte, 0)
	)
	ret, err := readTagAndLength(in, &data)

	if !errors.Is(err, errIsNotPack0x30) {
		t.Error("is not ldap fail")
	}

	log.Printf("%+v", ret)
}
