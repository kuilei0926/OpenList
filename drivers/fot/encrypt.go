package fot

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"time"
)

// fotFileName encodes the underlying .fot file name for a plaintext file:
// md5(original_name) + size(8-byte BE hex) + mtime(8-byte BE hex) + ".fot"
func fotFileName(name string, size int64, mtime time.Time) string {
	sum := md5.Sum([]byte(name))
	return fmt.Sprintf("%x%016x%016x.fot", sum, size, mtime.Unix())
}

// buildFOTHeader constructs the fixed 45-byte header + variable metadata for a
// plaintext file. It returns the header blob (which must be prepended to the
// encrypted body) and the body encryption key.
func buildFOTHeader(password, filename string, plainLen int64, dataIV, usabilityIV [16]byte, salt [fileSaltLen]byte) []byte {
	encryptCTR := func(key, iv, data []byte) []byte {
		block, _ := aes.NewCipher(key)
		out := make([]byte, len(data))
		cipher.NewCTR(block, iv).XORKeyStream(out, data)
		return out
	}

	// usability: IV || AES-CTR(fixed check plaintext)
	usabilityKey := deriveKey(password, salt[:], usabilityRounds)
	usabilityRaw := append(append([]byte{}, usabilityIV[:]...),
		encryptCTR(usabilityKey, usabilityIV[:], usabilityPlaintext)...)
	usabilityVal := base64.StdEncoding.EncodeToString(usabilityRaw)

	// filename: AES-CTR(name) || HMAC tag
	filenameKey := deriveKey(password, salt[:], filenameRounds)
	nameCT := encryptCTR(filenameKey, dataIV[:], []byte(filename))
	mac := hmac.New(sha256.New, filenameKey)
	mac.Write(nameCT)
	filenameRaw := append(append([]byte{}, nameCT...), mac.Sum(nil)[:tagLen]...)
	filenameVal := base64.StdEncoding.EncodeToString(filenameRaw)

	headerLen := fixedHeaderLen + 3 + len("usability") + len(usabilityVal) + 3 + len("filename") + len(filenameVal)
	blob := make([]byte, 0, headerLen+int(plainLen)+tagLen)
	blob = append(blob, []byte(fotMagic)...)
	blob = append(blob, fotVersion)
	blob = binary.BigEndian.AppendUint16(blob, uint16(headerLen))
	blob = binary.BigEndian.AppendUint64(blob, uint64(headerLen+int(plainLen)+tagLen))
	blob = append(blob, dataIV[:]...)
	blob = append(blob, salt[:]...)
	blob = append(blob, 0x00) // padding byte (unused)
	blob = append(blob, buildEntry("usability", usabilityVal)...)
	blob = append(blob, buildEntry("filename", filenameVal)...)
	return blob
}

// encryptBody writes the AES-CTR encrypted body and its HMAC tag to w, reading
// the plaintext from r. Returns the number of ciphertext bytes written.
func encryptBody(w io.Writer, r io.Reader, password string, salt [fileSaltLen]byte, dataIV [16]byte) (int64, error) {
	bodyKey := deriveKey(password, salt[:], bodyRounds)
	block, err := aes.NewCipher(bodyKey)
	if err != nil {
		return 0, err
	}
	ctr := cipher.NewCTR(block, dataIV[:])
	mac := hmac.New(sha256.New, bodyKey)

	buf := make([]byte, 64*1024)
	var written int64
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			enc := make([]byte, n)
			ctr.XORKeyStream(enc, buf[:n])
			if _, werr := w.Write(enc); werr != nil {
				return written, werr
			}
			mac.Write(enc)
			written += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return written, rerr
		}
	}
	// append the body HMAC tag
	if _, err := w.Write(mac.Sum(nil)[:tagLen]); err != nil {
		return written, err
	}
	return written, nil
}

// encryptToFOT encrypts a plaintext stream into a complete .fot blob in memory.
// Used for small files and for the unit round-trip test.
func encryptToFOT(password, filename string, plaintext []byte) ([]byte, error) {
	var salt [fileSaltLen]byte
	var dataIV, usabilityIV [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(dataIV[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(usabilityIV[:]); err != nil {
		return nil, err
	}
	header := buildFOTHeader(password, filename, int64(len(plaintext)), dataIV, usabilityIV, salt)
	var body bytes.Buffer
	if _, err := encryptBody(&body, bytes.NewReader(plaintext), password, salt, dataIV); err != nil {
		return nil, err
	}
	return append(header, body.Bytes()...), nil
}

// fotEncryptStream is an io.Reader that produces a complete .fot byte stream
// (header || AES-CTR encrypted body || HMAC tag) from a plaintext source, on the
// fly. It is used to upload a plaintext file as its encrypted .fot form.
type fotEncryptStream struct {
	header  []byte // fixed header + metadata, emitted first
	body    io.Reader
	block   cipher.Block
	ctr     cipher.Stream
	mac     hash.Hash
	buf     []byte
	enc     []byte
	state   int // 0=header, 1=body, 2=tag, 3=done
	written int64
}

// NewFOTEncryptStream builds a .fot producing stream for the given plaintext source.
func NewFOTEncryptStream(password, filename string, size int64, src io.Reader) (io.Reader, int64, error) {
	var salt [fileSaltLen]byte
	var dataIV, usabilityIV [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, 0, err
	}
	if _, err := rand.Read(dataIV[:]); err != nil {
		return nil, 0, err
	}
	if _, err := rand.Read(usabilityIV[:]); err != nil {
		return nil, 0, err
	}
	header := buildFOTHeader(password, filename, size, dataIV, usabilityIV, salt)

	bodyKey := deriveKey(password, salt[:], bodyRounds)
	block, err := aes.NewCipher(bodyKey)
	if err != nil {
		return nil, 0, err
	}
	return &fotEncryptStream{
		header: header,
		body:   src,
		block:  block,
		ctr:    cipher.NewCTR(block, dataIV[:]),
		mac:    hmac.New(sha256.New, bodyKey),
		buf:    make([]byte, 64*1024),
		enc:    make([]byte, 64*1024),
	}, int64(len(header) + int(size) + tagLen), nil
}

func (s *fotEncryptStream) Read(p []byte) (int, error) {
	switch s.state {
	case 0: // emit header
		n := copy(p, s.header)
		s.header = s.header[n:]
		if len(s.header) == 0 {
			s.state = 1
		}
		return n, nil
	case 1: // encrypt body
		rn, rerr := s.body.Read(s.buf[:min(len(p), len(s.buf))])
		if rn > 0 {
			s.ctr.XORKeyStream(s.enc[:rn], s.buf[:rn])
			s.mac.Write(s.enc[:rn])
			s.written += int64(rn)
			return copy(p, s.enc[:rn]), nil
		}
		if rerr == io.EOF {
			s.state = 2
			return s.Read(p)
		}
		return 0, rerr
	case 2: // emit tag
		tag := s.mac.Sum(nil)[:tagLen]
		n := copy(p, tag)
		if n == len(tag) {
			s.state = 3
		}
		return n, nil
	default:
		return 0, io.EOF
	}
}
