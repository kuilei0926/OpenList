package fot

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"golang.org/x/crypto/pbkdf2"
)

// FOT format constants, reverse-engineered from the fnOS backup-cloud binary
// (see the offline-decryption writeup used as reference).
const (
	fotMagic              = "\x46\x4f\x54\xa3\x1c\x77\x00\x5e"
	fotVersion            = 1
	fixedHeaderLen        = 45
	ivLen                 = 16
	fileSaltLen           = 9
	tagLen                = 16
	kdfPrefix             = "\x3c\xa1\x5e\xf9\xd2\x07\x6b"
	usabilityRounds       = 100
	filenameRounds        = 1000
	bodyRounds            = 10000
	keyLen                = 32
	usabilityPlaintextLen = 38
)

// fixed check plaintext the usability metadata decrypts to, used to validate the password
var usabilityPlaintext = []byte("teirenfeiniuyunpanbeifencryptoencrypto")

var (
	errMagic       = errors.New("FOT magic mismatch")
	errVersion     = errors.New("unsupported FOT version")
	errHeader      = errors.New("invalid FOT header")
	errMeta        = errors.New("invalid FOT metadata")
	errPassword    = errors.New("wrong password or corrupted usability metadata")
	errFilename    = errors.New("filename HMAC mismatch: wrong password or corrupted metadata")
	errBodyTag     = errors.New("body HMAC mismatch: wrong password or corrupted/truncated file")
	errBadBase64   = errors.New("invalid base64 metadata")
	errBadFilename = errors.New("invalid filename")
)

// fotHeader is the parsed result of a FOT file header.
type fotHeader struct {
	headerLen   int
	totalLen    int64
	dataIV      [ivLen]byte
	salt        [fileSaltLen]byte
	usabilityIV [ivLen]byte
	// usability ciphertext is the encrypted fixed check value (usabilityPlaintextLen bytes)
	usabilityCT []byte
	// encrypted filename bytes
	fileNameCT []byte
	// 16-byte truncated HMAC tag authenticating fileNameCT
	fileNameTag [tagLen]byte
	// trailing 16-byte HMAC tag authenticating the whole body ciphertext
	bodyTag [tagLen]byte
}

// parseFOTHeader parses the fixed header and the variable-length metadata of a FOT
// blob. When headOnly is true (reading a head fragment of an arbitrarily large file),
// the total_len == len(blob) check is skipped because the head may be shorter than
// the whole file; the caller already knows the real size.
func parseFOTHeader(blob []byte, headOnly ...bool) (*fotHeader, error) {
	if len(blob) < fixedHeaderLen+tagLen {
		return nil, errHeader
	}
	if !bytes.Equal(blob[:8], []byte(fotMagic)) {
		return nil, errMagic
	}
	if blob[8] != fotVersion {
		return nil, fmt.Errorf("%w: %d", errVersion, blob[8])
	}
	headerLen := int(binary.BigEndian.Uint16(blob[9:11]))
	totalLen := int64(binary.BigEndian.Uint64(blob[11:19]))
	if headerLen < fixedHeaderLen || headerLen > len(blob)-tagLen {
		return nil, errHeader
	}
	if !utils.IsBool(headOnly...) && totalLen != int64(len(blob)) {
		return nil, fmt.Errorf("%w: header total_len=%d, actual=%d", errHeader, totalLen, len(blob))
	}
	if !utils.IsBool(headOnly...) && totalLen < int64(headerLen)+tagLen {
		return nil, errHeader
	}

	h := &fotHeader{
		headerLen: headerLen,
		totalLen:  totalLen,
	}
	copy(h.dataIV[:], blob[19:35])
	copy(h.salt[:], blob[35:44])
	if int64(len(blob)) >= totalLen {
		copy(h.bodyTag[:], blob[totalLen-tagLen:])
	}

	// parse the variable-length metadata entries:
	// uint16_be entry_len | uint8 key_len | key[key_len] | value[entry_len-3-key_len]
	offset := fixedHeaderLen
	for offset < headerLen {
		if offset+3 > headerLen {
			return nil, errMeta
		}
		entryLen := int(binary.BigEndian.Uint16(blob[offset : offset+2]))
		keyLen := int(blob[offset+2])
		if entryLen < keyLen+3 || offset+entryLen > headerLen {
			return nil, errMeta
		}
		keyEnd := offset + 3 + keyLen
		key := string(blob[offset+3 : keyEnd])
		value := blob[keyEnd : offset+entryLen]
		switch key {
		case "usability":
			raw, err := base64.StdEncoding.DecodeString(string(value))
			if err != nil {
				return nil, errBadBase64
			}
			// raw = 16-byte IV + 38-byte fixed check ciphertext
			if len(raw) != ivLen+usabilityPlaintextLen {
				return nil, errMeta
			}
			copy(h.usabilityIV[:], raw[:ivLen])
			h.usabilityCT = append([]byte(nil), raw[ivLen:]...)
		case "filename":
			raw, err := base64.StdEncoding.DecodeString(string(value))
			if err != nil {
				return nil, errBadBase64
			}
			if len(raw) < tagLen {
				return nil, errMeta
			}
			h.fileNameCT = append([]byte(nil), raw[:len(raw)-tagLen]...)
			copy(h.fileNameTag[:], raw[len(raw)-tagLen:])
		}
		offset += entryLen
	}
	if offset != headerLen {
		return nil, errMeta
	}
	if h.usabilityCT == nil || h.fileNameCT == nil {
		return nil, fmt.Errorf("%w: missing usability or filename entry", errMeta)
	}
	return h, nil
}

// buildEntry encodes one metadata entry:
// uint16_be entry_len | uint8 key_len | key | value
func buildEntry(key, value string) []byte {
	entry := make([]byte, 0, 3+len(key)+len(value))
	entry = binary.BigEndian.AppendUint16(entry, uint16(3+len(key)+len(value)))
	entry = append(entry, byte(len(key)))
	entry = append(entry, key...)
	entry = append(entry, value...)
	return entry
}

// deriveKey runs PBKDF2-HMAC-SHA256 with the fixed KDF prefix concatenated with the file salt.
func deriveKey(password string, salt []byte, iterations int) []byte {
	kdfSalt := make([]byte, 0, len(kdfPrefix)+len(salt))
	kdfSalt = append(kdfSalt, kdfPrefix...)
	kdfSalt = append(kdfSalt, salt...)
	return pbkdf2.Key([]byte(password), kdfSalt, iterations, keyLen, sha256.New)
}

// validatePassword decrypts the usability check value to confirm the password is correct.
func (h *fotHeader) validatePassword(password string) error {
	key := deriveKey(password, h.salt[:], usabilityRounds)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(block, h.usabilityIV[:])
	plain := make([]byte, len(h.usabilityCT))
	ctr.XORKeyStream(plain, h.usabilityCT)
	if !hmac.Equal(plain, usabilityPlaintext) {
		return errPassword
	}
	return nil
}

// decryptFilename authenticates and decrypts the stored filename.
func (h *fotHeader) decryptFilename(password string) (string, error) {
	key := deriveKey(password, h.salt[:], filenameRounds)
	mac := hmac.New(sha256.New, key)
	mac.Write(h.fileNameCT)
	computed := mac.Sum(nil)[:tagLen]
	if !hmac.Equal(computed, h.fileNameTag[:]) {
		return "", errFilename
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ctr := cipher.NewCTR(block, h.dataIV[:])
	plain := make([]byte, len(h.fileNameCT))
	ctr.XORKeyStream(plain, h.fileNameCT)
	name := string(plain)
	if name == "" || name == "." || name == ".." {
		return "", errBadFilename
	}
	for _, c := range name {
		if c == '/' || c == '\\' {
			return "", errBadFilename
		}
	}
	return name, nil
}

// fotCipher holds the per-file decryption key and layout, enabling random access.
type fotCipher struct {
	h         *fotHeader
	bodyKey   [keyLen]byte
	cipherLen int64 // plaintext size == body ciphertext size
	block     cipher.Block
	filename  string
}

// newFotCipher derives the body key and stores the authenticated filename.
func newFotCipher(h *fotHeader, password string) (*fotCipher, error) {
	name, err := h.decryptFilename(password)
	if err != nil {
		return nil, err
	}
	key := deriveKey(password, h.salt[:], bodyRounds)
	var k [keyLen]byte
	copy(k[:], key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	return &fotCipher{
		h:         h,
		bodyKey:   k,
		cipherLen: h.totalLen - int64(h.headerLen) - tagLen,
		block:     block,
		filename:  name,
	}, nil
}

// PlainLen returns the plaintext size of the body (equal to the body ciphertext length).
func (c *fotCipher) PlainLen() int64 {
	return c.cipherLen
}

// incrementCTRIv adds skip to the big-endian 128-bit counter encoded in iv.
func incrementCTRIv(iv [ivLen]byte, skip int64) [ivLen]byte {
	n := iv
	carry := uint64(skip)
	for i := ivLen - 1; i >= 0; i-- {
		sum := uint64(n[i]) + carry&0xff
		carry = (uint64(n[i]) + carry) >> 8
		n[i] = byte(sum)
		if carry == 0 {
			break
		}
	}
	return n
}

// NewCTRForOffset returns an AES-256-CTR stream positioned at plaintext offset off.
// AES-CTR treats the 128-bit IV as a big-endian counter: the first 16 bytes of plaintext
// use counter = dataIV, the next 16 use dataIV+1, and so on. To decrypt a range starting
// at byte offset off, we jump the counter by off/16 blocks, then pre-warm the keystream
// by off%16 bytes so the stream starts exactly at off.
func (c *fotCipher) NewCTRForOffset(off int64) cipher.Stream {
	iv := c.h.dataIV
	skip := off / ivLen
	if skip > 0 {
		iv = incrementCTRIv(iv, skip)
	}
	ctr := cipher.NewCTR(c.block, iv[:])
	prefix := off - skip*ivLen
	if prefix > 0 {
		buf := make([]byte, prefix)
		ctr.XORKeyStream(buf, buf)
	}
	return ctr
}

// verifyBodyTag authenticates the full body ciphertext against the trailing tag.
func (c *fotCipher) verifyBodyTag(ciphertext []byte) bool {
	mac := hmac.New(sha256.New, c.bodyKey[:])
	mac.Write(ciphertext)
	return hmac.Equal(mac.Sum(nil)[:tagLen], c.h.bodyTag[:])
}
