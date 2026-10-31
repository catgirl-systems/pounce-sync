package roster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
)

const (
	maxActive  = 32
	maxEntries = 10000
	maxMeta    = 1024
)

var ErrInvalid = errors.New("roster: invalid entry")

type Device struct {
	ID, SignPub, KemPub, Meta []byte
}

type Entry struct {
	AccountID []byte
	Index     uint64
	PrevHash  []byte
	Action    string
	Device    Device // genesis, add_device, recover
	TargetID  []byte // remove_device
	Epoch     uint32 // rotate
	SignerID  []byte

	RecoveryID, RecoverySignPub, RecoveryKemPub []byte // genesis
}

// Parse decodes a body and checks sizes and keys; chain and signer rules are in `Apply`.
func Parse(body []byte) (*Entry, error) {
	// read latches the first failure, so later reads return nil and the final
	// check rejects the entry. reads run in field order (go evaluates left to right).
	in, read := cryptobyte.String(body), true
	str := func() []byte {
		var n uint32
		var v []byte
		read = read && in.ReadUint32(&n) && in.ReadBytes(&v, int(n))
		return v[:len(v):len(v)]
	}
	e := &Entry{}
	label := string(str())
	e.AccountID = str()
	read = read && in.ReadUint64(&e.Index)
	e.PrevHash = str()
	e.Action = string(str())
	valid := false
	switch e.Action {
	case "genesis", "add_device", "recover":
		e.Device = Device{str(), str(), str(), str()}
		valid = validDevice(e.Device)
		if e.Action == "genesis" {
			e.RecoveryID, e.RecoverySignPub, e.RecoveryKemPub = str(), str(), str()
			valid = valid && len(e.RecoveryID) == 16 && validKey(e.RecoverySignPub) && validKey(e.RecoveryKemPub)
		}
	case "remove_device":
		e.TargetID = str()
		valid = len(e.TargetID) == 16
	case "rotate":
		read = read && in.ReadUint32(&e.Epoch)
		valid = true
	}
	e.SignerID = str()
	// trailing bytes are never ignored.
	if !read || !in.Empty() || !valid || label != "pounce/v1/roster" ||
		len(e.AccountID) != 16 || len(e.PrevHash) != 32 || len(e.SignerID) != 16 {
		return nil, ErrInvalid
	}
	return e, nil
}

func validDevice(d Device) bool {
	return len(d.ID) == 16 && validKey(d.SignPub) && validKey(d.KemPub) && len(d.Meta) <= maxMeta
}

// validKey accepts only a 65-byte uncompressed P-256 point on the curve.
func validKey(pub []byte) bool {
	_, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	return err == nil
}

func Hash(body, sig []byte) []byte {
	h := sha256.Sum256(message(body, sig))
	return h[:]
}

var halfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// Verify is the one signature check of the server: ECDSA P-256 over SHA-256(msg),
// with sig the raw 64-byte r | s. s must be in the lower half of the order, so a
// signed entry has exactly one valid encoding and one hash.
func Verify(pub, msg, sig []byte) bool {
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil || len(sig) != 64 {
		return false
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if s.Cmp(halfOrder) > 0 {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.Verify(k, h[:], r, s)
}

// message is the ssh encoding (rfc 4251 §5) of every signed byte string: strings
// and byte slices as uint32 length-prefixed strings, uint32 big-endian. it must
// match `SSHWire.swift` in the app byte for byte.
func message(fields ...any) []byte {
	var b cryptobyte.Builder
	for _, f := range fields {
		switch v := f.(type) {
		case string:
			b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes([]byte(v)) })
		case []byte:
			b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(v) })
		case uint32:
			b.AddUint32(v)
		default:
			panic("roster: unsupported message field")
		}
	}
	return b.BytesOrPanic()
}

func AuthMessage(origin string, accountID, deviceID, nonce []byte) []byte {
	return message("pounce/v1/auth", origin, accountID, deviceID, nonce)
}

func WrappedKeyMessage(accountID, recipientID []byte, epoch uint32, blob []byte) []byte {
	return message("pounce/v1/wrapped-key", accountID, recipientID, epoch, blob)
}

func PairingNonceMessage(accountID, pairingID, payloadHash, nonce []byte) []byte {
	return message("pounce/v1/pairing-nonce", accountID, pairingID, payloadHash, nonce)
}

func DeleteMessage(origin string, accountID, deviceID, headHash []byte) []byte {
	return message("pounce/v1/delete-account", origin, accountID, deviceID, headHash)
}

type Member struct {
	SignPub []byte
	Active  bool
}

// State is the roster after Count entries. Devices holds every device ever
// added, active or not, so together with RecoveryID it is the set of used ids.
// RotatePending is set by remove_device and recover and cleared by the rotate
// that must follow them; it is the only time a rotate is accepted.
type State struct {
	AccountID     []byte
	Count         uint64
	HeadHash      []byte
	Epoch         uint32
	RotatePending bool
	RecoveryID    []byte
	RecoveryPub   []byte
	Devices       map[string]*Member
}

func (s *State) ActiveCount() int {
	n := 0
	for _, m := range s.Devices {
		if m.Active {
			n++
		}
	}
	return n
}

func (s *State) used(id []byte) bool {
	_, ok := s.Devices[string(id)]
	return ok || bytes.Equal(id, s.RecoveryID)
}

func (s *State) active(id []byte) *Member {
	if m := s.Devices[string(id)]; m != nil && m.Active {
		return m
	}
	return nil
}

// Apply checks every rule for appending (body, sig) as the next entry, then
// applies its effects; on error the state is left untouched.
func (s *State) Apply(body, sig []byte) (*Entry, error) {
	e, err := Parse(body)
	if err != nil {
		return nil, err
	}
	prev := s.HeadHash
	if s.Count == 0 {
		prev = make([]byte, 32)
	}
	// the entry cap stops growth only: removals, recoveries and the rotate they
	// call for always go through, so a device can never make itself unevictable.
	if !bytes.Equal(e.AccountID, s.AccountID) || e.Index != s.Count || (e.Index >= maxEntries && e.Action == "add_device") ||
		!bytes.Equal(e.PrevHash, prev) || (s.Count == 0) != (e.Action == "genesis") {
		return nil, ErrInvalid
	}

	// signer is the active device named by SignerID, except for genesis
	// (the device in the entry) and recover (the recovery key).
	var signer []byte
	if m := s.active(e.SignerID); m != nil {
		signer = m.SignPub
	}
	ok := false
	switch e.Action {
	case "genesis":
		signer = e.Device.SignPub
		ok = bytes.Equal(e.SignerID, e.Device.ID) && !bytes.Equal(e.Device.ID, e.RecoveryID)
	case "add_device":
		ok = signer != nil && !s.used(e.Device.ID) && s.ActiveCount() < maxActive
	case "remove_device":
		ok = signer != nil && s.active(e.TargetID) != nil
	case "rotate":
		ok = signer != nil && s.RotatePending && e.Epoch == s.Epoch+1
	case "recover":
		signer = s.RecoveryPub
		ok = bytes.Equal(e.SignerID, s.RecoveryID) && !s.used(e.Device.ID)
	}
	if !ok || !Verify(signer, body, sig) {
		return nil, ErrInvalid
	}

	switch e.Action {
	case "genesis":
		s.Epoch = 1
		s.RecoveryID = e.RecoveryID
		s.RecoveryPub = e.RecoverySignPub
		s.Devices = map[string]*Member{}
	case "remove_device":
		s.Devices[string(e.TargetID)].Active = false
		s.RotatePending = true
	case "rotate":
		s.Epoch = e.Epoch
		s.RotatePending = false
	case "recover":
		for _, m := range s.Devices {
			m.Active = false
		}
		s.RotatePending = true
	}
	// Parse sets Device only for genesis, add_device and recover.
	if e.Device.ID != nil {
		s.Devices[string(e.Device.ID)] = &Member{SignPub: e.Device.SignPub, Active: true}
	}
	s.Count++
	s.HeadHash = Hash(body, sig)
	return e, nil
}
