// Package horcrux provides security question style password recovery while
// preserving end-to-end cryptographic security.
//
// Given N pairs of security questions and answers, the secret is split using
// Shamir's Secret Sharing algorithm into N shares, one for each question. A
// 256-bit key is derived from the answer to each question using scrypt, and the
// share is then encrypted with that key using ChaCha20Poly1305.
//
// To recover the secret given K of N answers, the secret keys are re-derived and
// the shares are decrypted and combined.
package horcrux

import (
	"crypto/rand"
	"fmt"
	"io"

	"code.google.com/p/go.crypto/scrypt"
	"github.com/codahale/chacha20"
	"github.com/codahale/chacha20poly1305"
	"github.com/codahale/sss"
)

const (
	saltLen = 32
)

// Fragment is an encrypted fragment of the secret associated with a security
// question.
type Fragment struct {
	ID int // ID is a unique identifier for the fragment.
	K  int // K is the number of fragments required to recover the secret.
	N  int // N is the scrypt iteration parameter.
	R  int // R is the scrypt memory parameter.
	P  int // P is the scrypt parallelism parameter.

	Question string // Question is the security question.
	Nonce    []byte // Nonce is the random nonce used for encryption.
	Salt     []byte // Salt is the random salted used for scrypt.
	Value    []byte // Value is the encrypted share.
}

func (f Fragment) String() string {
	return fmt.Sprintf("%d/%d:%s:%d:%d:%d:%x:%x",
		f.ID, f.K, f.Question, f.N, f.R, f.P, f.Salt, f.Value)
}

// Answer is an encrypted fragment of the secret, plus the answer to the
// security question.
type Answer struct {
	Fragment
	Answer string // Answer is the answer to the security question.
}

func (f Answer) String() string {
	return fmt.Sprintf("%v:%s", f.Fragment, f.Answer)
}

// Split splits the given secret into encrypted fragments based on the given
// security questions. k is the number of fragments required to recover the
// secret. n is the scrypt iteration parameter, and should be set fairly high
// due to the low entropy of most security question answers (recommended: 2<<14).
// r is the scrypt memory parameter (recommended: 8). p is the scrypt parallelism
// parameter (recommended: 1). Returns either a slice of fragments or an error.
func Split(secret []byte, questions map[string]string, k, n, r, p int) ([]Fragment, error) {
	shares, err := sss.Split(len(questions), k, secret)
	if err != nil {
		return nil, err
	}

	f := make([]Fragment, 0, len(questions))

	i := 1
	for q, a := range questions {
		salt := make([]byte, saltLen)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			return nil, err
		}

		frag := Fragment{
			N:        n,
			R:        r,
			P:        p,
			ID:       i,
			K:        k,
			Salt:     salt,
			Question: q,
		}

		k, err := scrypt.Key([]byte(a), salt, frag.N, frag.R, frag.P, chacha20.KeySize)
		if err != nil {
			return nil, err
		}

		frag.Nonce = make([]byte, chacha20.NonceSize)
		_, err = io.ReadFull(rand.Reader, frag.Nonce)
		if err != nil {
			return nil, err
		}

		aead, err := chacha20poly1305.NewChaCha20Poly1305(k)
		if err != nil {
			return nil, err
		}
		frag.Value = aead.Seal(nil, frag.Nonce, shares[i], nil)

		f = append(f, frag)

		i++
	}

	return f, nil
}

// Recover combines the given answers and returns the original secret or an
// error.
func Recover(answers []Answer) ([]byte, error) {
	shares := make(map[int][]byte)

	for _, a := range answers {
		if a.K > len(answers) {
			return nil, fmt.Errorf(
				"horcrux: need at least %d answers but only have %d",
				a.K, len(answers))
		}

		k, err := scrypt.Key([]byte(a.Answer), a.Salt, a.N, a.R, a.P,
			chacha20.KeySize)
		if err != nil {
			return nil, err
		}

		aead, err := chacha20poly1305.NewChaCha20Poly1305(k)
		if err != nil {
			return nil, err
		}

		v, err := aead.Open(nil, a.Nonce, a.Value, nil)
		if err != nil {
			return nil, err
		}

		shares[a.ID] = v
	}

	return sss.Combine(shares), nil
}
