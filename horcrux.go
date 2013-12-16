// Package horcrux provides security question style password recovery while
// preserving end-to-end cryptographic security.
//
// Given N pairs of security questions and answers, the secret is split using
// Shamir's Secret Sharing algorithm into N shares, one for each question. A
// 256-bit key is derived from the answer to each question using PBKDF2-SHA512,
// and the share is then encrypted with that key using 256-bit AES-GCM.
//
// To recover the secret given K of N answers, the secret keys are re-derived and
// the shares are decrypted and combined.
//
// This package has not been audited by cryptography or security professionals.
package horcrux

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"crypto/cipher"
	"code.google.com/p/go.crypto/pbkdf2"
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
	N  int // N is the PBKDF2 iteration parameter.

	Question string // Question is the security question.
	Nonce    []byte // Nonce is the random nonce used for encryption.
	Salt     []byte // Salt is the random salt used for PBKDF2.
	Value    []byte // Value is the encrypted share.
}

func (f Fragment) String() string {
	return fmt.Sprintf("%d/%d:%s:%d:%x:%x",
		f.ID, f.K, f.Question, f.N, f.Salt, f.Value)
}

// Answer is an encrypted fragment of the secret, plus the answer to the
// security question.
type Answer struct {
	Fragment        // Fragment is the previously-encrypted fragment.
	Answer   string // Answer is the answer to the security question.
}

func (f Answer) String() string {
	return fmt.Sprintf("%v:%s", f.Fragment, f.Answer)
}

// Split splits the given secret into encrypted fragments based on the given
// security questions. k is the number of fragments required to recover the
// secret. n is the PBKDF2 iteration parameter, and should be set fairly high
// due to the low entropy of most security question answers (recommended: 2<<14).
// Returns either a slice of fragments or an error.
func Split(secret []byte, questions map[string]string, k, n int) ([]Fragment, error) {
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
			ID:       i,
			K:        k,
			Salt:     salt,
			Question: q,
		}

		k := pbkdf2.Key([]byte(a), salt, frag.N, 32, sha512.New)

		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		frag.Nonce = make([]byte, gcm.NonceSize())
		frag.Value = gcm.Seal(nil, frag.Nonce, shares[i], nil)

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

		k := pbkdf2.Key([]byte(a.Answer), a.Salt, a.N, 32, sha512.New)

		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		v, err := gcm.Open(nil, a.Nonce, a.Value, nil)
		if err != nil {
			return nil, err
		}

		shares[a.ID] = v
	}

	return sss.Combine(shares), nil
}
