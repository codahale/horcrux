package horcrux

import (
	"fmt"
	"testing"
)

func TestFragmentStringer(t *testing.T) {
	f := Fragment{
		ID:       1,
		N:        2,
		R:        3,
		P:        4,
		K:        5,
		Question: "Q",
		Nonce:    []byte{10},
		Salt:     []byte{11},
		Value:    []byte{12},
	}

	expected := "1/5:Q:2:3:4:0b:0c"
	actual := f.String()
	if actual != expected {
		t.Fatalf("Expected %v but was %v", expected, actual)
	}
}

func TestAnswerStringer(t *testing.T) {
	a := Answer{
		Fragment: Fragment{
			ID:       1,
			N:        2,
			R:        3,
			P:        4,
			K:        5,
			Question: "Q",
			Nonce:    []byte{10},
			Salt:     []byte{11},
			Value:    []byte{12},
		},
		Answer: "A",
	}

	expected := "1/5:Q:2:3:4:0b:0c:A"
	actual := a.String()
	if actual != expected {
		t.Fatalf("Expected %v but was %v", expected, actual)
	}
}

func Example() {
	secret := []byte("my favorite password")
	questions := map[string]string{
		"What's your first pet's name?":     "Spot",
		"What's your least favorite food?":  "broccoli",
		"What's your mother's maiden name?": "Hernandez",
		"What's your real name?":            "Rumplestiltskin",
	}

	// Split into four fragments, any two of which can be combined to recover
	// the secret.
	frags, err := Split(secret, questions, 2, 2<<14, 8, 1)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Answer two of the security questions.
	answers := make([]Answer, 2)
	for i := range answers {
		answers[i] = Answer{
			Fragment: frags[i],
			Answer:   questions[frags[i].Question],
		}
	}

	// Recover the original secret.
	s, err := Recover(answers)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(s))
	// Output:
	// my favorite password
}

var (
	secret    = []byte("my favorite password")
	questions = map[string]string{
		"What's your first pet's name?":     "Spot",
		"What's your least favorite food?":  "broccoli",
		"What's your mother's maiden name?": "Hernandez",
		"What's your real name?":            "Rumplestiltskin",
	}
)

func TestSplitBadSssParams(t *testing.T) {
	frags, err := Split(secret, questions, 1, 2<<10, 8, 1)
	if err == nil {
		t.Fatalf("Expected error but got %v", frags)
	}

	expected := "K must be > 1"
	actual := err.Error()
	if actual != expected {
		t.Fatalf("Expected %v but was %v", expected, actual)
	}
}

func TestSplitBadScryptParams(t *testing.T) {
	frags, err := Split(secret, questions, 2, 7, 8, 1)
	if err == nil {
		t.Fatalf("Expected error but got %v", frags)
	}

	expected := "scrypt: N must be > 1 and a power of 2"
	actual := err.Error()
	if actual != expected {
		t.Fatalf("Expected %v but was %v", expected, actual)
	}
}

func TestRecoverTooFewAnswers(t *testing.T) {
	frags, err := Split(secret, questions, 2, 2<<10, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	answers := make([]Answer, 1)
	for i := range answers {
		answers[i] = Answer{
			Fragment: frags[i],
			Answer:   questions[frags[i].Question],
		}
	}

	s, err := Recover(answers)
	if s != nil {
		t.Fatalf("Expected nil, but was %v", s)
	}

	expected := "horcrux: need at least 2 answers but only have 1"
	actual := err.Error()
	if actual != expected {
		t.Fatalf("Expected %v but was %v", expected, actual)
	}
}

func TestRecoverBadAnswers(t *testing.T) {
	frags, err := Split(secret, questions, 2, 2<<10, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	answers := make([]Answer, 2)
	for i := range answers {
		answers[i] = Answer{
			Fragment: frags[i],
			Answer:   questions[frags[i].Question] + "woo",
		}
	}

	s, err := Recover(answers)
	if s != nil {
		t.Fatalf("Expected nil, but was %v", s)
	}

	expected := "message authentication failed"
	actual := err.Error()
	if actual != expected {
		t.Fatalf("Expected %v but was %v", expected, actual)
	}
}
