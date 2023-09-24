package trie

import (
	"testing"
)

func TestSuffixQuery(t *testing.T) {
	words := []string{
		"example.co.uk.", "localhost.", "org.",
		"example-org.com.", "www.example.com.", "123-example.io",
	}
	trie := NewSuffixTrie(words)
	testCase := map[string]bool{
		"www.example.com.":     true,
		"example.com.":         false,
		"123-example.co.uk.":   true,
		"example.io.":          false,
		"www.123-example.io.":  false,
		"1.www.example.co.uk.": true,
	}

	for k, v := range testCase {
		s, st := trie.Query(k)
		if st != v {
			t.Errorf("%s should suffix with %s\n", k, s)
		}
		/*
			if st {
				fmt.Printf("%s suffix with %s\n", k, s)
			}
		*/
	}
}

func TestPrefixQuery(t *testing.T) {
	words := []string{
		"1-example", "123-example", "www.example",
		"localhost", "example-", "www-",
	}
	trie := NewPrefixTrie(words)
	testCase := map[string]bool{
		"example.com.":         false,
		"example-org.com.":     true,
		"localhost.":           true,
		"www.example.com.":     true,
		"www.123-example.com.": false,
		"123-example.com.":     true,
		"www-1.example.com":    true,
	}

	for k, v := range testCase {
		s, st := trie.Query(k)
		if st != v {
			t.Errorf("%s should prefix with %s\n", k, s)
		}
		/*
			if st {
				fmt.Printf("%s prefix with %s\n", k, s)
			}
		*/
	}
}
