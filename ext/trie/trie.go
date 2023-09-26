package trie

type node struct {
	next map[byte]*node
	//word bool
}

/*
type Trie struct {
	root *node
}
*/

type SuffixTrie struct {
	root *node
}

type PrefixTrie struct {
	root *node
}

type Trie interface {
	Query(string) (string bool)
}

func NewSuffixTrie(words []string) *SuffixTrie {
	return newSuffixTrie(words)
}

func newSuffixTrie(words []string) *SuffixTrie {
	t := &SuffixTrie{
		root: &node{
			next: make(map[byte]*node),
		},
	}

	for _, word := range words {
		t.add(word)
	}
	return t
}

func (t *SuffixTrie) Add(word string) {
	t.add(word)
}

func (t *SuffixTrie) add(word string) {
	curr := t.root
	for i := len(word) - 1; i >= 0; i-- {
		b := word[i]
		if _, found := curr.next[b]; !found {
			curr.next[b] = &node{next: make(map[byte]*node)}
		}
		curr = curr.next[b]
	}
	//curr.word = true
	curr.next['$'] = nil
}

func (t *SuffixTrie) Query(word string) (string, bool) {
	return t.query(word)
}

func (t *SuffixTrie) query(word string) (string, bool) {
	curr := t.root
	for i := len(word) - 1; i >= 0; i-- {
		b := word[i]

		if _, found := curr.next[b]; !found {
			return "", false
		}
		curr = curr.next[b]
		/*
			if curr.word {
				return word[i:], true
			}
		*/
		if _v, found := curr.next['$']; found && _v == nil {
			return word[i:], true
		}
	}
	return "", false
}

// Prefix Tree
func NewPrefixTrie(words []string) *PrefixTrie {
	return newPrefixTrie(words)
}

func newPrefixTrie(words []string) *PrefixTrie {
	t := &PrefixTrie{
		root: &node{
			next: make(map[byte]*node),
		},
	}

	for _, word := range words {
		t.add(word)
	}
	return t
}

func (t *PrefixTrie) Add(word string) {
	t.add(word)
}

func (t *PrefixTrie) add(word string) {
	curr := t.root
	for i := 0; i < len(word); i++ {
		b := word[i]
		if _, found := curr.next[b]; !found {
			curr.next[b] = &node{next: make(map[byte]*node)}
		}
		curr = curr.next[b]
	}
	//curr.word = true
	curr.next['$'] = nil
}

func (t *PrefixTrie) Query(word string) (string, bool) {
	return t.query(word)
}

func (t *PrefixTrie) query(word string) (string, bool) {
	curr := t.root
	for i := 0; i < len(word); i++ {
		b := word[i]

		if _, found := curr.next[b]; !found {
			return "", false
		}
		curr = curr.next[b]
		/*
			if curr.word {
				return word[i:], true
			}
		*/
		if _v, found := curr.next['$']; found && _v == nil {
			return word[:i+1], true
		}
	}
	return "", false
}
