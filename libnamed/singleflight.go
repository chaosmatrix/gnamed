/*
Copyright 2012 Google Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package singleflight provides a duplicate function call suppression
// mechanism.
//package singleflight

package libnamed

import (
	"sync"

	"github.com/miekg/dns"
)

// call is an in-flight or completed Do call
type call struct {
	wg    sync.WaitGroup
	val   *dns.Msg
	err   error
	count int // count of in-flight
}

// Group represents a class of work and forms a namespace in which
// units of work can be executed with duplicate suppression.
type Group struct {
	mu sync.Mutex       // protects m
	m  map[string]*call // lazily initialized
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
func (g *Group) Do(key string, fn func() (*dns.Msg, error)) (*dns.Msg, bool, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		c.count++
		g.mu.Unlock()
		c.wg.Wait()
		// caller might update value, need to do copy
		if c.err != nil {
			return c.val, true, c.err
		}
		return c.val.Copy(), true, c.err
	}
	c := new(call)
	c.count = 1
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	// if no concurrency flying request, it wast time to do deep copy
	if c.err != nil {
		return c.val, false, c.err
	}

	if c.count == 1 {
		// only one, don't need to do deep copy
		return c.val, false, c.err
	}

	return c.val.Copy(), false, c.err
}
