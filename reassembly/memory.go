// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"flag"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

var memLog = flag.Bool("assembly_memuse_log", defaultDebug, "If true, the github.com/google/gopacket/reassembly library will log information regarding its memory use every once in a while.")

/*
 * pageCache
 */
// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.
type pageCache struct {
	pagePool     *sync.Pool
	used         int
	pageRequests int64
}

/*
pageCache结构体在gopacket的reassembly子目录中，主要用于避免频繁的内存分配，提高性能。

pageCache是一个并发非安全的page对象存储。它使用sync.Pool来缓存和回收page对象。sync.Pool是Go标准库提供的一个用于存储临时对象的并发安全的内存池，它可以有效减少内存分配的开销，提高性能。

pageCache结构体包含以下字段：

pagePool：一个sync.Pool对象，用于存储和回收page对象。
used：当前已使用的page对象数量。
pageRequests：已请求page对象的总数量。
在处理TCP数据包时，如果需要一个新的page对象，可以从pageCache中获取。如果pageCache中没有可用的page对象，sync.Pool会自动创建一个新的page对象。当page对象不再需要时，可以将其归还给pageCache，以便后续重用。这样可以避免频繁的内存分配和垃圾回收，提高性能。
*/

func newPageCache() *pageCache {
	pc := &pageCache{
		pagePool: &sync.Pool{
			New: func() interface{} { return new(page) },
		}}
	return pc
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time) (p *page) {
	if *memLog {
		c.pageRequests++
		if c.pageRequests&0xFFFF == 0 {
			log.Println("PageCache:", c.pageRequests, "requested,", c.used, "used,")
		}
	}
	p = c.pagePool.Get().(*page)
	p.seen = ts
	p.bytes = p.buf[:0]
	c.used++
	if *memLog {
		log.Printf("allocator returns %s\n", p)
	}

	return p
}

// replace replaces a page into the pageCache.
func (c *pageCache) replace(p *page) {
	c.used--
	if *memLog {
		log.Printf("replacing %s\n", p)
	}
	p.prev = nil
	p.next = nil
	c.pagePool.Put(p)
}

/*
 * StreamPool
 */

// StreamPool stores all streams created by Assemblers, allowing multiple
// assemblers to work together on stream processing while enforcing the fact
// that a single stream receives its data serially.  It is safe
// for concurrency, usable by multiple Assemblers at once.
//
// StreamPool handles the creation and storage of Stream objects used by one or
// more Assembler objects.  When a new TCP stream is found by an Assembler, it
// creates an associated Stream by calling its StreamFactory's New method.
// Thereafter (until the stream is closed), that Stream object will receive
// assembled TCP data via Assembler's calls to the stream's Reassembled
// function.
//
// Like the Assembler, StreamPool attempts to minimize allocation.  Unlike the
// Assembler, though, it does have to do some locking to make sure that the
// connection objects it stores are accessible to multiple Assemblers.
type StreamPool struct {
	conns              map[key]*connection
	users              int
	mu                 sync.RWMutex
	factory            StreamFactory
	free               []*connection
	all                [][]connection
	nextAlloc          int
	newConnectionCount int64
}

const initialAllocSize = 1024

func (p *StreamPool) grow() {
	conns := make([]connection, p.nextAlloc)
	p.all = append(p.all, conns)
	for i := range conns {
		p.free = append(p.free, &conns[i])
	}
	if *memLog {
		log.Println("StreamPool: created", p.nextAlloc, "new connections")
	}
	p.nextAlloc *= 2
}

// Dump logs all connections
func (p *StreamPool) Dump() {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.Printf("Remaining %d connections: ", len(p.conns))
	for _, conn := range p.conns {
		log.Printf("%v %s", conn.key, conn)
	}
}

func (p *StreamPool) remove(conn *connection) {
	p.mu.Lock()
	if _, ok := p.conns[conn.key]; ok {
		delete(p.conns, conn.key)
		p.free = append(p.free, conn)
	}
	p.mu.Unlock()
}

// NewStreamPool creates a new connection pool.  Streams will
// be created as necessary using the passed-in StreamFactory.
func NewStreamPool(factory StreamFactory) *StreamPool {
	return &StreamPool{
		conns:     make(map[key]*connection, initialAllocSize),
		free:      make([]*connection, 0, initialAllocSize),
		factory:   factory,
		nextAlloc: initialAllocSize,
	}
}

func (p *StreamPool) connections() []*connection {
	p.mu.RLock()
	conns := make([]*connection, 0, len(p.conns))
	for _, conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.RUnlock()
	return conns
}

func (p *StreamPool) newConnection(k key, s Stream, ts time.Time) (c *connection, h *halfconnection, r *halfconnection) {
	if *memLog {
		p.newConnectionCount++
		if p.newConnectionCount&0x7FFF == 0 {
			log.Println("StreamPool:", p.newConnectionCount, "requests,", len(p.conns), "used,", len(p.free), "free")
		}
	}
	if len(p.free) == 0 {
		p.grow()
	}
	index := len(p.free) - 1
	c, p.free = p.free[index], p.free[:index]
	c.reset(k, s, ts)
	return c, &c.c2s, &c.s2c
}

func (p *StreamPool) getHalf(k key) (*connection, *halfconnection, *halfconnection) {
	conn := p.conns[k]
	if conn != nil {
		return conn, &conn.c2s, &conn.s2c
	}
	rk := k.Reverse()
	conn = p.conns[rk]
	if conn != nil {
		return conn, &conn.s2c, &conn.c2s
	}
	return nil, nil, nil
}

// getConnection returns a connection.  If end is true and a connection
// does not already exist, returns nil.  This allows us to check for a
// connection without actually creating one if it doesn't already exist.
func (p *StreamPool) getConnection(k key, end bool, ts time.Time, tcp *layers.TCP, ac AssemblerContext) (*connection, *halfconnection, *halfconnection) {
	p.mu.RLock()
	conn, half, rev := p.getHalf(k)
	p.mu.RUnlock()
	if end || conn != nil {
		return conn, half, rev
	}
	s := p.factory.New(k[0], k[1], tcp, ac)
	p.mu.Lock()
	defer p.mu.Unlock()
	conn, half, rev = p.newConnection(k, s, ts)
	conn2, half2, rev2 := p.getHalf(k)
	if conn2 != nil {
		if conn2.key != k {
			panic("FIXME: other dir added in the meantime...")
		}
		// FIXME: delete s ?
		return conn2, half2, rev2
	}
	p.conns[k] = conn
	return conn, half, rev
}
