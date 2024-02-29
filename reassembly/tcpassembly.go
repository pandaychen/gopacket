// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package reassembly provides TCP stream re-assembly.
//
// The reassembly package implements uni-directional TCP reassembly, for use in
// packet-sniffing applications.  The caller reads packets off the wire, then
// presents them to an Assembler in the form of gopacket layers.TCP packets
// (github.com/google/gopacket, github.com/google/gopacket/layers).
//
// The Assembler uses a user-supplied
// StreamFactory to create a user-defined Stream interface, then passes packet
// data in stream order to that object.  A concurrency-safe StreamPool keeps
// track of all current Streams being reassembled, so multiple Assemblers may
// run at once to assemble packets while taking advantage of multiple cores.
//
// TODO: Add simplest example
package reassembly

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TODO:
// - push to Stream on Ack
// - implement chunked (cheap) reads and Reader() interface
// - better organize file: split files: 'mem', 'misc' (seq + flow)

var defaultDebug = false

var debugLog = flag.Bool("assembly_debug_log", defaultDebug, "If true, the github.com/google/gopacket/reassembly library will log verbose debugging information (at least one line per packet)")

const invalidSequence = -1
const uint32Max = 0xFFFFFFFF

// Sequence is a TCP sequence number.  It provides a few convenience functions
// for handling TCP wrap-around.  The sequence should always be in the range
// [0,0xFFFFFFFF]... its other bits are simply used in wrap-around calculations
// and should never be set.
type Sequence int64

/*
Sequence类型在gopacket的reassembly子目录中，用于表示TCP序列号。它提供了一些便利功能来处理TCP序列号的回绕（wrap-around）。TCP序列号是一个32位无符号整数，范围是[0,0xFFFFFFFF]。序列号在达到最大值后会回绕到0重新开始。

Sequence类型是一个别名，它将int64类型重定义为Sequence。通过使用int64类型，可以方便地处理TCP序列号的加法、减法等操作，同时考虑到回绕的情况。

在TCP流重组过程中，Sequence类型用于表示数据包的序列号，以便按照正确的顺序对数据包进行排序和重组。
*/

// Difference defines an ordering for comparing TCP sequences that's safe for
// roll-overs.  It returns:
//
//	> 0 : if t comes after s
//	< 0 : if t comes before s
//	  0 : if t == s
//
// The number returned is the sequence difference, so 4.Difference(8) will
// return 4.
//
// It handles rollovers by considering any sequence in the first quarter of the
// uint32 space to be after any sequence in the last quarter of that space, thus
// wrapping the uint32 space.
func (s Sequence) Difference(t Sequence) int {
	if s > uint32Max-uint32Max/4 && t < uint32Max/4 {
		t += uint32Max
	} else if t > uint32Max-uint32Max/4 && s < uint32Max/4 {
		s += uint32Max
	}
	return int(t - s)
}

// Add adds an integer to a sequence and returns the resulting sequence.
func (s Sequence) Add(t int) Sequence {
	return (s + Sequence(t)) & uint32Max
}

// TCPAssemblyStats provides some figures for a ScatterGather
type TCPAssemblyStats struct {
	// For this ScatterGather
	Chunks  int
	Packets int
	// For the half connection, since last call to ReassembledSG()
	QueuedBytes    int
	QueuedPackets  int
	OverlapBytes   int
	OverlapPackets int
}

/*
TCPAssemblyStats结构体在gopacket的reassembly子目录中，主要用于提供一些关于ScatterGather（分散/聚集）的统计数据。

ScatterGather是一种常见的数据处理模式，它允许数据在内存中的不同区域之间移动，而无需进行额外的复制。在TCP流重组中，ScatterGather可以提高数据处理的效率。

TCPAssemblyStats结构体包含以下字段：

Chunks：这个ScatterGather的块数。
Packets：这个ScatterGather的数据包数。
QueuedBytes：自上次调用ReassembledSG()以来，半连接中排队的字节数。
QueuedPackets：自上次调用ReassembledSG()以来，半连接中排队的数据包数。
OverlapBytes：自上次调用ReassembledSG()以来，半连接中重叠的字节数。
OverlapPackets：自上次调用ReassembledSG()以来，半连接中重叠的数据包数。
TCPAssemblyStats结构体提供了一种方便的方式来收集和查看关于ScatterGather的统计数据。这些数据可以用于分析TCP流重组的性能，或者用于诊断可能的问题。
*/

// ScatterGather is used to pass reassembled data and metadata of reassembled
// packets to a Stream via ReassembledSG
type ScatterGather interface {
	// Returns the length of available bytes and saved bytes
	Lengths() (int, int)
	// Returns the bytes up to length (shall be <= available bytes)
	Fetch(length int) []byte
	// Tell to keep from offset
	KeepFrom(offset int)
	// Return CaptureInfo of packet corresponding to given offset
	CaptureInfo(offset int) gopacket.CaptureInfo
	// Return some info about the reassembled chunks
	Info() (direction TCPFlowDirection, start bool, end bool, skip int)
	// Return some stats regarding the state of the stream
	Stats() TCPAssemblyStats
}

/*
ScatterGather接口在gopacket的reassembly子目录中，用于将重组后的数据和元数据传递给Stream。这是通过ReassembledSG方法实现的。

ScatterGather接口定义了一组方法，包括：

Lengths()：返回可用字节和已保存字节的长度。
Fetch(length int)：返回长度为length的字节（应该小于或等于可用字节）。
KeepFrom(offset int)：告诉ScatterGather从offset开始保留数据。
CaptureInfo(offset int)：返回与给定偏移量对应的数据包的CaptureInfo。
Info()：返回一些关于重组块的信息，包括方向、是否是开始、是否是结束以及跳过的字节数。
Stats()：返回一些关于流状态的统计信息。
ScatterGather接口提供了一种方便的方式来访问和管理重组后的数据和元数据。在处理TCP数据包时，可以通过实现ScatterGather接口，将重组后的数据和元数据传递给Stream，以便进行进一步的处理。
*/

// byteContainer is either a page or a livePacket
type byteContainer interface {
	getBytes() []byte
	length() int
	convertToPages(*pageCache, int, AssemblerContext) (*page, *page, int)
	captureInfo() gopacket.CaptureInfo
	assemblerContext() AssemblerContext
	release(*pageCache) int
	isStart() bool
	isEnd() bool
	getSeq() Sequence
	isPacket() bool
}

/*
byteContainer接口在gopacket的reassembly子目录中，用于表示一个可以包含字节数据的容器。byteContainer可以是一个page或一个livePacket。这个接口定义了一组方法来操作和管理字节数据，使得Assembler可以处理不同类型的容器，而无需关心具体的实现细节。

byteContainer接口定义了以下方法：

getBytes() []byte：返回容器中的字节数据。
length() int：返回容器中字节数据的长度。
convertToPages(*pageCache, int, AssemblerContext) (*page, *page, int)：将容器中的字节数据转换为page对象。这个方法接受一个pageCache，一个整数参数和一个AssemblerContext，返回两个page指针和一个整数。
captureInfo() gopacket.CaptureInfo：返回与容器关联的gopacket.CaptureInfo。
assemblerContext() AssemblerContext：返回与容器关联的AssemblerContext。
release(*pageCache) int：将容器中的资源释放回pageCache，并返回释放的字节数。
isStart() bool：返回容器是否表示一个TCP流的开始。
isEnd() bool：返回容器是否表示一个TCP流的结束。
getSeq() Sequence：返回容器中字节数据的序列号。
isPacket() bool：返回容器是否是一个数据包。
通过实现byteContainer接口，可以让Assembler处理不同类型的字节数据容器，如page和livePacket。这提高了代码的灵活性和可扩展性。
*/

// Implements a ScatterGather
type reassemblyObject struct {
	all       []byteContainer
	Skip      int
	Direction TCPFlowDirection
	saved     int
	toKeep    int
	// stats
	queuedBytes    int
	queuedPackets  int
	overlapBytes   int
	overlapPackets int
}

/*
reassemblyObject结构体在gopacket的reassembly子目录中，实现了ScatterGather接口。它用于将重组后的数据和元数据传递给Stream。reassemblyObject结构体包含了一个方向上的TCP数据流的状态和统计信息。

reassemblyObject结构体包含以下字段：

all：一个byteContainer类型的切片，包含所有的字节数据容器（如page和livePacket）。
Skip：一个整数，表示需要跳过的字节数。
Direction：一个TCPFlowDirection类型的值，表示数据流的方向（从客户端到服务器或从服务器到客户端）。
saved：一个整数，表示已保存的字节数。
toKeep：一个整数，表示需要保留的字节数。
queuedBytes，queuedPackets：分别表示已排队的字节数和数据包数。
overlapBytes，overlapPackets：分别表示重叠的字节数和数据包数。
reassemblyObject结构体实现了ScatterGather接口，提供了一种方便的方式来访问和管理重组后的数据和元数据。在处理TCP数据包时，可以通过reassemblyObject结构体将重组后的数据和元数据传递给Stream，以便进行进一步的处理。
*/

func (rl *reassemblyObject) Lengths() (int, int) {
	l := 0
	for _, r := range rl.all {
		l += r.length()
	}
	return l, rl.saved
}

func (rl *reassemblyObject) Fetch(l int) []byte {
	if l <= rl.all[0].length() {
		return rl.all[0].getBytes()[:l]
	}
	bytes := make([]byte, 0, l)
	for _, bc := range rl.all {
		bytes = append(bytes, bc.getBytes()...)
	}
	return bytes[:l]
}

func (rl *reassemblyObject) KeepFrom(offset int) {
	rl.toKeep = offset
}

func (rl *reassemblyObject) CaptureInfo(offset int) gopacket.CaptureInfo {
	if offset < 0 {
		return gopacket.CaptureInfo{}
	}

	current := 0
	for _, r := range rl.all {
		if current+r.length() > offset {
			return r.captureInfo()
		}
		current += r.length()
	}
	// Invalid offset
	return gopacket.CaptureInfo{}
}

func (rl *reassemblyObject) Info() (TCPFlowDirection, bool, bool, int) {
	return rl.Direction, rl.all[0].isStart(), rl.all[len(rl.all)-1].isEnd(), rl.Skip
}

func (rl *reassemblyObject) Stats() TCPAssemblyStats {
	packets := int(0)
	for _, r := range rl.all {
		if r.isPacket() {
			packets++
		}
	}
	return TCPAssemblyStats{
		Chunks:         len(rl.all),
		Packets:        packets,
		QueuedBytes:    rl.queuedBytes,
		QueuedPackets:  rl.queuedPackets,
		OverlapBytes:   rl.overlapBytes,
		OverlapPackets: rl.overlapPackets,
	}
}

const pageBytes = 1900

// TCPFlowDirection distinguish the two half-connections directions.
//
// TCPDirClientToServer is assigned to half-connection for the first received
// packet, hence might be wrong if packets are not received in order.
// It's up to the caller (e.g. in Accept()) to decide if the direction should
// be interpretted differently.
type TCPFlowDirection bool

/*
TCPFlowDirection类型在gopacket的reassembly子目录中，用于区分一个TCP连接的两个方向：从客户端到服务器（ClientToServer）和从服务器到客户端（ServerToClient）。

TCPFlowDirection类型是一个布尔值，它有两个可能的值：

TCPDirClientToServer：表示从客户端到服务器的方向。这个值被分配给第一个接收到的数据包的半连接，因此，如果数据包不是按顺序接收的，这个值可能是错误的。
TCPDirServerToClient：表示从服务器到客户端的方向。
在处理TCP数据包时，可以使用TCPFlowDirection类型来确定数据包的方向。这对于数据包的排序和重组非常有用。需要注意的是，如果数据包不是按顺序接收的，决定如何解释方向（即是否需要交换方向）是由调用者（例如在Accept()函数中）决定的。
*/

// Value are not really useful
const (
	TCPDirClientToServer TCPFlowDirection = false
	TCPDirServerToClient TCPFlowDirection = true
)

func (dir TCPFlowDirection) String() string {
	switch dir {
	case TCPDirClientToServer:
		return "client->server"
	case TCPDirServerToClient:
		return "server->client"
	}
	return ""
}

// Reverse returns the reversed direction
func (dir TCPFlowDirection) Reverse() TCPFlowDirection {
	return !dir
}

/* page: implements a byteContainer */

// page is used to store TCP data we're not ready for yet (out-of-order
// packets).  Unused pages are stored in and returned from a pageCache, which
// avoids memory allocation.  Used pages are stored in a doubly-linked list in
// a connection.
// // page被用来存储我们还未准备好的TCP数据（乱序数据包）。未使用的page被存储在pageCache中，这避免了内存分配。已使用的page被存储在连接中的一个双向链表里
type page struct {
	bytes      []byte
	seq        Sequence
	prev, next *page
	buf        [pageBytes]byte
	ac         AssemblerContext // only set for the first page of a packet
	seen       time.Time
	start, end bool
}

/*
page结构体的作用：

page结构体在gopacket的reassembly子目录中，主要用于存储接收到的TCP数据包。当数据包乱序到达时，会先存储在page中，等待其它数据包到达后进行重组。

page结构体包含以下字段：

bytes：存储TCP数据包的负载数据。
seq：TCP数据包的序列号。
prev，next：在双向链表中，指向前一个和后一个page。
buf：一个固定大小的缓冲区，用于存储TCP数据包的负载数据。
ac：AssemblerContext对象，只在数据包的第一个page中设置。
seen：记录这个page被看到（接收到）的时间。
start，end：标记这个page是否是一个TCP数据流的开始或结束。
在处理TCP数据包时，page结构体提供了一种方便的方式来存储和管理数据包。通过prev和next字段，可以将多个page组织成一个双向链表，方便进行数据包的排序和重组。
*/

func (p *page) getBytes() []byte {
	return p.bytes
}
func (p *page) captureInfo() gopacket.CaptureInfo {
	return p.ac.GetCaptureInfo()
}
func (p *page) assemblerContext() AssemblerContext {
	return p.ac
}
func (p *page) convertToPages(pc *pageCache, skip int, ac AssemblerContext) (*page, *page, int) {
	if skip != 0 {
		p.bytes = p.bytes[skip:]
		p.seq = p.seq.Add(skip)
	}
	p.prev, p.next = nil, nil
	return p, p, 1
}
func (p *page) length() int {
	return len(p.bytes)
}
func (p *page) release(pc *pageCache) int {
	pc.replace(p)
	return 1
}
func (p *page) isStart() bool {
	return p.start
}
func (p *page) isEnd() bool {
	return p.end
}
func (p *page) getSeq() Sequence {
	return p.seq
}
func (p *page) isPacket() bool {
	return p.ac != nil
}
func (p *page) String() string {
	return fmt.Sprintf("page@%p{seq: %v, bytes:%d, -> nextSeq:%v} (prev:%p, next:%p)", p, p.seq, len(p.bytes), p.seq+Sequence(len(p.bytes)), p.prev, p.next)
}

/* livePacket: implements a byteContainer */
type livePacket struct {
	bytes []byte
	start bool
	end   bool
	ac    AssemblerContext
	seq   Sequence
}

/*
livePacket结构体在gopacket的reassembly子目录中，实现了byteContainer接口。它表示一个实时接收到的TCP数据包。

livePacket结构体包含以下字段：

bytes：一个字节切片，存储TCP数据包的负载数据。
start：一个布尔值，表示这个数据包是否是一个TCP流的开始。
end：一个布尔值，表示这个数据包是否是一个TCP流的结束。
ac：一个AssemblerContext类型的值，与此livePacket关联。
seq：一个Sequence类型的值，表示数据包的序列号。
livePacket结构体实现了byteContainer接口，可以让Assembler处理实时接收到的TCP数据包，而无需关心具体的实现细节。通过将实时接收到的数据包存储在livePacket结构体中，可以方便地对数据包进行排序和重组。
*/

func (lp *livePacket) getBytes() []byte {
	return lp.bytes
}
func (lp *livePacket) captureInfo() gopacket.CaptureInfo {
	return lp.ac.GetCaptureInfo()
}
func (lp *livePacket) assemblerContext() AssemblerContext {
	return lp.ac
}
func (lp *livePacket) length() int {
	return len(lp.bytes)
}
func (lp *livePacket) isStart() bool {
	return lp.start
}
func (lp *livePacket) isEnd() bool {
	return lp.end
}
func (lp *livePacket) getSeq() Sequence {
	return lp.seq
}
func (lp *livePacket) isPacket() bool {
	return true
}

// Creates a page (or set of pages) from a TCP packet: returns the first and last
// page in its doubly-linked list of new pages.
// 从TCP数据包创建一个（或一组）页面：返回其新页面双向链表中的第一个和最后一个页面。
func (lp *livePacket) convertToPages(pc *pageCache, skip int, ac AssemblerContext) (*page, *page, int) {
	ts := lp.captureInfo().Timestamp
	first := pc.next(ts)
	current := first
	current.prev = nil
	first.ac = ac
	numPages := 1
	seq, bytes := lp.seq.Add(skip), lp.bytes[skip:]
	for {
		length := min(len(bytes), pageBytes)
		current.bytes = current.buf[:length]
		copy(current.bytes, bytes)
		current.seq = seq
		bytes = bytes[length:]
		if len(bytes) == 0 {
			current.end = lp.isEnd()
			current.next = nil
			break
		}
		seq = seq.Add(length)
		current.next = pc.next(ts)
		current.next.prev = current
		current = current.next
		current.ac = nil
		numPages++
	}
	return first, current, numPages
}
func (lp *livePacket) estimateNumberOfPages() int {
	return (len(lp.bytes) + pageBytes + 1) / pageBytes
}

func (lp *livePacket) release(*pageCache) int {
	return 0
}

// Stream is implemented by the caller to handle incoming reassembled
// TCP data.  Callers create a StreamFactory, then StreamPool uses
// it to create a new Stream for every TCP stream.
//
// assembly will, in order:
//  1. Create the stream via StreamFactory.New
//  2. Call ReassembledSG 0 or more times, passing in reassembled TCP data in order
//  3. Call ReassemblyComplete one time, after which the stream is dereferenced by assembly.
type Stream interface {
	// Tell whether the TCP packet should be accepted, start could be modified to force a start even if no SYN have been seen
	Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir TCPFlowDirection, nextSeq Sequence, start *bool, ac AssemblerContext) bool

	// ReassembledSG is called zero or more times.
	// ScatterGather is reused after each Reassembled call,
	// so it's important to copy anything you need out of it,
	// especially bytes (or use KeepFrom())
	ReassembledSG(sg ScatterGather, ac AssemblerContext)

	// ReassemblyComplete is called when assembly decides there is
	// no more data for this Stream, either because a FIN or RST packet
	// was seen, or because the stream has timed out without any new
	// packet data (due to a call to FlushCloseOlderThan).
	// It should return true if the connection should be removed from the pool
	// It can return false if it want to see subsequent packets with Accept(), e.g. to
	// see FIN-ACK, for deeper state-machine analysis.
	ReassemblyComplete(ac AssemblerContext) bool
}

/*
Stream接口在gopacket的reassembly子目录中，由调用者实现，用于处理传入的已重组TCP数据。调用者创建一个StreamFactory，然后StreamPool使用它为每个TCP流创建一个新的Stream。

assembly将按以下顺序执行操作：

通过StreamFactory.New创建流。
调用ReassembledSG 0次或多次，按顺序传入已重组的TCP数据。
调用ReassemblyComplete一次，在此之后，assembly将取消对该流的引用。
Stream接口定义了以下方法：

Accept：确定是否应接受TCP数据包，可以修改start以强制在未看到SYN的情况下开始。此方法接受TCP层信息、捕获信息、流向、下一个序列号、开始标志和装配上下文作为参数。
ReassembledSG：此方法会被调用零次或多次。ScatterGather在每次Reassembled调用后被重用，因此从中复制出任何需要的数据（尤其是字节）或使用KeepFrom()方法是很重要的。
ReassemblyComplete：当assembly决定没有更多数据传输给此Stream时调用，可能是因为看到了FIN或RST数据包，或者因为在没有新的数据包数据的情况下流超时（由于调用FlushCloseOlderThan）。如果连接应从池中删除，则应返回true。如果希望通过Accept()查看后续数据包（例如查看FIN-ACK以进行更深入的状态机分析），则可以返回false。
Stream接口提供了一种方便的方式来处理TCP数据流，并允许调用者自定义如何处理重组后的数据。通过实现Stream接口，可以根据需要对TCP数据进行排序、重组和处理。
*/

// StreamFactory is used by assembly to create a new stream for each
// new TCP session.
type StreamFactory interface {
	// New should return a new stream for the given TCP key.
	New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac AssemblerContext) Stream
}

/*
StreamFactory接口在gopacket的reassembly子目录中，用于为每个新的TCP会话创建新的流。assembly（装配器）使用StreamFactory来实例化新的Stream对象以处理TCP数据流。

StreamFactory接口定义了以下方法：

New：此方法应为给定的TCP键返回一个新的流。它接受网络层流、传输层流、TCP层信息和装配上下文作为参数。
通过实现StreamFactory接口，可以让调用者自定义如何为每个新的TCP会话创建新的流。这使得在处理TCP数据包时，可以根据需要创建和管理不同类型的流。
*/

type key [2]gopacket.Flow

/*
key类型是一个长度为2的gopacket.Flow数组，它在gopacket的reassembly子目录中用作表示一个TCP连接的唯一标识。key通常由连接的源地址、目的地址、源端口和目的端口组成。

在key数组中：

key[0]：表示网络层（如IP）的流，包含源地址和目的地址。
key[1]：表示传输层（如TCP）的流，包含源端口和目的端口。
key类型通过将网络层和传输层的流组合在一起，可以唯一地标识一个TCP连接。这对于在StreamPool和Assembler中查找和管理TCP连接非常有用。
*/

func (k *key) String() string {
	return fmt.Sprintf("%s:%s", k[0], k[1])
}

func (k *key) Reverse() key {
	return key{
		k[0].Reverse(),
		k[1].Reverse(),
	}
}

const assemblerReturnValueInitialSize = 16

/* one-way connection, i.e. halfconnection */
type halfconnection struct {
	dir               TCPFlowDirection
	pages             int      // Number of pages used (both in first/last and saved)
	saved             *page    // Doubly-linked list of in-order pages (seq < nextSeq) already given to Stream who told us to keep
	first, last       *page    // Doubly-linked list of out-of-order pages (seq > nextSeq)
	nextSeq           Sequence // sequence number of in-order received bytes
	ackSeq            Sequence
	created, lastSeen time.Time
	stream            Stream
	closed            bool
	// for stats
	queuedBytes    int
	queuedPackets  int
	overlapBytes   int
	overlapPackets int
}

/*
halfconnection结构体在gopacket的reassembly子目录中，表示一个TCP连接的一半，即单向连接。它用于存储和管理一个方向上的TCP数据流的状态。

halfconnection结构体包含以下字段：

dir：一个TCPFlowDirection类型的值，表示数据流的方向（从客户端到服务器或从服务器到客户端）。

pages：表示使用的page数量（包括first/last和saved中的）。

saved：一个指向page的指针，表示已经按序给到Stream但被告知保留的page的双向链表。

first, last：两个指向page的指针，表示乱序page的双向链表。

nextSeq：一个Sequence类型的值，表示按序接收到的字节的序列号。

ackSeq：一个Sequence类型的值，表示已确认的序列号。

created, lastSeen：两个time.Time类型的值，分别表示halfconnection的创建时间和最后一次接收到数据的时间。

stream：一个Stream接口，表示与此halfconnection关联的TCP流。

closed：一个布尔值，表示此halfconnection是否已关闭。

queuedBytes，queuedPackets：分别表示已排队的字节数和数据包数。

overlapBytes，overlapPackets：分别表示重叠的字节数和数据包数。

halfconnection结构体提供了一种方便的方式来存储和管理一个方向上的TCP数据流的状态。通过使用saved、first和last字段，可以将多个page组织成一个双向链表，方便进行数据包的排序和重组。
*/

func (half *halfconnection) String() string {
	closed := ""
	if half.closed {
		closed = "closed "
	}
	return fmt.Sprintf("%screated:%v, last:%v", closed, half.created, half.lastSeen)
}

// Dump returns a string (crypticly) describing the halfconnction
func (half *halfconnection) Dump() string {
	s := fmt.Sprintf("pages: %d\n"+
		"nextSeq: %d\n"+
		"ackSeq: %d\n"+
		"Seen :  %s\n"+
		"dir:    %s\n", half.pages, half.nextSeq, half.ackSeq, half.lastSeen, half.dir)
	nb := 0
	for p := half.first; p != nil; p = p.next {
		s += fmt.Sprintf("	Page[%d] %s len: %d\n", nb, p, len(p.bytes))
		nb++
	}
	return s
}

/* Bi-directionnal connection */

type connection struct {
	key      key // client->server
	c2s, s2c halfconnection
	mu       sync.Mutex
}

/*
connection结构体在gopacket的reassembly子目录中，表示一个双向的TCP连接。它包含了从客户端到服务器（client->server）和从服务器到客户端（server->client）两个方向的数据流。connection结构体用于存储和管理TCP连接的状态，以便对接收到的数据包进行排序和重组。

connection结构体包含以下字段：

key：一个key类型的值，表示TCP连接的唯一标识。key通常由连接的源地址、目的地址、源端口和目的端口组成。
c2s：一个halfconnection结构体，表示从客户端到服务器（client->server）方向的数据流。它包含一个名为pages的列表，用于存储接收到的数据包。
s2c：一个halfconnection结构体，表示从服务器到客户端（server->client）方向的数据流。它包含一个名为pages的列表，用于存储接收到的数据包。
mu：一个互斥锁，用于保护connection结构体的并发访问。
connection结构体提供了一种方便的方式来存储和管理TCP连接的状态。通过使用互斥锁，connection结构体可以在保证线程安全的同时，对接收到的数据包进行排序和重组。
*/

func (c *connection) reset(k key, s Stream, ts time.Time) {
	c.key = k
	base := halfconnection{
		nextSeq:  invalidSequence,
		ackSeq:   invalidSequence,
		created:  ts,
		lastSeen: ts,
		stream:   s,
	}
	c.c2s, c.s2c = base, base
	c.c2s.dir, c.s2c.dir = TCPDirClientToServer, TCPDirServerToClient
}

func (c *connection) lastSeen() time.Time {
	if c.c2s.lastSeen.Before(c.s2c.lastSeen) {
		return c.s2c.lastSeen
	}

	return c.c2s.lastSeen
}

func (c *connection) String() string {
	return fmt.Sprintf("c2s: %s, s2c: %s", &c.c2s, &c.s2c)
}

/*
 * Assembler
 */

// DefaultAssemblerOptions provides default options for an assembler.
// These options are used by default when calling NewAssembler, so if
// modified before a NewAssembler call they'll affect the resulting Assembler.
//
// Note that the default options can result in ever-increasing memory usage
// unless one of the Flush* methods is called on a regular basis.
var DefaultAssemblerOptions = AssemblerOptions{
	MaxBufferedPagesPerConnection: 0, // unlimited
	MaxBufferedPagesTotal:         0, // unlimited
}

// AssemblerOptions controls the behavior of each assembler.  Modify the
// options of each assembler you create to change their behavior.
type AssemblerOptions struct {
	// MaxBufferedPagesTotal is an upper limit on the total number of pages to
	// buffer while waiting for out-of-order packets.  Once this limit is
	// reached, the assembler will degrade to flushing every connection it
	// gets a packet for.  If <= 0, this is ignored.
	MaxBufferedPagesTotal int
	// MaxBufferedPagesPerConnection is an upper limit on the number of pages
	// buffered for a single connection.  Should this limit be reached for a
	// particular connection, the smallest sequence number will be flushed, along
	// with any contiguous data.  If <= 0, this is ignored.
	MaxBufferedPagesPerConnection int
}

/*
AssemblerOptions结构体在gopacket的reassembly子目录中，用于控制每个装配器的行为。通过修改创建的每个装配器的选项，可以改变它们的行为。

AssemblerOptions结构体包含以下字段：

MaxBufferedPagesTotal：在等待乱序数据包时，缓冲的总页面数的上限。一旦达到此限制，装配器将降级为刷新收到数据包的每个连接。如果小于等于0，则忽略此限制。
MaxBufferedPagesPerConnection：单个连接缓冲的页面数的上限。如果某个特定连接达到此限制，则将刷新具有最小序列号的页面以及任何连续的数据。如果小于等于0，则忽略此限制。
通过设置AssemblerOptions结构体的字段值，可以根据需要调整装配器在处理TCP数据包时的缓冲页面限制。这有助于在保证性能的同时，避免内存占用过高。
*/

// Assembler handles reassembling TCP streams.  It is not safe for
// concurrency... after passing a packet in via the Assemble call, the caller
// must wait for that call to return before calling Assemble again.  Callers can
// get around this by creating multiple assemblers that share a StreamPool.  In
// that case, each individual stream will still be handled serially (each stream
// has an individual mutex associated with it), however multiple assemblers can
// assemble different connections concurrently.
//
// The Assembler provides (hopefully) fast TCP stream re-assembly for sniffing
// applications written in Go.  The Assembler uses the following methods to be
// as fast as possible, to keep packet processing speedy:
//
// # Avoids Lock Contention
//
// Assemblers locks connections, but each connection has an individual lock, and
// rarely will two Assemblers be looking at the same connection.  Assemblers
// lock the StreamPool when looking up connections, but they use Reader
// locks initially, and only force a write lock if they need to create a new
// connection or close one down.  These happen much less frequently than
// individual packet handling.
//
// Each assembler runs in its own goroutine, and the only state shared between
// goroutines is through the StreamPool.  Thus all internal Assembler state
// can be handled without any locking.
//
// NOTE:  If you can guarantee that packets going to a set of Assemblers will
// contain information on different connections per Assembler (for example,
// they're already hashed by PF_RING hashing or some other hashing mechanism),
// then we recommend you use a seperate StreamPool per Assembler, thus
// avoiding all lock contention.  Only when different Assemblers could receive
// packets for the same Stream should a StreamPool be shared between them.
//
// # Avoids Memory Copying
//
// In the common case, handling of a single TCP packet should result in zero
// memory allocations.  The Assembler will look up the connection, figure out
// that the packet has arrived in order, and immediately pass that packet on to
// the appropriate connection's handling code.  Only if a packet arrives out of
// order is its contents copied and stored in memory for later.
//
// # Avoids Memory Allocation
//
// Assemblers try very hard to not use memory allocation unless absolutely
// necessary.  Packet data for sequential packets is passed directly to streams
// with no copying or allocation.  Packet data for out-of-order packets is
// copied into reusable pages, and new pages are only allocated rarely when the
// page cache runs out.  Page caches are Assembler-specific, thus not used
// concurrently and requiring no locking.
//
// Internal representations for connection objects are also reused over time.
// Because of this, the most common memory allocation done by the Assembler is
// generally what's done by the caller in StreamFactory.New.  If no allocation
// is done there, then very little allocation is done ever, mostly to handle
// large increases in bandwidth or numbers of connections.
//
// TODO:  The page caches used by an Assembler will grow to the size necessary
// to handle a workload, and currently will never shrink.  This means that
// traffic spikes can result in large memory usage which isn't garbage
// collected when typical traffic levels return.
type Assembler struct {
	AssemblerOptions
	ret      []byteContainer
	pc       *pageCache
	connPool *StreamPool
	cacheLP  livePacket
	cacheSG  reassemblyObject
	start    bool
}

/*
Assembler结构体用于处理TCP流的重组。它不是线程安全的。在通过Assemble方法传入一个数据包后，调用者必须等待该调用返回，然后再次调用Assemble。调用者可以通过创建多个共享StreamPool的装配器来解决这个问题。在这种情况下，每个单独的流仍将被顺序处理（每个流都有一个与之关联的单独互斥锁），但是多个装配器可以同时组装不同的连接。

Assembler为用Go编写的嗅探应用程序提供了（希望）快速的TCP流重组。为了尽可能快地处理数据包，Assembler使用以下方法:

避免锁竞争

装配器对连接进行加锁，但每个连接都有一个单独的锁，很少有两个装配器查看相同的连接。装配器在查找连接时锁定StreamPool，但它们最初使用读取锁，只有在需要创建新连接或关闭连接时才强制写锁。这些操作发生的频率远远低于单个数据包的处理。

每个装配器在其自己的goroutine中运行，而通过StreamPool在goroutine之间共享的唯一状态。因此，所有内部装配器状态都可以在没有任何锁定的情况下处理。

注意：如果您可以保证发送给一组装配器的数据包将包含每个装配器的不同连接信息（例如，它们已经通过PF_RING哈希或其他哈希机制进行了哈希），那么我们建议您为每个装配器使用一个单独的StreamPool，从而避免所有锁竞争。只有当不同的装配器可能接收到相同流的数据包时，才应在它们之间共享一个StreamPool。

避免内存复制

在常见情况下，处理单个TCP数据包应该导致零内存分配。装配器将查找连接，确定数据包已按顺序到达，并立即将该数据包传递给适当连接的处理代码。只有当数据包乱序到达时，才会将其内容复制并存储在内存中以供稍后使用。

避免内存分配

装配器非常努力地避免使用内存分配，除非绝对必要。顺序数据包的数据直接传递给流，无需复制或分配。乱序数据包的数据被复制到可重用的页面中，只有在页面缓存用完时才分配新页面。页面缓存是装配器特有的，因此不会被并发使用，也不需要锁定。

随着时间的推移，连接对象的内部表示也会被重用。因此，装配器完成的最常见的内存分配通常是在StreamFactory.New中完成的。如果在那里没有分配，那么几乎没有什么分配是永久性的，主要是为了处理带宽或连接数量的大幅增加。

TODO：装配器使用的页面缓存将增长到处理工作负载所需的大小，目前永远不会收缩。这意味着流量峰值可能导致大量内存使用，而在典型流量水平恢复时不会被垃圾收集。

Assembler结构体包含以下字段：

AssemblerOptions：控制装配器行为的选项。
ret：一个byteContainer类型的切片，用于存储返回的字节容器。

pc：一个指向pageCache的指针，用于管理页面缓存。
connPool：一个指向StreamPool的指针，用于管理TCP流。
cacheLP：一个livePacket类型的值，用于缓存实时数据包。
cacheSG：一个reassemblyObject类型的值，用于缓存重组对象。
start：一个布尔值，表示是否开始处理数据包。
Assembler结构体提供了一种高效处理TCP数据流的方法，旨在最大程度地减少锁竞争、内存复制和内存分配。通过使用Assembler，可以更快地对TCP数据包进行排序、重组和处理，从而提高嗅探应用程序的性能。

*/

// NewAssembler creates a new assembler.  Pass in the StreamPool
// to use, may be shared across assemblers.
//
// This sets some sane defaults for the assembler options,
// see DefaultAssemblerOptions for details.
func NewAssembler(pool *StreamPool) *Assembler {
	pool.mu.Lock()
	pool.users++
	pool.mu.Unlock()
	return &Assembler{
		ret:              make([]byteContainer, 0, assemblerReturnValueInitialSize),
		pc:               newPageCache(),
		connPool:         pool,
		AssemblerOptions: DefaultAssemblerOptions,
	}
}

// Dump returns a short string describing the page usage of the Assembler
func (a *Assembler) Dump() string {
	s := ""
	s += fmt.Sprintf("pageCache: used: %d:", a.pc.used)
	return s
}

// AssemblerContext provides method to get metadata
type AssemblerContext interface {
	GetCaptureInfo() gopacket.CaptureInfo
}

// Implements AssemblerContext for Assemble()
type assemblerSimpleContext gopacket.CaptureInfo

/*
assemblerSimpleContext 类型在gopacket的reassembly子目录中，它是一个类型别名，将 gopacket.CaptureInfo 类型重定义为 assemblerSimpleContext。gopacket.CaptureInfo 类型包含了数据包捕获时的一些元数据信息，例如捕获时间戳、数据包长度等。

将 gopacket.CaptureInfo 重定义为 assemblerSimpleContext 可以让装配器（assembler）在处理TCP数据包时使用简单的上下文（context），而无需关心具体的实现细节。这样可以简化代码并提高可读性。
*/

func (asc *assemblerSimpleContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo(*asc)
}

// Assemble calls AssembleWithContext with the current timestamp, useful for
// packets being read directly off the wire.
func (a *Assembler) Assemble(netFlow gopacket.Flow, t *layers.TCP) {
	ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Now()})
	a.AssembleWithContext(netFlow, t, &ctx)
}

type assemblerAction struct {
	nextSeq Sequence
	queue   bool
}

// AssembleWithContext reassembles the given TCP packet into its appropriate
// stream.
//
// The timestamp passed in must be the timestamp the packet was seen.
// For packets read off the wire, time.Now() should be fine.  For packets read
// from PCAP files, CaptureInfo.Timestamp should be passed in.  This timestamp
// will affect which streams are flushed by a call to FlushCloseOlderThan.
//
// Each AssembleWithContext call results in, in order:
//
//	zero or one call to StreamFactory.New, creating a stream
//	zero or one call to ReassembledSG on a single stream
//	zero or one call to ReassemblyComplete on the same stream
/*
AssembleWithContext方法用于将给定的TCP数据包重新组装到其相应的流中。

传入的时间戳必须是数据包被观察到的时间。对于从网络中读取的数据包，time.Now()应该足够了。对于从PCAP文件中读取的数据包，应传入CaptureInfo.Timestamp。此时间戳将影响FlushCloseOlderThan调用时刷新哪些流。

每个AssembleWithContext调用按顺序执行以下操作：

零次或一次调用StreamFactory.New，创建一个流
零次或一次调用单个流上的ReassembledSG
零次或一次调用同一流上的ReassemblyComplete
该方法接受网络层流、TCP层信息和装配上下文作为参数。它首先根据网络层流和传输层流查找或创建连接，然后锁定连接并处理数据包。根据数据包的顺序和内容，该方法会将数据包发送给相应的流，或者将其存储在连接中以备稍后使用。最后，该方法会更新连接的状态并解锁连接。

AssembleWithContext方法提供了一种处理TCP数据包并将其重新组装到流中的方法。通过使用此方法，可以根据需要对TCP数据包进行排序、重组和处理。
*/
func (a *Assembler) AssembleWithContext(netFlow gopacket.Flow, t *layers.TCP, ac AssemblerContext) {
	var conn *connection
	var half *halfconnection
	var rev *halfconnection

	a.ret = a.ret[:0]
	key := key{netFlow, t.TransportFlow()}
	ci := ac.GetCaptureInfo()
	timestamp := ci.Timestamp

	conn, half, rev = a.connPool.getConnection(key, false, timestamp, t, ac)
	if conn == nil {
		if *debugLog {
			log.Printf("%v got empty packet on otherwise empty connection", key)
		}
		return
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if half.lastSeen.Before(timestamp) {
		half.lastSeen = timestamp
	}
	a.start = half.nextSeq == invalidSequence && t.SYN
	if *debugLog {
		if half.nextSeq < rev.ackSeq {
			log.Printf("Delay detected on %v, data is acked but not assembled yet (acked %v, nextSeq %v)", key, rev.ackSeq, half.nextSeq)
		}
	}

	if !half.stream.Accept(t, ci, half.dir, half.nextSeq, &a.start, ac) {
		if *debugLog {
			log.Printf("Ignoring packet")
		}
		return
	}
	if half.closed {
		// this way is closed
		if *debugLog {
			log.Printf("%v got packet on closed half", key)
		}
		return
	}

	seq, ack, bytes := Sequence(t.Seq), Sequence(t.Ack), t.Payload
	if t.ACK {
		half.ackSeq = ack
	}
	// TODO: push when Ack is seen ??
	action := assemblerAction{
		nextSeq: Sequence(invalidSequence),
		queue:   true,
	}
	a.dump("AssembleWithContext()", half)
	if half.nextSeq == invalidSequence {
		if t.SYN {
			if *debugLog {
				log.Printf("%v saw first SYN packet, returning immediately, seq=%v", key, seq)
			}
			seq = seq.Add(1)
			half.nextSeq = seq
			action.queue = false
		} else if a.start {
			if *debugLog {
				log.Printf("%v start forced", key)
			}
			half.nextSeq = seq
			action.queue = false
		} else {
			if *debugLog {
				log.Printf("%v waiting for start, storing into connection", key)
			}
		}
	} else {
		diff := half.nextSeq.Difference(seq)
		if diff > 0 {
			if *debugLog {
				log.Printf("%v gap in sequence numbers (%v, %v) diff %v, storing into connection", key, half.nextSeq, seq, diff)
			}
		} else {
			if *debugLog {
				log.Printf("%v found contiguous data (%v, %v), returning immediately: len:%d", key, seq, half.nextSeq, len(bytes))
			}
			action.queue = false
		}
	}

	action = a.handleBytes(bytes, seq, half, t.SYN, t.RST || t.FIN, action, ac)
	if len(a.ret) > 0 {
		action.nextSeq = a.sendToConnection(conn, half, ac)
	}
	if action.nextSeq != invalidSequence {
		half.nextSeq = action.nextSeq
		if t.FIN {
			half.nextSeq = half.nextSeq.Add(1)
		}
	}
	if *debugLog {
		log.Printf("%v nextSeq:%d", key, half.nextSeq)
	}
}

// Overlap strategies:
//  - new packet overlaps with sent packets:
//	1) discard new overlapping part
//	2) overwrite old overlapped (TODO)
//  - new packet overlaps existing queued packets:
//	a) consider "age" by timestamp (TODO)
//	b) consider "age" by being present
//	Then
//      1) discard new overlapping part
//      2) overwrite queued part
/*
checkOverlap 方法用于处理TCP数据包在重组过程中可能出现的重叠问题。当新数据包与已发送的数据包或现有队列中的数据包重叠时，此方法会根据不同的策略来处理这种情况。

方法接收三个参数：half 是一个指向 halfconnection 的指针，表示当前处理的半连接；queue 是一个布尔值，表示是否需要将数据包加入队列；ac 是装配上下文。

在处理重叠时，方法首先遍历当前连接中的所有页面，然后根据页面与新数据包之间的关系，确定如何处理重叠。以下是可能的情况：

新数据包与已发送的数据包重叠：丢弃新数据包的重叠部分或覆盖旧数据包的重叠部分（TODO）。
新数据包与现有队列中的数据包重叠：考虑时间戳（TODO）或存在时间，然后丢弃新数据包的重叠部分或覆盖队列中的部分。
在处理完重叠之后，方法会将处理后的数据包分割成页面，并将其插入队列中。

checkOverlap 方法通过处理数据包重叠，确保TCP流重组的正确性和完整性。这对于在乱序或丢包的情况下正确处理TCP数据包至关重要。
*/
func (a *Assembler) checkOverlap(half *halfconnection, queue bool, ac AssemblerContext) {
	var next *page
	cur := half.last
	bytes := a.cacheLP.bytes
	start := a.cacheLP.seq
	end := start.Add(len(bytes))

	a.dump("before checkOverlap", half)

	//          [s6           :           e6]
	//   [s1:e1][s2:e2] -- [s3:e3] -- [s4:e4][s5:e5]
	//             [s <--ds-- : --de--> e]
	for cur != nil {

		if *debugLog {
			log.Printf("cur = %p (%s)\n", cur, cur)
		}

		// end < cur.start: continue (5)
		if end.Difference(cur.seq) > 0 {
			if *debugLog {
				log.Printf("case 5\n")
			}
			next = cur
			cur = cur.prev
			continue
		}

		curEnd := cur.seq.Add(len(cur.bytes))
		// start > cur.end: stop (1)
		if start.Difference(curEnd) <= 0 {
			if *debugLog {
				log.Printf("case 1\n")
			}
			break
		}

		diffStart := start.Difference(cur.seq)
		diffEnd := end.Difference(curEnd)

		// end > cur.end && start < cur.start: drop (3)
		if diffEnd <= 0 && diffStart >= 0 {
			if *debugLog {
				log.Printf("case 3\n")
			}
			if cur.isPacket() {
				half.overlapPackets++
			}
			half.overlapBytes += len(cur.bytes)
			// update links
			if cur.prev != nil {
				cur.prev.next = cur.next
			} else {
				half.first = cur.next
			}
			if cur.next != nil {
				cur.next.prev = cur.prev
			} else {
				half.last = cur.prev
			}
			tmp := cur.prev
			half.pages -= cur.release(a.pc)
			cur = tmp
			continue
		}

		// end > cur.end && start < cur.end: drop cur's end (2)
		if diffEnd < 0 && start.Difference(curEnd) > 0 {
			if *debugLog {
				log.Printf("case 2\n")
			}
			cur.bytes = cur.bytes[:-start.Difference(cur.seq)]
			break
		} else

		// start < cur.start && end > cur.start: drop cur's start (4)
		if diffStart > 0 && end.Difference(cur.seq) < 0 {
			if *debugLog {
				log.Printf("case 4\n")
			}
			cur.bytes = cur.bytes[-end.Difference(cur.seq):]
			cur.seq = cur.seq.Add(-end.Difference(cur.seq))
			next = cur
		} else

		// end < cur.end && start > cur.start: replace bytes inside cur (6)
		if diffEnd >= 0 && diffStart <= 0 {
			if *debugLog {
				log.Printf("case 6\n")
			}
			copy(cur.bytes[-diffStart:-diffStart+len(bytes)], bytes)
			bytes = bytes[:0]
		} else {
			if *debugLog {
				log.Printf("no overlap\n")
			}
			next = cur
		}
		cur = cur.prev
	}

	// Split bytes into pages, and insert in queue
	a.cacheLP.bytes = bytes
	a.cacheLP.seq = start
	if len(bytes) > 0 && queue {
		p, p2, numPages := a.cacheLP.convertToPages(a.pc, 0, ac)
		half.queuedPackets++
		half.queuedBytes += len(bytes)
		half.pages += numPages
		if cur != nil {
			if *debugLog {
				log.Printf("adding %s after %s", p, cur)
			}
			cur.next = p
			p.prev = cur
		} else {
			if *debugLog {
				log.Printf("adding %s as first", p)
			}
			half.first = p
		}
		if next != nil {
			if *debugLog {
				log.Printf("setting %s as next of new %s", next, p2)
			}
			p2.next = next
			next.prev = p2
		} else {
			if *debugLog {
				log.Printf("setting %s as last", p2)
			}
			half.last = p2
		}
	}
	a.dump("After checkOverlap", half)
}

// Warning: this is a low-level dumper, i.e. a.ret or a.cacheSG might
// be strange, but it could be ok.
func (a *Assembler) dump(text string, half *halfconnection) {
	if !*debugLog {
		return
	}
	log.Printf("%s: dump\n", text)
	if half != nil {
		p := half.first
		if p == nil {
			log.Printf(" * half.first = %p, no chunks queued\n", p)
		} else {
			s := 0
			nb := 0
			log.Printf(" * half.first = %p, queued chunks:", p)
			for p != nil {
				log.Printf("\t%s bytes:%s\n", p, hex.EncodeToString(p.bytes))
				s += len(p.bytes)
				nb++
				p = p.next
			}
			log.Printf("\t%d chunks for %d bytes", nb, s)
		}
		log.Printf(" * half.last = %p\n", half.last)
		log.Printf(" * half.saved = %p\n", half.saved)
		p = half.saved
		for p != nil {
			log.Printf("\tseq:%d %s bytes:%s\n", p.getSeq(), p, hex.EncodeToString(p.bytes))
			p = p.next
		}
	}
	log.Printf(" * a.ret\n")
	for i, r := range a.ret {
		log.Printf("\t%d: %v b:%s\n", i, r.captureInfo(), hex.EncodeToString(r.getBytes()))
	}
	log.Printf(" * a.cacheSG.all\n")
	for i, r := range a.cacheSG.all {
		log.Printf("\t%d: %v b:%s\n", i, r.captureInfo(), hex.EncodeToString(r.getBytes()))
	}
}

func (a *Assembler) overlapExisting(half *halfconnection, start, end Sequence, bytes []byte) ([]byte, Sequence) {
	if half.nextSeq == invalidSequence {
		// no start yet
		return bytes, start
	}
	diff := start.Difference(half.nextSeq)
	if diff == 0 {
		return bytes, start
	}
	s := 0
	e := len(bytes)
	// TODO: depending on strategy, we might want to shrink half.saved if possible
	if e != 0 {
		if *debugLog {
			log.Printf("Overlap detected: ignoring current packet's first %d bytes", diff)
		}
		half.overlapPackets++
		half.overlapBytes += diff
	}
	s += diff
	if s >= e {
		// Completely included in sent
		s = e
	}
	bytes = bytes[s:]
	return bytes, half.nextSeq
}

// Prepare send or queue
func (a *Assembler) handleBytes(bytes []byte, seq Sequence, half *halfconnection, start bool, end bool, action assemblerAction, ac AssemblerContext) assemblerAction {
	a.cacheLP.bytes = bytes
	a.cacheLP.start = start
	a.cacheLP.end = end
	a.cacheLP.seq = seq
	a.cacheLP.ac = ac

	if action.queue {
		a.checkOverlap(half, true, ac)
		if (a.MaxBufferedPagesPerConnection > 0 && half.pages >= a.MaxBufferedPagesPerConnection) ||
			(a.MaxBufferedPagesTotal > 0 && a.pc.used >= a.MaxBufferedPagesTotal) {
			if *debugLog {
				log.Printf("hit max buffer size: %+v, %v, %v", a.AssemblerOptions, half.pages, a.pc.used)
			}
			action.queue = false
			a.addNextFromConn(half)
		}
		a.dump("handleBytes after queue", half)
	} else {
		a.cacheLP.bytes, a.cacheLP.seq = a.overlapExisting(half, seq, seq.Add(len(bytes)), a.cacheLP.bytes)
		a.checkOverlap(half, false, ac)
		if len(a.cacheLP.bytes) != 0 || end || start {
			a.ret = append(a.ret, &a.cacheLP)
		}
		a.dump("handleBytes after no queue", half)
	}
	return action
}

func (a *Assembler) setStatsToSG(half *halfconnection) {
	a.cacheSG.queuedBytes = half.queuedBytes
	half.queuedBytes = 0
	a.cacheSG.queuedPackets = half.queuedPackets
	half.queuedPackets = 0
	a.cacheSG.overlapBytes = half.overlapBytes
	half.overlapBytes = 0
	a.cacheSG.overlapPackets = half.overlapPackets
	half.overlapPackets = 0
}

// Build the ScatterGather object, i.e. prepend saved bytes and
// append continuous bytes.
func (a *Assembler) buildSG(half *halfconnection) (bool, Sequence) {
	// find if there are skipped bytes
	skip := -1
	if half.nextSeq != invalidSequence {
		skip = half.nextSeq.Difference(a.ret[0].getSeq())
	}
	last := a.ret[0].getSeq().Add(a.ret[0].length())
	// Prepend saved bytes
	saved := a.addPending(half, a.ret[0].getSeq())
	// Append continuous bytes
	nextSeq := a.addContiguous(half, last)
	a.cacheSG.all = a.ret
	a.cacheSG.Direction = half.dir
	a.cacheSG.Skip = skip
	a.cacheSG.saved = saved
	a.cacheSG.toKeep = -1
	a.setStatsToSG(half)
	a.dump("after buildSG", half)
	return a.ret[len(a.ret)-1].isEnd(), nextSeq
}

func (a *Assembler) cleanSG(half *halfconnection, ac AssemblerContext) {
	cur := 0
	ndx := 0
	skip := 0

	a.dump("cleanSG(start)", half)

	var r byteContainer
	// Find first page to keep
	if a.cacheSG.toKeep < 0 {
		ndx = len(a.cacheSG.all)
	} else {
		skip = a.cacheSG.toKeep
		found := false
		for ndx, r = range a.cacheSG.all {
			if a.cacheSG.toKeep < cur+r.length() {
				found = true
				break
			}
			cur += r.length()
			if skip >= r.length() {
				skip -= r.length()
			}
		}
		if !found {
			ndx++
		}
	}
	// Release consumed pages
	for _, r := range a.cacheSG.all[:ndx] {
		if r == half.saved {
			if half.saved.next != nil {
				half.saved.next.prev = nil
			}
			half.saved = half.saved.next
		} else if r == half.first {
			if half.first.next != nil {
				half.first.next.prev = nil
			}
			if half.first == half.last {
				half.first, half.last = nil, nil
			} else {
				half.first = half.first.next
			}
		}
		half.pages -= r.release(a.pc)
	}
	a.dump("after consumed release", half)
	// Keep un-consumed pages
	nbKept := 0
	half.saved = nil
	var saved *page
	for _, r := range a.cacheSG.all[ndx:] {
		preConvertLen := r.length()
		first, last, nb := r.convertToPages(a.pc, skip, ac)

		// Update skip count as we move from one container to the next.
		if delta := preConvertLen - r.length(); delta > skip {
			skip = 0
		} else {
			skip -= delta
		}

		if half.saved == nil {
			half.saved = first
		} else {
			saved.next = first
			first.prev = saved
		}
		saved = last
		nbKept += nb
	}
	if *debugLog {
		log.Printf("Remaining %d chunks in SG\n", nbKept)
		log.Printf("%s\n", a.Dump())
		a.dump("after cleanSG()", half)
	}
}

// sendToConnection sends the current values in a.ret to the connection, closing
// the connection if the last thing sent had End set.
func (a *Assembler) sendToConnection(conn *connection, half *halfconnection, ac AssemblerContext) Sequence {
	if *debugLog {
		log.Printf("sendToConnection\n")
	}
	end, nextSeq := a.buildSG(half)
	half.stream.ReassembledSG(&a.cacheSG, ac)
	a.cleanSG(half, ac)
	if end {
		a.closeHalfConnection(conn, half)
	}
	if *debugLog {
		log.Printf("after sendToConnection: nextSeq: %d\n", nextSeq)
	}
	return nextSeq
}

func (a *Assembler) addPending(half *halfconnection, firstSeq Sequence) int {
	if half.saved == nil {
		return 0
	}
	s := 0
	ret := []byteContainer{}
	for p := half.saved; p != nil; p = p.next {
		if *debugLog {
			log.Printf("adding pending @%p %s (%s)\n", p, p, hex.EncodeToString(p.bytes))
		}
		ret = append(ret, p)
		s += len(p.bytes)
	}
	if half.saved.seq.Add(s) != firstSeq {
		// non-continuous saved: drop them
		var next *page
		for p := half.saved; p != nil; p = next {
			next = p.next
			p.release(a.pc)
		}
		half.saved = nil
		ret = []byteContainer{}
		s = 0
	}

	a.ret = append(ret, a.ret...)
	return s
}

// addContiguous adds contiguous byte-sets to a connection.
func (a *Assembler) addContiguous(half *halfconnection, lastSeq Sequence) Sequence {
	page := half.first
	if page == nil {
		if *debugLog {
			log.Printf("addContiguous(%d): no pages\n", lastSeq)
		}
		return lastSeq
	}
	if lastSeq == invalidSequence {
		lastSeq = page.seq
	}
	for page != nil && lastSeq.Difference(page.seq) == 0 {
		if *debugLog {
			log.Printf("addContiguous: lastSeq: %d, first.seq=%d, page.seq=%d\n", half.nextSeq, half.first.seq, page.seq)
		}
		lastSeq = lastSeq.Add(len(page.bytes))
		a.ret = append(a.ret, page)
		half.first = page.next
		if half.first == nil {
			half.last = nil
		}
		if page.next != nil {
			page.next.prev = nil
		}
		page = page.next
	}
	return lastSeq
}

// skipFlush skips the first set of bytes we're waiting for and returns the
// first set of bytes we have.  If we have no bytes saved, it closes the
// connection.
func (a *Assembler) skipFlush(conn *connection, half *halfconnection) {
	if *debugLog {
		log.Printf("skipFlush %v\n", half.nextSeq)
	}
	// Well, it's embarassing it there is still something in half.saved
	// FIXME: change API to give back saved + new/no packets
	if half.first == nil {
		a.closeHalfConnection(conn, half)
		return
	}
	a.ret = a.ret[:0]
	a.addNextFromConn(half)
	nextSeq := a.sendToConnection(conn, half, a.ret[0].assemblerContext())
	if nextSeq != invalidSequence {
		half.nextSeq = nextSeq
	}
}

func (a *Assembler) closeHalfConnection(conn *connection, half *halfconnection) {
	if *debugLog {
		log.Printf("%v closing", conn)
	}
	half.closed = true
	for p := half.first; p != nil; p = p.next {
		// FIXME: it should be already empty
		a.pc.replace(p)
		half.pages--
	}
	if conn.s2c.closed && conn.c2s.closed {
		if half.stream.ReassemblyComplete(nil) { //FIXME: which context to pass ?
			a.connPool.remove(conn)
		}
	}
}

// addNextFromConn pops the first page from a connection off and adds it to the
// return array.
func (a *Assembler) addNextFromConn(conn *halfconnection) {
	if conn.first == nil {
		return
	}
	if *debugLog {
		log.Printf("   adding from conn (%v, %v) %v (%d)\n", conn.first.seq, conn.nextSeq, conn.nextSeq-conn.first.seq, len(conn.first.bytes))
	}
	a.ret = append(a.ret, conn.first)
	conn.first = conn.first.next
	if conn.first != nil {
		conn.first.prev = nil
	} else {
		conn.last = nil
	}
}

// FlushOptions provide options for flushing connections.
type FlushOptions struct {
	T  time.Time // If nonzero, only connections with data older than T are flushed
	TC time.Time // If nonzero, only connections with data older than TC are closed (if no FIN/RST received)
}

// FlushWithOptions finds any streams waiting for packets older than
// the given time T, and pushes through the data they have (IE: tells
// them to stop waiting and skip the data they're waiting for).
//
// It also closes streams older than TC (that can be set to zero, to keep
// long-lived stream alive, but to flush data anyway).
//
// Each Stream maintains a list of zero or more sets of bytes it has received
// out-of-order.  For example, if it has processed up through sequence number
// 10, it might have bytes [15-20), [20-25), [30,50) in its list.  Each set of
// bytes also has the timestamp it was originally viewed.  A flush call will
// look at the smallest subsequent set of bytes, in this case [15-20), and if
// its timestamp is older than the passed-in time, it will push it and all
// contiguous byte-sets out to the Stream's Reassembled function.  In this case,
// it will push [15-20), but also [20-25), since that's contiguous.  It will
// only push [30-50) if its timestamp is also older than the passed-in time,
// otherwise it will wait until the next FlushCloseOlderThan to see if bytes
// [25-30) come in.
//
// Returns the number of connections flushed, and of those, the number closed
// because of the flush.
func (a *Assembler) FlushWithOptions(opt FlushOptions) (flushed, closed int) {
	conns := a.connPool.connections()
	closes := 0
	flushes := 0
	for _, conn := range conns {
		remove := false
		conn.mu.Lock()
		for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
			flushed, closed := a.flushClose(conn, half, opt.T, opt.TC)
			if flushed {
				flushes++
			}
			if closed {
				closes++
			}
		}
		if conn.s2c.closed && conn.c2s.closed && conn.s2c.lastSeen.Before(opt.TC) && conn.c2s.lastSeen.Before(opt.TC) {
			remove = true
		}
		conn.mu.Unlock()
		if remove {
			a.connPool.remove(conn)
		}
	}
	return flushes, closes
}

// FlushCloseOlderThan flushes and closes streams older than given time
func (a *Assembler) FlushCloseOlderThan(t time.Time) (flushed, closed int) {
	return a.FlushWithOptions(FlushOptions{T: t, TC: t})
}

func (a *Assembler) flushClose(conn *connection, half *halfconnection, t time.Time, tc time.Time) (bool, bool) {
	flushed, closed := false, false
	if half.closed {
		return flushed, closed
	}
	for half.first != nil && half.first.seen.Before(t) {
		flushed = true
		a.skipFlush(conn, half)
		if half.closed {
			closed = true
			return flushed, closed
		}
	}
	// Close the connection only if both halfs of the connection last seen before tc.
	if !half.closed && half.first == nil && conn.lastSeen().Before(tc) {
		a.closeHalfConnection(conn, half)
		closed = true
	}
	return flushed, closed
}

// FlushAll flushes all remaining data into all remaining connections and closes
// those connections. It returns the total number of connections flushed/closed
// by the call.
func (a *Assembler) FlushAll() (closed int) {
	conns := a.connPool.connections()
	closed = len(conns)
	for _, conn := range conns {
		conn.mu.Lock()
		for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
			for !half.closed {
				a.skipFlush(conn, half)
			}
			if !half.closed {
				a.closeHalfConnection(conn, half)
			}
		}
		conn.mu.Unlock()
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
