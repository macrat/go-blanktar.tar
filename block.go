package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

var (
	PropertyOverflow = errors.New("property overflow")
	NameTooLong      = errors.New("file name is too long")
)

func toHumanReadable(i uint64) string {
	switch {
	case i < 1<<10:
		return fmt.Sprintf("%dB", i)
	case i < 1<<20:
		return fmt.Sprintf("%.2fKB", float64(i)/(1<<10))
	case i < 1<<30:
		return fmt.Sprintf("%.2fMB", float64(i)/(1<<20))
	default:
		return fmt.Sprintf("%.2fGB", float64(i)/(1<<30))
	}
}

type String155 [155]byte

func NewString155(s string) (String155, error) {
	var r String155

	b := []byte(s)
	if len(b)-1 >= 155 {
		return r, PropertyOverflow
	}

	copy(r[:], b)
	return r, nil
}

func (s String155) String() string {
	return strings.TrimRight(string(s[:]), "\u0000")
}

type String100 [100]byte

func NewString100(s string) (String100, error) {
	var r String100

	b := []byte(s)
	if len(b)-1 >= 100 {
		return r, PropertyOverflow
	}

	copy(r[:], b)
	return r, nil
}

func (s String100) String() string {
	return strings.TrimRight(string(s[:]), "\u0000")
}

type String32 [32]byte

func NewString32(s string) (String32, error) {
	var r String32

	b := []byte(s)
	if len(b)-1 >= 32 {
		return r, PropertyOverflow
	}

	copy(r[:], b)
	return r, nil
}

func (s String32) String() string {
	return strings.TrimRight(string(s[:]), "\u0000")
}

type String8 [8]byte

func NewString8(s string) (String8, error) {
	var r String8

	b := []byte(s)
	if len(b)-1 >= 8 {
		return r, PropertyOverflow
	}

	copy(r[:], b)
	return r, nil
}

func (s String8) String() string {
	return strings.TrimRight(string(s[:]), "\u0000")
}

type Mode [8]byte

func NewMode(mode os.FileMode) Mode {
	var i uint32

	i = uint32(mode & os.ModePerm)
	if mode&os.ModeSetuid != 0 {
		i |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		i |= 02000
	}

	var m Mode
	copy(m[:], fmt.Sprintf("%07o", i))
	return m
}

func (m Mode) FileMode() os.FileMode {
	var i os.FileMode

	fmt.Sscanf(string(m[3:]), "%o", &i)

	if i&04000 != 0 {
		i |= os.ModeSetuid
	}
	if i&02000 != 0 {
		i |= os.ModeSetgid
	}

	return os.FileMode(i)
}

func (m Mode) String() string {
	return fmt.Sprintf("%o", m.FileMode())
}

type Size [12]byte

func NewSize(size uint64) Size {
	var s Size
	copy(s[:], []byte(fmt.Sprintf("%07o", size)))
	return s
}

func (s Size) Int() uint64 {
	var i uint64
	fmt.Sscanf(string(s[:]), "%o", &i)
	return i
}

func (s Size) String() string {
	return toHumanReadable(s.Int())
}

type Timestamp [12]byte

func NewTimestamp(t time.Time) Timestamp {
	n := t.Unix()
	if n < 0 {
		n = 0
	}

	var x Timestamp
	copy(x[:], []byte(fmt.Sprintf("%011o", n)))
	return x
}

func (t Timestamp) Time() time.Time {
	var i int64
	fmt.Sscanf(string(t[:]), "%o", &i)
	return time.Unix(i, 0)
}

func (t Timestamp) String() string {
	return fmt.Sprint(t.Time())
}

type CheckSum [8]byte

func NewCheckSum(checksum int64) CheckSum {
	var c CheckSum
	copy(c[:], []byte(fmt.Sprintf("%07o", checksum)))
	return c
}

func (c CheckSum) Int() int64 {
	var i int64
	fmt.Sscanf(string(c[:]), "%o", &i)
	return i
}

func (c CheckSum) String() string {
	return fmt.Sprintf("0x%016X", c.Int())
}

type TypeFlag byte

const (
	REGTYPE  TypeFlag = '0'
	AREGTYPE TypeFlag = '\n'
	LINKTYPE TypeFlag = '1'
	SYMTYPE  TypeFlag = '2'
	CHRTYPE  TypeFlag = '3'
	BLKTYPE  TypeFlag = '4'
	DIRTYPE  TypeFlag = '5'
	FIFOTYPE TypeFlag = '6'
	CONTTYPE TypeFlag = '7'
)

func NewTypeFlag(mode os.FileMode) TypeFlag {
	switch {
	case mode&os.ModeSymlink != 0:
		return SYMTYPE
	case mode&os.ModeCharDevice != 0:
		return CHRTYPE
	case mode&os.ModeDevice != 0:
		return BLKTYPE
	case mode&os.ModeDir != 0:
		return DIRTYPE
	case mode&os.ModeNamedPipe != 0:
		return FIFOTYPE
	default:
		return REGTYPE
	}
}

func (t TypeFlag) FileMode() os.FileMode {
	switch t {
	case SYMTYPE:
		return os.ModeSymlink
	case CHRTYPE:
		return os.ModeCharDevice
	case BLKTYPE:
		return os.ModeDevice
	case DIRTYPE:
		return os.ModeDir
	case FIFOTYPE:
		return os.ModeNamedPipe
	default:
		return os.FileMode(0)
	}
}

func (t TypeFlag) String() string {
	switch t {
	case REGTYPE:
		return "regular file"
	case AREGTYPE:
		return "regular file (already archived)"
	case LINKTYPE:
		return "link"
	case SYMTYPE:
		return "symbolic link"
	case CHRTYPE:
		return "character device"
	case BLKTYPE:
		return "block device"
	case DIRTYPE:
		return "directory"
	case FIFOTYPE:
		return "fifo special file"
	case CONTTYPE:
		return "reserved"
	default:
		return "unknown"
	}
}

type Magic [6]byte

func NewMagic() Magic {
	var m Magic
	copy(m[:], "ustar")
	return m
}

func (m Magic) String() string {
	return string(m[:])
}

type Version [2]byte

func NewVersion() Version {
	var v Version
	v[0] = '0'
	v[1] = '0'
	return v
}

type Block interface {
	IsHeader() bool
	IsFooter() bool
	WriteTo(io.Writer) error
}

type ID [8]byte

func NewID(id uint32) ID {
	var i ID
	copy(i[:], []byte(fmt.Sprintf("%07o", id)))
	return i
}

func (id ID) Int() uint32 {
	var i uint32
	fmt.Sscanf(string(id[:]), "%o", &i)
	return i
}

func (id ID) String() string {
	return fmt.Sprintf("%d", id.Int())
}

type HeaderBlock struct {
	Name      String100
	Mode      Mode
	UID       ID
	GID       ID
	Size      Size
	Modified  Timestamp
	CheckSum  CheckSum
	TypeFlag  TypeFlag
	LinkName  String100
	Magic     Magic
	Version   Version
	UserName  String32
	GroupName String32
	DevMajor  String8
	DevMinor  String8
	Prefix    String155
	Padding   [12]byte
}

func NewHeaderBlock(info os.FileInfo) (HeaderBlock, error) {
	name := info.Name()
	prefix := ""

	for len([]byte(name))-1 >= 100 {
		xs := strings.SplitN(name, "/", 2)
		prefix = path.Join(prefix, xs[0])
		name = xs[1]
	}

	n, err := NewString100(name)
	if err != nil {
		return HeaderBlock{}, NameTooLong
	}
	p, err := NewString155(prefix)
	if err != nil {
		return HeaderBlock{}, NameTooLong
	}

	h := HeaderBlock{
		Name:     n,
		Mode:     NewMode(info.Mode()),
		Modified: NewTimestamp(info.ModTime()),
		TypeFlag: NewTypeFlag(info.Mode()),
		Magic:    NewMagic(),
		Version:  NewVersion(),
		Prefix:   p,
	}

	h.CheckSum = NewCheckSum(h.CalcSum())

	return h, nil
}

func (h HeaderBlock) IsHeader() bool {
	return h.calcTotal() > 0
}

func (h HeaderBlock) IsFooter() bool {
	return h.calcTotal() == 0
}

func (h HeaderBlock) ContentBlockNum() uint64 {
	if h.TypeFlag != REGTYPE && h.TypeFlag != CONTTYPE {
		return 0
	}
	return (h.Size.Int() + 511) / 512
}

func (h HeaderBlock) WriteTo(w io.Writer) error {
	return binary.Write(w, binary.BigEndian, h)
}

func (h HeaderBlock) Bytes() []byte {
	buf := new(bytes.Buffer)
	h.WriteTo(buf)
	return buf.Bytes()
}

func (h HeaderBlock) calcTotal() int64 {
	var sum int64

	for _, x := range h.Bytes() {
		sum += int64(x)
	}

	return sum
}

func (h HeaderBlock) CalcSum() int64 {
	sum := h.calcTotal()

	for _, x := range [8]byte(h.CheckSum) {
		sum -= int64(x)
	}
	sum += 0x30*6 - 0x20

	return sum
}

func (h HeaderBlock) Validate() bool {
	return h.CalcSum() == h.CheckSum.Int()
}

type ContentBlock [512]byte

func (c ContentBlock) IsHeader() bool {
	return false
}

func (c ContentBlock) IsFooter() bool {
	return false
}

func (c ContentBlock) WriteTo(w io.Writer) error {
	_, err := w.Write(c[:])
	return err
}

type FooterBlock [1024]byte

func (f FooterBlock) IsHeader() bool {
	return false
}

func (f FooterBlock) IsFooter() bool {
	return true
}

func (f FooterBlock) WriteTo(w io.Writer) error {
	_, err := w.Write(f[:])
	return err
}

type BlockArray []Block

func (b BlockArray) IsHeader() bool {
	return false
}

func (b BlockArray) IsFooter() bool {
	if len(b) == 0 {
		return false
	}

	return b[len(b)-1].IsFooter()
}

func (b BlockArray) WriteTo(w io.Writer) error {
	for _, b := range b {
		if err := b.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}
