package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

func toHumanReadable(i int64) string {
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

func (s String155) String() string {
	return string(s[:])
}

type String100 [100]byte

func NewString100(s string) String100 {
	var r String100
	copy(r[:], s)
	return r
}

func (s String100) String() string {
	return string(s[:])
}

type String32 [32]byte

func (s String32) String() string {
	return string(s[:])
}

type String8 [8]byte

func (s String8) String() string {
	return string(s[:])
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

func (s Size) Int() int64 {
	var i int64
	fmt.Sscanf(string(s[:]), "%o", &i)
	return i
}

func (s Size) String() string {
	return toHumanReadable(s.Int())
}

type Timestamp [12]byte

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
	BaseName String100
	RawMode  Mode
	UID      ID
	GID      ID
	RawSize  Size
	MTime    Timestamp
	CheckSum CheckSum
	TypeFlag TypeFlag
	LinkName String100
	Magic    Magic
	Version  Version
	UName    String32
	GName    String32
	DevMajor String8
	DevMinor String8
	Prefix   String155
	Padding  [12]byte
}

func (h HeaderBlock) IsHeader() bool {
	return true
}

func (h HeaderBlock) IsFooter() bool {
	return false
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

func (h HeaderBlock) Name() string {
	pre := h.Prefix.String()
	if pre == "" {
		return h.BaseName.String()
	} else {
		return fmt.Sprintf("%s/%s", pre, h.BaseName)
	}
}

func (h HeaderBlock) Size() int64 {
	return h.RawSize.Int()
}

func (h HeaderBlock) Mode() os.FileMode {
	return h.RawMode.FileMode() | h.TypeFlag.FileMode()
}

func (h HeaderBlock) ModTime() time.Time {
	return h.MTime.Time()
}

func (h HeaderBlock) IsDir() bool {
	return h.TypeFlag == DIRTYPE
}

func (h HeaderBlock) Sys() interface{} {
	return nil
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

type ContentsArray []ContentBlock

func (cs ContentsArray) Bytes() []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, c[:]...)
	}
	return b
}

func (cs ContentsArray) WriteTo(w io.Writer) error {
	for _, c := range cs {
		if _, err := w.Write(c[:]); err != nil {
			return err
		}
	}
	return nil
}

type File struct {
	Header HeaderBlock
	Body   []byte
	reader io.ReadSeeker
}

func NewFile(name string) *File {
	body := []byte{}

	h := HeaderBlock{
		BaseName: NewString100(name),
		RawMode:  NewMode(os.ModePerm),
		TypeFlag: REGTYPE,
		UID:      NewID(1000),
		GID:      NewID(1000),
		Magic:    NewMagic(),
		Version:  NewVersion(),
	}

	h.CheckSum = NewCheckSum(h.CalcSum())

	return &File{
		Header: h,
		Body:   body,
		reader: bytes.NewReader(body),
	}
}

func ParseFile(r io.Reader) (*File, error) {
	f := File{}

	if err := binary.Read(r, binary.BigEndian, &f.Header); err != nil {
		return nil, err
	}

	if f.Header.calcTotal() == 0 {
		return nil, io.EOF
	}

	if f.Header.TypeFlag != REGTYPE && f.Header.TypeFlag != CONTTYPE {
		return &f, nil
	}

	blocks := (f.Header.Size() + 511) / 512

	buf := bytes.NewBuffer([]byte{})
	if n, err := io.CopyN(buf, r, blocks); err != nil {
		return nil, err
	} else if n != blocks {
		return nil, io.EOF
	}

	f.Body = buf.Bytes()[:f.Header.Size()]

	return &f, nil
}

func (f File) Name() string {
	return f.Header.Name()
}

func (f File) Size() uint64 {
	return uint64(len(f.Body))
}

func (f File) Blocks() int {
	return int((f.Size() + 511) / 512)
}

func (f *File) Write(p []byte) (int, error) {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	if len(f.Body)-int(pos) < len(p) {
		buf := make([]byte, len(f.Body)-int(pos)+len(p))
		copy(buf, f.Body)
		f.Body = buf
	}

	n, err := f.Seek(int64(copy(f.Body[pos:], p)), io.SeekCurrent)

	f.Header.RawSize = NewSize(f.Size())
	f.Header.CheckSum = NewCheckSum(f.Header.CalcSum())

	return int(n), err
}

func (f *File) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}

func (f File) ContentBlocks() ContentsArray {
	var arr ContentsArray
	for i := 0; i < int((f.Size()+511)/512); i++ {
		var c ContentBlock
		copy(c[:], f.Body[i*512:])
		arr = append(arr, c)
	}
	return arr
}

func (f File) WriteTo(w io.Writer) error {
	if err := f.Header.WriteTo(w); err != nil {
		return err
	}

	if f.Header.TypeFlag == REGTYPE || f.Header.TypeFlag == CONTTYPE {
		if err := f.ContentBlocks().WriteTo(w); err != nil {
			return err
		}
	}

	return nil
}

func Walk(r io.Reader, fun func(*File) error) error {
	for {
		f, err := ParseFile(r)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		err = fun(f)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	out, _ := os.Create("out.tar")
	file := NewFile("foobar")
	fmt.Fprintln(file, "hello world!")
	file.WriteTo(out)
}
