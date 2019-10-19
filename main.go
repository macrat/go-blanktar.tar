package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type FileInfo struct {
	Name_    string
	Size_    int64
	Mode_    os.FileMode
	ModTime_ time.Time
}

func (f FileInfo) Name() string {
	return f.Name_
}

func (f FileInfo) Size() int64 {
	return f.Size_
}

func (f FileInfo) Mode() os.FileMode {
	return f.Mode_
}

func (f FileInfo) ModTime() time.Time {
	return f.ModTime_
}

func (f FileInfo) IsDir() bool {
	return f.Mode().IsDir()
}

func (f FileInfo) Sys() interface{} {
	return nil
}

type Header struct {
	HeaderBlock
}

func NewHeader(info os.FileInfo) (*Header, error) {
	h, err := NewHeaderBlock(info)
	return &Header{h}, err
}

func (h Header) Name() string {
	pre := h.HeaderBlock.Prefix.String()
	if pre == "" {
		return h.HeaderBlock.Name.String()
	} else {
		return fmt.Sprintf("%s/%s", pre, h.HeaderBlock.Name)
	}
}

func (h Header) Size() int64 {
	return int64(h.HeaderBlock.Size.Int())
}

func (h *Header) SetSize(size int64) {
	h.HeaderBlock.Size = NewSize(uint64(size))
}

func (h Header) Mode() os.FileMode {
	return h.HeaderBlock.Mode.FileMode() | h.HeaderBlock.TypeFlag.FileMode()
}

func (h Header) ModTime() time.Time {
	return h.HeaderBlock.Modified.Time()
}

func (h Header) IsDir() bool {
	return h.HeaderBlock.TypeFlag == DIRTYPE
}

func (h Header) Sys() interface{} {
	return nil
}

func (h Header) Validate() bool {
	return h.HeaderBlock.Validate()
}

func (h Header) IsHeader() bool {
	return true
}

func (h Header) IsFooter() bool {
	return false
}

func (h Header) WriteTo(w io.Writer) error {
	return h.HeaderBlock.WriteTo(w)
}

func (h *Header) UpdateSum() {
	h.HeaderBlock.CheckSum = NewCheckSum(h.HeaderBlock.CalcSum())
}

type File struct {
	Header *Header
	body   []byte
	reader io.ReadSeeker
}

func NewFile(info os.FileInfo) (*File, error) {
	body := []byte{}

	h, err := NewHeader(info)
	return &File{
		Header: h,
		body:   body,
		reader: bytes.NewReader(body),
	}, err
}

func NewFileFromBinary(r io.Reader) (*File, error) {
	f := File{Header: new(Header)}

	if err := binary.Read(r, binary.BigEndian, f.Header); err != nil {
		return nil, err
	}

	if f.Header.HeaderBlock.IsFooter() {
		return nil, io.EOF
	}

	blocks := int64(f.Header.HeaderBlock.ContentBlockNum())
	if blocks == 0 {
		return &f, nil
	}

	buf := bytes.NewBuffer([]byte{})
	if n, err := io.CopyN(buf, r, blocks*512); err != nil {
		return nil, err
	} else if n != (blocks * 512) {
		return nil, io.EOF
	}

	f.body = buf.Bytes()[:f.Header.Size()]

	return &f, nil
}

func (f File) Name() string {
	return f.Header.Name()
}

func (f File) Stat() (os.FileInfo, error) {
	return f.Header, nil
}

func (f *File) Write(p []byte) (int, error) {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	if len(f.body)-int(pos) < len(p) {
		buf := make([]byte, len(f.body)-int(pos)+len(p))
		copy(buf, f.body)
		f.body = buf
	}

	n, err := f.Seek(int64(copy(f.body[pos:], p)), io.SeekCurrent)

	f.Header.SetSize(int64(len(f.body)))
	f.Header.UpdateSum()

	return int(n), err
}

func (f *File) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}

func (f File) WriteTo(w io.Writer) error {
	if err := f.Header.WriteTo(w); err != nil {
		return err
	}

	if f.Header.HeaderBlock.ContentBlockNum() > 0 {
		if _, err := w.Write(f.body); err != nil {
			return err
		}

		if _, err := w.Write(make([]byte, ((len(f.body)+511)/512)*512-len(f.body))); err != nil {
			return err
		}
	}

	return nil
}

func Walk(r io.Reader, fun func(*File) error) error {
	for {
		f, err := NewFileFromBinary(r)
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

type FileView struct {
	tar    Tar
	file   *File
	reader io.ReadSeeker
}

func NewFileView(t Tar, f *File) *FileView {
	return &FileView{
		tar:    t,
		file:   f,
		reader: bytes.NewReader(f.body),
	}
}

func (f FileView) Close() error {
	if f.reader == nil {
		return io.ErrClosedPipe
	}
	f.reader = nil
	return nil
}

func (f FileView) Read(p []byte) (n int, err error) {
	if f.reader == nil {
		return 0, io.ErrClosedPipe
	}
	n, err = f.reader.Read(p)
	return
}

func (f FileView) Seek(offset int64, whence int) (int64, error) {
	if f.reader == nil {
		return 0, io.ErrClosedPipe
	}
	return f.reader.Seek(offset, whence)
}

func (f FileView) Readdir(count int) ([]os.FileInfo, error) {
	fs := []os.FileInfo{}

	for _, x := range f.tar {
		n := path.Clean(x.Name())
		if !strings.HasSuffix(n, "/") {
			n += "/"
		}
		if strings.HasPrefix(n, path.Clean(f.file.Name())) {
			s, err := x.Stat()
			if err != nil {
				return nil, err
			}
			fs = append(fs, s)
		}
	}

	return fs[:count], nil
}

func (f FileView) Stat() (os.FileInfo, error) {
	return f.file.Stat()
}

type Tar []*File

func Read(r io.Reader) (Tar, error) {
	var t Tar

	err := Walk(r, func(f *File) error {
		t = append(t, f)
		return nil
	})

	return t, err
}

func (t Tar) Open(name string) (http.File, error) {
	name = path.Clean("." + name)
	for _, x := range t {
		if path.Clean(x.Name()) == name {
			return NewFileView(t, x), nil
		}
	}
	return nil, http.ErrMissingFile
}

func main() {
	/*
		out, _ := os.Create("out.tar")

		file, err := NewFile(FileInfo{
	        Name_: "foobar",
	        ModTime_: time.Now(),
	        Mode_: 0644,
	    })
	    if err != nil {
	        panic(err.Error())
	    }

		fmt.Fprintln(file, "hello world!")
		file.WriteTo(out)
	*/

	in, _ := os.Open("www.tar")
	t, err := Read(in)
	if err != nil {
		panic(err.Error())
	}
	http.ListenAndServe("localhost:8080", http.FileServer(t))
}
