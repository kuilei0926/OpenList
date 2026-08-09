package fot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdpath "path"
	"strings"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// fotSuffix is the extension of fnOS encrypted backup files.
const fotSuffix = ".fot"

// maxHeaderRead is how many bytes we fetch from the head of a .fot file to parse its
// header and metadata (172-176 bytes in practice).
const maxHeaderRead = 4096

type Fot struct {
	model.Storage
	Addition
	password string
	// headerCache caches parsed .fot headers by underlying actual path so repeated
	// listings of the same directory don't re-fetch each file's header from the
	// storage API (which is slow and risks rate limiting on cloud storages).
	headerCache sync.Map // map[string]*fotCipher
}

func (d *Fot) Config() driver.Config {
	return config
}

func (d *Fot) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Fot) Init(ctx context.Context) error {
	d.RemotePath = utils.FixAndCleanPath(d.RemotePath)
	d.password = d.Password
	return nil
}

func (d *Fot) Drop(ctx context.Context) error {
	return nil
}

// readFOTHeader reads the head of a .fot file through a range reader built from the
// underlying storage link. It returns the parsed header plus the plaintext layout.
func (d *Fot) readFOTHeader(ctx context.Context, remoteStorage driver.Driver, remoteActualPath string, remoteSize int64, remoteLink *model.Link) (*fotCipher, error) {
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		return nil, fmt.Errorf("failed to build range reader: %w", err)
	}
	// request no more than the file size (small .fot files may be shorter than maxHeaderRead)
	length := int64(maxHeaderRead)
	if remoteSize > 0 && remoteSize < length {
		length = remoteSize
	}
	rc, err := rrf.RangeRead(ctx, http_range.Range{Start: 0, Length: length})
	if err != nil {
		return nil, fmt.Errorf("failed to read FOT header: %w", err)
	}
	defer rc.Close()
	head, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read FOT header: %w", err)
	}
	h, err := parseFOTHeader(head, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse FOT header: %w", err)
	}
	if err := h.validatePassword(d.password); err != nil {
		return nil, fmt.Errorf("failed to validate FOT file: %w", err)
	}
	cipher, err := newFotCipher(h, d.password)
	if err != nil {
		return nil, fmt.Errorf("failed to derive FOT keys: %w", err)
	}
	return cipher, nil
}

// linkFOTFile builds a link that decrypts the .fot file located at remoteActualPath
// of the underlying storage. The returned link exposes the plaintext with the
// plaintext size, and its RangeReader decrypts arbitrary ranges on the fly.
func (d *Fot) linkFOTFile(ctx context.Context, remoteStorage driver.Driver, remoteActualPath string, remoteLink *model.Link, remoteFile model.Obj) (*model.Link, error) {
	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = remoteFile.GetSize()
	}
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		_ = remoteLink.Close()
		return nil, fmt.Errorf("the underlying storage driver needs to be enhanced to support range reads")
	}

	// parse the header to derive keys and the plaintext size; reuse the cache if a
	// previous list already parsed this file.
	cipher, _ := d.headerCache.Load(remoteActualPath)
	var c *fotCipher
	if cipher != nil {
		c = cipher.(*fotCipher)
	} else {
		// request no more than the file size (small .fot files may be shorter than maxHeaderRead)
		length := int64(maxHeaderRead)
		if remoteSize > 0 && remoteSize < length {
			length = remoteSize
		}
		headRC, err := rrf.RangeRead(ctx, http_range.Range{Start: 0, Length: length})
		if err != nil {
			_ = remoteLink.Close()
			return nil, fmt.Errorf("failed to read FOT header: %w", err)
		}
		head, err := io.ReadAll(headRC)
		headRC.Close()
		if err != nil {
			_ = remoteLink.Close()
			return nil, fmt.Errorf("failed to read FOT header: %w", err)
		}
		h, err := parseFOTHeader(head, true)
		if err != nil {
			_ = remoteLink.Close()
			return nil, fmt.Errorf("failed to parse FOT header: %w", err)
		}
		if err := h.validatePassword(d.password); err != nil {
			_ = remoteLink.Close()
			return nil, fmt.Errorf("failed to validate FOT file: %w", err)
		}
		c, err = newFotCipher(h, d.password)
		if err != nil {
			_ = remoteLink.Close()
			return nil, fmt.Errorf("failed to derive FOT keys: %w", err)
		}
		d.headerCache.Store(remoteActualPath, c)
	}

	plainLen := c.PlainLen()
	headerLen := int64(c.h.headerLen)

	var mu sync.Mutex
	var fileHeader []byte
	// rangeReaderFunc fetches the raw (encrypted) range of the underlying .fot file.
	// The plaintext and the ciphertext have the same length, so the plaintext offset
	// maps 1:1 to the ciphertext offset shifted by headerLen. For files smaller than
	// maxHeaderRead, the requested range is clamped to the actual ciphertext size.
	headSize := min(int64(maxHeaderRead), plainLen)
	rangeReaderFunc := func(ctx context.Context, offset, limit int64) (io.ReadCloser, error) {
		length := limit
		// clamp to the ciphertext size (offset is a plaintext offset)
		if length < 0 || offset+length > plainLen {
			length = plainLen - offset
		}
		if length <= 0 {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		if offset == 0 && limit > 0 {
			mu.Lock()
			if limit <= headSize {
				defer mu.Unlock()
				if fileHeader != nil {
					return io.NopCloser(bytes.NewReader(fileHeader[:limit])), nil
				}
				// pad the small request up to headSize so we cache the header
				length = headSize
			} else if fileHeader == nil {
				defer mu.Unlock()
				// length stays = limit; we consume headSize bytes below to fill the cache
			} else {
				mu.Unlock()
			}
		}

		remoteReader, err := rrf.RangeRead(ctx, http_range.Range{Start: offset + headerLen, Length: length})
		if err != nil {
			return nil, err
		}

		if offset == 0 && limit > 0 {
			fileHeader = make([]byte, headSize)
			n, err := io.ReadFull(remoteReader, fileHeader)
			if int64(n) != headSize {
				fileHeader = nil
				return nil, fmt.Errorf("failed to read all data: (expect =%d, actual =%d) %w", headSize, n, err)
			}
			if limit <= headSize {
				remoteReader.Close()
				return io.NopCloser(bytes.NewReader(fileHeader[:limit])), nil
			} else {
				remoteReader = utils.ReadCloser{
					Reader: io.MultiReader(bytes.NewReader(fileHeader), remoteReader),
					Closer: remoteReader,
				}
			}
		}
		return remoteReader, nil
	}

	return &model.Link{
		ContentLength: plainLen,
		RangeReader: stream.RangeReaderFunc(func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
			start := httpRange.Start
			length := httpRange.Length
			if length < 0 || start+length > plainLen {
				length = plainLen - start
			}
			raw, err := rangeReaderFunc(ctx, start, length)
			if err != nil {
				return nil, err
			}
			// decrypt the ciphertext range in place with an offset-positioned CTR
			ctr := c.NewCTRForOffset(start)
			return &decryptReadCloser{
				Reader: raw,
				ctr:    ctr,
				block:  length,
			}, nil
		}),
		SyncClosers:      utils.NewSyncClosers(remoteLink),
		RequireReference: remoteLink.RequireReference,
	}, nil
}

func (d *Fot) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	remoteFullPath := dir.GetPath()
	objs, err := fs.List(ctx, remoteFullPath, &fs.ListArgs{NoLog: true, Refresh: args.Refresh})
	if err != nil {
		return nil, err
	}

	result := make([]model.Obj, 0, len(objs))
	// collect .fot files so their headers can be resolved concurrently
	var fotFiles []model.Obj
	for _, obj := range objs {
		mask := model.GetObjMask(obj)
		// the underlying storage may wrap obj names (e.g. when it has no Getter)
		name := model.UnwrapObjName(obj).GetName()
		path := stdpath.Join(remoteFullPath, name)
		if mask&model.Virtual != 0 {
			// pass through virtual objects as-is
			objRes := &model.Object{
				Path:     path,
				Name:     name,
				Size:     obj.GetSize(),
				Modified: obj.ModTime(),
				IsFolder: obj.IsDir(),
				Ctime:    obj.CreateTime(),
				Mask:     mask &^ model.Temp,
			}
			result = append(result, objRes)
			continue
		}
		if obj.IsDir() {
			if !d.ShowHidden && strings.HasPrefix(name, ".") {
				continue
			}
			objRes := &model.Object{
				Path:     path,
				Name:     name,
				Size:     obj.GetSize(),
				Modified: obj.ModTime(),
				IsFolder: true,
				Ctime:    obj.CreateTime(),
				Mask:     mask &^ model.Temp,
			}
			result = append(result, objRes)
			continue
		}
		// only .fot files are decryptable; pass everything else through unchanged
		if !strings.HasSuffix(strings.ToLower(name), fotSuffix) {
			if !d.ShowHidden && strings.HasPrefix(name, ".") {
				continue
			}
			objRes := &model.Object{
				Path:     path,
				Name:     name,
				Size:     obj.GetSize(),
				Modified: obj.ModTime(),
				IsFolder: false,
				Ctime:    obj.CreateTime(),
				Mask:     mask &^ model.Temp,
			}
			result = append(result, objRes)
			continue
		}
		fotFiles = append(fotFiles, obj)
	}

	// resolve .fot headers concurrently to reveal real filenames and sizes.
	// NOTE: fs.List returns objects whose GetPath() is the underlying storage's
	// actual path (mount prefix stripped, platform separators). We must rebuild the
	// mount path (remoteFullPath + name) ourselves before resolving the header.
	if len(fotFiles) > 0 {
		headers := d.resolveFotHeaders(ctx, remoteFullPath, fotFiles)
		for i, cipher := range headers {
			if cipher == nil {
				continue
			}
			obj := fotFiles[i]
			objRes := &model.Object{
				Path:     stdpath.Join(remoteFullPath, model.UnwrapObjName(obj).GetName()),
				Name:     cipher.filename,
				Size:     cipher.PlainLen(),
				Modified: obj.ModTime(),
				IsFolder: false,
				Ctime:    obj.CreateTime(),
				Mask:     model.GetObjMask(obj) &^ model.Temp,
			}
			result = append(result, objRes)
		}
	}
	return result, nil
}

// resolveFotHeaders parses the headers of the given .fot objects concurrently,
// returning a slice aligned with the input (nil entries for undecryptable files).
// mountPath is the rebuilt mount path prefix (dir.GetPath()).
func (d *Fot) resolveFotHeaders(ctx context.Context, mountPath string, fotFiles []model.Obj) []*fotCipher {
	results := make([]*fotCipher, len(fotFiles))
	if len(fotFiles) == 0 {
		return results
	}

	// limit concurrent header reads to avoid overwhelming the underlying storage API
	// (each .fot header read costs one download-url request on cloud storages; too much
	// parallelism risks rate limiting)
	const maxConcurrent = 6
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, obj := range fotFiles {
		wg.Add(1)
		go func(idx int, o model.Obj) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			cipher, err := d.parseFotObject(ctx, mountPath, o)
			if err != nil {
				log.Warnf("fot: skip undecryptable file %s: %v", o.GetPath(), err)
				return
			}
			results[idx] = cipher
		}(i, obj)
	}
	wg.Wait()
	return results
}

// parseFotObject links a single .fot object (at mountPath + name) and parses its header.
func (d *Fot) parseFotObject(ctx context.Context, mountPath string, obj model.Obj) (*fotCipher, error) {
	// rebuild the mount path; obj.GetPath() is the underlying actual path (no mount prefix)
	path := stdpath.Join(mountPath, model.UnwrapObjName(obj).GetName())
	storage, actualPath, err := op.GetStorageAndActualPath(path)
	if err != nil {
		return nil, err
	}
	// serve repeated reads from the in-memory cache
	if v, ok := d.headerCache.Load(actualPath); ok {
		return v.(*fotCipher), nil
	}
	remoteLink, _, err := op.Link(ctx, storage, actualPath, model.LinkArgs{})
	if err != nil {
		return nil, err
	}
	defer remoteLink.Close()
	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = obj.GetSize()
	}
	cipher, err := d.readFOTHeader(ctx, storage, actualPath, remoteSize, remoteLink)
	if err != nil {
		return nil, err
	}
	d.headerCache.Store(actualPath, cipher)
	return cipher, nil
}

// Get resolves an object by its path. The .fot file name cannot be derived from the
// decrypted name (it is md5(name)+size+mtime), so we always return NotSupport to let
// op.Get fall back to op.List, which already returns objects under their decrypted
// names and sizes.
func (d *Fot) Get(ctx context.Context, path string) (model.Obj, error) {
	return nil, errs.NotSupport
}

func (d *Fot) Link(ctx context.Context, file model.Obj, _ model.LinkArgs) (*model.Link, error) {
	// file.GetPath() is the underlying storage path of the .fot file (mount prefix
	// stripped). Non-.fot files are passed through unchanged in List/Get, so their
	// link is the underlying storage link directly.
	remotePath := file.GetPath()
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(remotePath)
	if err != nil {
		return nil, err
	}
	remoteLink, remoteFile, err := op.Link(ctx, remoteStorage, remoteActualPath, model.LinkArgs{})
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(strings.ToLower(remoteFile.GetName()), fotSuffix) {
		// not a .fot file: pass the underlying link through unchanged
		return remoteLink, nil
	}
	return d.linkFOTFile(ctx, remoteStorage, remoteActualPath, remoteLink, remoteFile)
}

// Put encrypts a plaintext file into its .fot form and uploads it to the
// underlying storage directory.
func (d *Fot) Put(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(dstDir.GetPath())
	if err != nil {
		return err
	}
	// the underlying .fot file name derives from the plaintext name/size/mtime
	fotName := fotFileName(file.GetName(), file.GetSize(), file.ModTime())
	encStream, encSize, err := NewFOTEncryptStream(d.password, file.GetName(), file.GetSize(), file)
	if err != nil {
		return fmt.Errorf("failed to build FOT encrypt stream: %w", err)
	}
	streamOut := &stream.FileStream{
		Obj: &model.Object{
			ID:       file.GetID(),
			Path:     file.GetPath(),
			Name:     fotName,
			Size:     encSize,
			Modified: file.ModTime(),
			IsFolder: file.IsDir(),
		},
		Reader:            encStream,
		Mimetype:          "application/octet-stream",
		ForceStreamUpload: true,
		Exist:             file.GetExist(),
	}
	if err := op.Put(ctx, remoteStorage, remoteActualPath, streamOut, up); err != nil {
		return err
	}
	// invalidate our header cache for the uploaded file
	d.headerCache.Delete(stdpath.Join(remoteActualPath, fotName))
	return nil
}

// MakeDir creates a directory in the underlying storage.
func (d *Fot) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(parentDir.GetPath())
	if err != nil {
		return err
	}
	return op.MakeDir(ctx, remoteStorage, stdpath.Join(remoteActualPath, dirName))
}

// Remove deletes a file (its .fot form) or directory from the underlying storage.
func (d *Fot) Remove(ctx context.Context, obj model.Obj) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(obj.GetPath())
	if err != nil {
		return err
	}
	if err := op.Remove(ctx, remoteStorage, remoteActualPath); err != nil {
		return err
	}
	d.headerCache.Delete(remoteActualPath)
	return nil
}

// Rename renames a file or directory in the underlying storage. For files, the
// new .fot name must be regenerated from the new plaintext name.
func (d *Fot) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(srcObj.GetPath())
	if err != nil {
		return err
	}
	if srcObj.IsDir() {
		return op.Rename(ctx, remoteStorage, remoteActualPath, newName)
	}
	// file: regenerate the .fot name from the new plaintext name (size/mtime unchanged)
	newFotName := fotFileName(newName, srcObj.GetSize(), srcObj.ModTime())
	if err := op.Rename(ctx, remoteStorage, remoteActualPath, newFotName); err != nil {
		return err
	}
	d.headerCache.Delete(remoteActualPath)
	return nil
}

func (d *Fot) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	remoteStorage, _, err := op.GetStorageAndActualPath(d.RemotePath)
	if err != nil {
		return nil, errs.NotImplement
	}
	remoteDetails, err := op.GetStorageDetails(ctx, remoteStorage)
	if err != nil {
		return nil, err
	}
	return &model.StorageDetails{
		DiskUsage: remoteDetails.DiskUsage,
	}, nil
}

// decryptReadCloser decrypts an AES-CTR ciphertext stream as it is read.
type decryptReadCloser struct {
	io.Reader
	ctr   cipherStream
	block int64 // plaintext length limit for this range
}

// cipherStream is the minimal AES-CTR interface we need.
type cipherStream interface {
	XORKeyStream(dst, src []byte)
}

func (r *decryptReadCloser) Read(p []byte) (int, error) {
	if r.block <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.block {
		p = p[:r.block]
	}
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.ctr.XORKeyStream(p[:n], p[:n])
		r.block -= int64(n)
	}
	return n, err
}

func (r *decryptReadCloser) Close() error {
	if c, ok := r.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

var _ driver.Driver = (*Fot)(nil)
var _ driver.Getter = (*Fot)(nil)
var _ driver.Put = (*Fot)(nil)
var _ driver.Mkdir = (*Fot)(nil)
var _ driver.Rename = (*Fot)(nil)
var _ driver.Remove = (*Fot)(nil)
