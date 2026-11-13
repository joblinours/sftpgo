// Copyright (C) 2026 Lucas Joblin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package httpd

// Resumable chunked uploads for the WebClient and public shares.
//
// The protocol is a subset of tus 1.0.0 (core + creation + termination):
//
//   - POST   <base>?path=...        creates an upload, requires Upload-Length,
//     returns 201 and a relative Location header
//   - HEAD   <base>/<id>            returns the current Upload-Offset
//   - PATCH  <base>/<id>            appends a chunk at Upload-Offset
//   - DELETE <base>/<id>            aborts the upload
//   - GET    <base>/<id>            non tus extension, returns a JSON status
//
// Chunks are stored in a local temporary file. When the last chunk is received
// the response is sent immediately and the complete file is moved to the user's
// storage backend in background, using the standard SFTPGo upload path so
// permissions, quotas, hooks and events are applied as for any other upload.
// This way the final request never waits for a potentially slow backend upload,
// avoiding proxy timeouts (for example the Cloudflare 100 seconds timeout).

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/render"
	"github.com/shirou/gopsutil/v4/disk"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	tusVersion                    = "1.0.0"
	tusResumableHeader            = "Tus-Resumable"
	tusUploadLengthHeader         = "Upload-Length"
	tusUploadOffsetHeader         = "Upload-Offset"
	tusContentType                = "application/offset+octet-stream"
	chunkedUploadTempSuffix       = ".sftpgo-chunked"
	chunkedUploadDefaultDir       = "sftpgo-chunked-uploads"
	chunkedUploadIdleExpiration   = 24 * time.Hour
	chunkedUploadResultRetention  = time.Hour
	maxPendingChunkedUploadsOwner = 20
	chunkedUploadDiskReserve      = int64(512 * 1024 * 1024)
)

type chunkedUploadState int

const (
	chunkedUploadStateUploading chunkedUploadState = iota
	chunkedUploadStateProcessing
	chunkedUploadStateCompleted
	chunkedUploadStateFailed
)

func (s chunkedUploadState) String() string {
	switch s {
	case chunkedUploadStateProcessing:
		return "processing"
	case chunkedUploadStateCompleted:
		return "completed"
	case chunkedUploadStateFailed:
		return "failed"
	default:
		return "uploading"
	}
}

var (
	chunkedUploads           = newChunkedUploadManager()
	errChunkedUploadNotFound = errors.New("upload not found")
)

type chunkedUpload struct {
	mu           sync.Mutex
	ID           string
	Username     string
	ShareID      string
	VirtualPath  string
	MkdirParents bool
	Size         int64
	Offset       int64
	MTime        string
	TempFile     string
	LastActivity time.Time
	State        chunkedUploadState
	ErrorMessage string
	ErrorCode    int
	busy         bool
}

func (u *chunkedUpload) ownerKey() string {
	if u.ShareID != "" {
		return "share:" + u.ShareID
	}
	return "user:" + u.Username
}

type chunkedUploadStatusResponse struct {
	Status    string `json:"status"`
	Offset    int64  `json:"offset"`
	Size      int64  `json:"size"`
	Error     string `json:"error,omitempty"`
	ErrorCode int    `json:"error_code,omitempty"`
}

type chunkedUploadManager struct {
	mu       sync.Mutex
	uploads  map[string]*chunkedUpload
	tempPath string
}

func newChunkedUploadManager() *chunkedUploadManager {
	return &chunkedUploadManager{
		uploads: make(map[string]*chunkedUpload),
	}
}

func (m *chunkedUploadManager) setTempPath(configured string) {
	tempPath := configured
	if tempPath == "" {
		tempPath = filepath.Join(os.TempDir(), chunkedUploadDefaultDir)
	}
	m.mu.Lock()
	m.tempPath = filepath.Clean(tempPath)
	m.mu.Unlock()
	// remove leftovers from a previous run, only our own files are removed
	if entries, err := os.ReadDir(tempPath); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), chunkedUploadTempSuffix) {
				_ = os.Remove(filepath.Join(tempPath, e.Name()))
			}
		}
	}
}

func (m *chunkedUploadManager) getTempPath() (string, error) {
	m.mu.Lock()
	tempPath := m.tempPath
	m.mu.Unlock()
	if tempPath == "" {
		tempPath = filepath.Join(os.TempDir(), chunkedUploadDefaultDir)
	}
	if err := os.MkdirAll(tempPath, 0700); err != nil {
		return "", err
	}
	return tempPath, nil
}

func (m *chunkedUploadManager) get(id string) *chunkedUpload {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.uploads[id]
}

// add registers a new upload, it checks the per owner limit and the available
// local disk space taking into account the pending uploads
func (m *chunkedUploadManager) add(u *chunkedUpload, tempPath string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pendingForOwner := 0
	pendingBytes := int64(0)
	owner := u.ownerKey()
	for _, upload := range m.uploads {
		upload.mu.Lock()
		if upload.State == chunkedUploadStateUploading || upload.State == chunkedUploadStateProcessing {
			pendingBytes += upload.Size - upload.Offset
			if upload.State == chunkedUploadStateProcessing {
				pendingBytes += upload.Size
			}
			if upload.ownerKey() == owner {
				pendingForOwner++
			}
		}
		upload.mu.Unlock()
	}
	if pendingForOwner >= maxPendingChunkedUploadsOwner {
		return http.StatusTooManyRequests, errors.New("too many pending uploads")
	}
	if usage, err := disk.Usage(tempPath); err == nil {
		free := int64(usage.Free) - pendingBytes - chunkedUploadDiskReserve
		if u.Size > free {
			logger.Warn(logSender, u.ID, "not enough local disk space in %q for a chunked upload of %d bytes, available: %d",
				tempPath, u.Size, free)
			return http.StatusInsufficientStorage, errors.New("not enough temporary disk space on the server")
		}
	}
	m.uploads[u.ID] = u
	return 0, nil
}

func (m *chunkedUploadManager) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.uploads, id)
}

func (m *chunkedUploadManager) cleanup() {
	var expired []*chunkedUpload

	m.mu.Lock()
	for id, u := range m.uploads {
		u.mu.Lock()
		idle := time.Since(u.LastActivity)
		switch u.State {
		case chunkedUploadStateUploading:
			if !u.busy && idle > chunkedUploadIdleExpiration {
				delete(m.uploads, id)
				expired = append(expired, u)
			}
		case chunkedUploadStateCompleted, chunkedUploadStateFailed:
			if idle > chunkedUploadResultRetention {
				delete(m.uploads, id)
			}
		}
		u.mu.Unlock()
	}
	m.mu.Unlock()

	for _, u := range expired {
		logger.Info(logSender, u.ID, "removing abandoned chunked upload for %q, received %d/%d bytes",
			u.VirtualPath, u.Offset, u.Size)
		u.discard()
	}
}

// discard removes the temporary file and releases the share usage token, if any.
// The upload must already be removed from the manager
func (u *chunkedUpload) discard() {
	_ = os.Remove(u.TempFile)
	releaseShareToken(u.ShareID)
}

func releaseShareToken(shareID string) {
	if shareID == "" {
		return
	}
	share, err := dataprovider.ShareExists(shareID, "")
	if err == nil {
		_ = dataprovider.UpdateShareLastUse(&share, -1)
	}
}

func setTusHeaders(w http.ResponseWriter) {
	w.Header().Set(tusResumableHeader, tusVersion)
	w.Header().Set("Cache-Control", "no-store")
}

func sendTusError(w http.ResponseWriter, r *http.Request, err error, message string, status int) {
	setTusHeaders(w)
	sendAPIResponse(w, r, err, message, status)
}

func generateChunkedUploadID() string {
	return strings.ToLower(rand.Text())
}

func (s *httpdServer) getMaxChunkSize() int64 {
	return int64(s.binding.UploadChunkSize) * 1024 * 1024
}

// preCheckChunkedUpload performs early permission and quota checks so the user
// does not upload a huge file that will be refused at the end. All the checks
// are performed again when the file is moved to the storage backend
func preCheckChunkedUpload(conn *Connection, virtualPath string, size int64) (int, error) {
	if ok, _ := conn.User.IsFileAllowed(virtualPath); !ok {
		return http.StatusForbidden, conn.GetPermissionDeniedError()
	}
	dir := path.Dir(virtualPath)
	if !conn.User.HasPerm(dataprovider.PermUpload, dir) && !conn.User.HasPerm(dataprovider.PermOverwrite, dir) {
		return http.StatusForbidden, conn.GetPermissionDeniedError()
	}
	diskQuota, transferQuota := conn.HasSpace(true, false, virtualPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		return http.StatusRequestEntityTooLarge, common.ErrQuotaExceeded
	}
	maxWriteSize, _ := conn.GetMaxWriteSize(diskQuota, false, 0, false)
	if maxWriteSize > 0 && size > maxWriteSize {
		return http.StatusRequestEntityTooLarge, common.ErrQuotaExceeded
	}
	if transferQuota.AllowedULSize > 0 && size > transferQuota.AllowedULSize {
		return http.StatusRequestEntityTooLarge, common.ErrQuotaExceeded
	}
	if transferQuota.AllowedTotalSize > 0 && size > transferQuota.AllowedTotalSize {
		return http.StatusRequestEntityTooLarge, common.ErrQuotaExceeded
	}
	return 0, nil
}

func parseUploadLength(r *http.Request) (int64, error) {
	val := r.Header.Get(tusUploadLengthHeader)
	if val == "" {
		return 0, errors.New("missing Upload-Length header")
	}
	size, err := strconv.ParseInt(val, 10, 64)
	if err != nil || size < 0 {
		return 0, errors.New("invalid Upload-Length header")
	}
	return size, nil
}

// createChunkedUpload validates and registers a new upload, the caller must
// already have validated the target path
func (s *httpdServer) createChunkedUpload(w http.ResponseWriter, r *http.Request, conn *Connection,
	virtualPath, shareID, locationBase string,
) (*chunkedUpload, bool) {
	size, err := parseUploadLength(r)
	if err != nil {
		sendTusError(w, r, err, "", http.StatusBadRequest)
		return nil, false
	}
	if maxUploadFileSize > 0 && size > maxUploadFileSize {
		sendTusError(w, r, errors.New("file too large"), "", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	_ = conn.User.CheckFsRoot(conn.ID)
	if status, err := preCheckChunkedUpload(conn, virtualPath, size); err != nil {
		conn.Log(logger.LevelInfo, "chunked upload for %q denied: %v", virtualPath, err)
		sendTusError(w, r, err, fmt.Sprintf("Unable to upload file %q", virtualPath), status)
		return nil, false
	}
	tempPath, err := chunkedUploads.getTempPath()
	if err != nil {
		logger.Error(logSender, "", "unable to create the temporary directory for chunked uploads: %v", err)
		sendTusError(w, r, err, "", http.StatusInternalServerError)
		return nil, false
	}
	upload := &chunkedUpload{
		ID:           generateChunkedUploadID(),
		Username:     conn.User.Username,
		ShareID:      shareID,
		VirtualPath:  virtualPath,
		MkdirParents: getBoolQueryParam(r, "mkdir_parents"),
		Size:         size,
		MTime:        r.Header.Get(mTimeHeader),
		LastActivity: time.Now(),
		State:        chunkedUploadStateUploading,
	}
	upload.TempFile = filepath.Join(tempPath, upload.ID+chunkedUploadTempSuffix)
	f, err := os.OpenFile(upload.TempFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		logger.Error(logSender, upload.ID, "unable to create temporary file %q: %v", upload.TempFile, err)
		sendTusError(w, r, err, "", http.StatusInternalServerError)
		return nil, false
	}
	f.Close()
	if status, err := chunkedUploads.add(upload, tempPath); err != nil {
		_ = os.Remove(upload.TempFile)
		sendTusError(w, r, err, "", status)
		return nil, false
	}
	conn.Log(logger.LevelInfo, "chunked upload %q created for %q, size: %d", upload.ID, virtualPath, size)
	setTusHeaders(w)
	// relative location, it is resolved by the client against the URL it used,
	// so it works behind reverse proxies
	w.Header().Set("Location", path.Join(path.Base(locationBase), upload.ID))
	w.Header().Set(tusUploadOffsetHeader, "0")
	w.WriteHeader(http.StatusCreated)
	return upload, true
}

func (u *chunkedUpload) getStatus() chunkedUploadStatusResponse {
	u.mu.Lock()
	defer u.mu.Unlock()

	return chunkedUploadStatusResponse{
		Status:    u.State.String(),
		Offset:    u.Offset,
		Size:      u.Size,
		Error:     u.ErrorMessage,
		ErrorCode: u.ErrorCode,
	}
}

func handleChunkedUploadHead(w http.ResponseWriter, upload *chunkedUpload) {
	upload.mu.Lock()
	offset := upload.Offset
	size := upload.Size
	upload.mu.Unlock()

	setTusHeaders(w)
	w.Header().Set(tusUploadOffsetHeader, strconv.FormatInt(offset, 10))
	w.Header().Set(tusUploadLengthHeader, strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
}

func handleChunkedUploadStatus(w http.ResponseWriter, r *http.Request, upload *chunkedUpload) {
	w.Header().Set("Cache-Control", "no-store")
	render.JSON(w, r, upload.getStatus())
}

func handleChunkedUploadDelete(w http.ResponseWriter, r *http.Request, upload *chunkedUpload) {
	upload.mu.Lock()
	if upload.State != chunkedUploadStateUploading || upload.busy {
		upload.mu.Unlock()
		sendTusError(w, r, errors.New("the upload cannot be aborted now"), "", http.StatusConflict)
		return
	}
	upload.State = chunkedUploadStateFailed
	upload.ErrorMessage = "aborted"
	upload.mu.Unlock()

	chunkedUploads.remove(upload.ID)
	upload.discard()
	logger.Info(logSender, upload.ID, "chunked upload for %q aborted by the client", upload.VirtualPath)
	setTusHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}

// writeChunk appends the request body to the temporary file. It returns true if
// the upload is complete and must be finalized. On error the response is sent
func (s *httpdServer) writeChunk(w http.ResponseWriter, r *http.Request, upload *chunkedUpload) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), tusContentType) {
		sendTusError(w, r, errors.New("invalid Content-Type"), "", http.StatusUnsupportedMediaType)
		return false
	}
	offset, err := strconv.ParseInt(r.Header.Get(tusUploadOffsetHeader), 10, 64)
	if err != nil || offset < 0 {
		sendTusError(w, r, errors.New("invalid Upload-Offset header"), "", http.StatusBadRequest)
		return false
	}

	upload.mu.Lock()
	if upload.State != chunkedUploadStateUploading {
		upload.mu.Unlock()
		sendTusError(w, r, errors.New("the upload is already complete"), "", http.StatusConflict)
		return false
	}
	if upload.busy {
		upload.mu.Unlock()
		sendTusError(w, r, errors.New("another request is in progress for this upload"), "", http.StatusConflict)
		return false
	}
	if offset != upload.Offset {
		upload.mu.Unlock()
		sendTusError(w, r, fmt.Errorf("offset mismatch, expected %d", upload.Offset), "", http.StatusConflict)
		return false
	}
	upload.busy = true
	remaining := upload.Size - upload.Offset
	upload.mu.Unlock()

	defer func() {
		upload.mu.Lock()
		upload.busy = false
		upload.LastActivity = time.Now()
		upload.mu.Unlock()
	}()

	maxChunk := s.getMaxChunkSize()
	if r.ContentLength > remaining || r.ContentLength > maxChunk {
		sendTusError(w, r, errors.New("chunk too large"), "", http.StatusRequestEntityTooLarge)
		return false
	}
	limit := remaining
	if maxChunk < limit {
		limit = maxChunk
	}

	f, err := os.OpenFile(upload.TempFile, os.O_WRONLY, 0600)
	if err != nil {
		logger.Error(logSender, upload.ID, "unable to open temporary file: %v", err)
		sendTusError(w, r, err, "", http.StatusInternalServerError)
		return false
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		sendTusError(w, r, err, "", http.StatusInternalServerError)
		return false
	}
	// partial writes are kept, the client will resume from the stored offset
	written, copyErr := io.Copy(f, io.LimitReader(r.Body, limit))
	closeErr := f.Close()

	upload.mu.Lock()
	upload.Offset += written
	newOffset := upload.Offset
	isComplete := upload.Offset == upload.Size
	if isComplete {
		upload.State = chunkedUploadStateProcessing
	}
	upload.mu.Unlock()

	if copyErr != nil || closeErr != nil {
		err = copyErr
		if err == nil {
			err = closeErr
		}
		logger.Debug(logSender, upload.ID, "error receiving chunk, offset %d, written %d: %v", offset, written, err)
		sendTusError(w, r, err, "Error receiving chunk", http.StatusInternalServerError)
		return false
	}
	setTusHeaders(w)
	w.Header().Set(tusUploadOffsetHeader, strconv.FormatInt(newOffset, 10))
	if !isComplete {
		w.WriteHeader(http.StatusNoContent)
	}
	return isComplete
}

func (u *chunkedUpload) setResult(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.LastActivity = time.Now()
	if err != nil {
		u.State = chunkedUploadStateFailed
		u.ErrorMessage = err.Error()
		u.ErrorCode = getMappedStatusCode(err)
		return
	}
	u.State = chunkedUploadStateCompleted
}

// finalize moves the complete file to the user's storage using the standard
// upload path. It runs in background, conn is removed from the active
// connections when done
func (u *chunkedUpload) finalize(conn *Connection) {
	defer common.Connections.Remove(conn.GetID())
	defer os.Remove(u.TempFile)

	err := u.copyToStorage(conn)
	if err != nil {
		conn.Log(logger.LevelError, "unable to finalize chunked upload %q for %q: %v", u.ID, u.VirtualPath, err)
		if u.ShareID != "" {
			releaseShareToken(u.ShareID)
		}
	} else {
		conn.Log(logger.LevelInfo, "chunked upload %q for %q completed, size: %d", u.ID, u.VirtualPath, u.Size)
	}
	u.setResult(err)
}

func (u *chunkedUpload) copyToStorage(conn *Connection) error {
	_ = conn.User.CheckFsRoot(conn.ID)
	if u.MkdirParents {
		if err := conn.CheckParentDirs(path.Dir(u.VirtualPath)); err != nil {
			return err
		}
	}
	src, err := os.Open(u.TempFile)
	if err != nil {
		return err
	}
	defer src.Close()

	writer, err := conn.getFileWriter(u.VirtualPath)
	if err != nil {
		return err
	}
	if _, err = io.Copy(writer, src); err != nil {
		markTransferError(writer, err)
		writer.Close()
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	if u.MTime != "" {
		if mTime, err := strconv.ParseInt(u.MTime, 10, 64); err == nil {
			attrs := common.StatAttributes{
				Flags: common.StatAttrTimes,
				Atime: util.GetTimeFromMsecSinceEpoch(mTime),
				Mtime: util.GetTimeFromMsecSinceEpoch(mTime),
			}
			if err := conn.SetStat(u.VirtualPath, &attrs); err != nil {
				conn.Log(logger.LevelDebug, "unable to set modification time for %q: %v", u.VirtualPath, err)
			}
		}
	}
	return nil
}

// WebClient handlers

func getChunkedUploadForWebClientUser(w http.ResponseWriter, r *http.Request) (*chunkedUpload, bool) {
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendTusError(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return nil, false
	}
	upload := chunkedUploads.get(getURLParam(r, "uploadid"))
	if upload == nil || upload.ShareID != "" || upload.Username != claims.Username {
		sendTusError(w, r, errChunkedUploadNotFound, "", http.StatusNotFound)
		return nil, false
	}
	return upload, true
}

func (s *httpdServer) handleWebClientChunkedUploadCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !r.URL.Query().Has("path") {
		sendTusError(w, r, errors.New("please set a file path"), "", http.StatusBadRequest)
		return
	}
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	filePath := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	s.createChunkedUpload(w, r, connection, filePath, "", webClientChunkedUploadPath)
}

func (s *httpdServer) handleWebClientChunkedUploadHead(w http.ResponseWriter, r *http.Request) {
	if upload, ok := getChunkedUploadForWebClientUser(w, r); ok {
		handleChunkedUploadHead(w, upload)
	}
}

func (s *httpdServer) handleWebClientChunkedUploadStatus(w http.ResponseWriter, r *http.Request) {
	if upload, ok := getChunkedUploadForWebClientUser(w, r); ok {
		handleChunkedUploadStatus(w, r, upload)
	}
}

func (s *httpdServer) handleWebClientChunkedUploadDelete(w http.ResponseWriter, r *http.Request) {
	if upload, ok := getChunkedUploadForWebClientUser(w, r); ok {
		handleChunkedUploadDelete(w, r, upload)
	}
}

func (s *httpdServer) handleWebClientChunkedUploadPatch(w http.ResponseWriter, r *http.Request) {
	upload, ok := getChunkedUploadForWebClientUser(w, r)
	if !ok {
		return
	}
	if !s.writeChunk(w, r, upload) {
		return
	}
	// last chunk received, a new connection is required since the request
	// connection is closed when the handler returns
	connection, err := getUserTaskConnection(w, r)
	if err != nil {
		upload.setResult(err)
		os.Remove(upload.TempFile)
		return
	}
	go upload.finalize(connection)
	w.WriteHeader(http.StatusNoContent)
}

// Public shares handlers

var chunkedUploadShareScopes = []dataprovider.ShareScope{dataprovider.ShareScopeWrite, dataprovider.ShareScopeReadWrite}

func (s *httpdServer) getChunkedUploadForShare(w http.ResponseWriter, r *http.Request,
) (*chunkedUpload, *Connection, bool) {
	share, connection, err := s.checkPublicShareWithOptions(w, r, chunkedUploadShareScopes, true)
	if err != nil {
		return nil, nil, false
	}
	upload := chunkedUploads.get(getURLParam(r, "uploadid"))
	if upload == nil || upload.ShareID != share.ShareID {
		connection.CloseFS() //nolint:errcheck
		sendTusError(w, r, errChunkedUploadNotFound, "", http.StatusNotFound)
		return nil, nil, false
	}
	return upload, connection, true
}

func (s *httpdServer) handleShareChunkedUploadCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, connection, err := s.checkPublicShare(w, r, chunkedUploadShareScopes)
	if err != nil {
		return
	}
	defer connection.CloseFS() //nolint:errcheck

	name := r.URL.Query().Get("name")
	filePath := util.CleanPath(path.Join(share.Paths[0], name))
	expectedPrefix := share.Paths[0]
	if !strings.HasSuffix(expectedPrefix, "/") {
		expectedPrefix += "/"
	}
	if name == "" || !strings.HasPrefix(filePath, expectedPrefix) {
		sendTusError(w, r, errors.New("invalid path"), "Uploading outside the share is not allowed", http.StatusForbidden)
		return
	}
	// one usage token per file, reserved now and released if the upload fails
	if err := dataprovider.UpdateShareLastUse(&share, 1); err != nil {
		sendTusError(w, r, err, "", getRespStatus(err))
		return
	}
	if _, ok := s.createChunkedUpload(w, r, connection, filePath, share.ShareID,
		path.Join(webClientPubSharesPath, share.ShareID, "chunked-upload")); !ok {
		_ = dataprovider.UpdateShareLastUse(&share, -1)
	}
}

func (s *httpdServer) handleShareChunkedUploadHead(w http.ResponseWriter, r *http.Request) {
	upload, connection, ok := s.getChunkedUploadForShare(w, r)
	if !ok {
		return
	}
	defer connection.CloseFS() //nolint:errcheck

	handleChunkedUploadHead(w, upload)
}

func (s *httpdServer) handleShareChunkedUploadStatus(w http.ResponseWriter, r *http.Request) {
	upload, connection, ok := s.getChunkedUploadForShare(w, r)
	if !ok {
		return
	}
	defer connection.CloseFS() //nolint:errcheck

	handleChunkedUploadStatus(w, r, upload)
}

func (s *httpdServer) handleShareChunkedUploadDelete(w http.ResponseWriter, r *http.Request) {
	upload, connection, ok := s.getChunkedUploadForShare(w, r)
	if !ok {
		return
	}
	defer connection.CloseFS() //nolint:errcheck

	handleChunkedUploadDelete(w, r, upload)
}

func (s *httpdServer) handleShareChunkedUploadPatch(w http.ResponseWriter, r *http.Request) {
	upload, connection, ok := s.getChunkedUploadForShare(w, r)
	if !ok {
		return
	}
	if !s.writeChunk(w, r, upload) {
		connection.CloseFS() //nolint:errcheck
		return
	}
	// last chunk, the connection is used in background, without the response controller
	bgConnection := &Connection{
		BaseConnection: connection.BaseConnection,
		request:        r,
	}
	if err := common.Connections.Add(bgConnection); err != nil {
		connection.CloseFS() //nolint:errcheck
		upload.setResult(err)
		os.Remove(upload.TempFile)
		releaseShareToken(upload.ShareID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	go upload.finalize(bgConnection)
	w.WriteHeader(http.StatusNoContent)
}
