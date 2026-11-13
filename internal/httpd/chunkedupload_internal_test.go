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

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestChunkedUpload(t *testing.T, dir string, size int64) *chunkedUpload {
	u := &chunkedUpload{
		ID:           generateChunkedUploadID(),
		Username:     "user",
		VirtualPath:  "/file.bin",
		Size:         size,
		LastActivity: time.Now(),
		State:        chunkedUploadStateUploading,
	}
	u.TempFile = filepath.Join(dir, u.ID+chunkedUploadTempSuffix)
	require.NoError(t, os.WriteFile(u.TempFile, nil, 0600))
	return u
}

func TestChunkedUploadManagerLimitsAndCleanup(t *testing.T) {
	dir := t.TempDir()
	m := newChunkedUploadManager()

	for i := 0; i < maxPendingChunkedUploadsOwner; i++ {
		status, err := m.add(newTestChunkedUpload(t, dir, 10), dir)
		require.NoError(t, err)
		require.Equal(t, 0, status)
	}
	status, err := m.add(newTestChunkedUpload(t, dir, 10), dir)
	assert.Error(t, err)
	assert.Equal(t, http.StatusTooManyRequests, status)
	// another owner is not limited
	other := newTestChunkedUpload(t, dir, 10)
	other.ShareID = "share"
	_, err = m.add(other, dir)
	assert.NoError(t, err)

	tooBig := newTestChunkedUpload(t, dir, 1<<60)
	tooBig.Username = "another"
	status, err = m.add(tooBig, dir)
	assert.Error(t, err)
	assert.Equal(t, http.StatusInsufficientStorage, status)

	// abandoned uploads are removed together with their temporary file
	abandoned := newTestChunkedUpload(t, dir, 10)
	abandoned.Username = "abandoned"
	abandoned.LastActivity = time.Now().Add(-chunkedUploadIdleExpiration - time.Minute)
	_, err = m.add(abandoned, dir)
	require.NoError(t, err)
	// completed uploads are kept for a while so the client can read the result
	completed := newTestChunkedUpload(t, dir, 10)
	completed.Username = "completed"
	completed.State = chunkedUploadStateCompleted
	_, err = m.add(completed, dir)
	require.NoError(t, err)
	oldCompleted := newTestChunkedUpload(t, dir, 10)
	oldCompleted.Username = "completed"
	oldCompleted.State = chunkedUploadStateFailed
	oldCompleted.LastActivity = time.Now().Add(-chunkedUploadResultRetention - time.Minute)
	_, err = m.add(oldCompleted, dir)
	require.NoError(t, err)

	m.cleanup()
	assert.Nil(t, m.get(abandoned.ID))
	assert.NoFileExists(t, abandoned.TempFile)
	assert.NotNil(t, m.get(completed.ID))
	assert.Nil(t, m.get(oldCompleted.ID))
	assert.NotNil(t, m.get(other.ID))
}

func TestChunkedUploadSetTempPath(t *testing.T) {
	dir := t.TempDir()
	ours := filepath.Join(dir, "abc"+chunkedUploadTempSuffix)
	notOurs := filepath.Join(dir, "important.txt")
	require.NoError(t, os.WriteFile(ours, []byte("x"), 0600))
	require.NoError(t, os.WriteFile(notOurs, []byte("x"), 0600))

	m := newChunkedUploadManager()
	m.setTempPath(dir)
	assert.NoFileExists(t, ours)
	assert.FileExists(t, notOurs)
	p, err := m.getTempPath()
	assert.NoError(t, err)
	assert.Equal(t, filepath.Clean(dir), p)
}

func TestChunkedUploadWriteChunk(t *testing.T) {
	dir := t.TempDir()
	s := &httpdServer{binding: Binding{UploadChunkSize: 1}}
	data := bytes.Repeat([]byte("a"), 1024*1024+100)
	u := newTestChunkedUpload(t, dir, int64(len(data)))

	patch := func(body []byte, offset int64, contentType string) (*httptest.ResponseRecorder, bool) {
		r := httptest.NewRequest(http.MethodPatch, "/upload", bytes.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		r.Header.Set(tusUploadOffsetHeader, strconv.FormatInt(offset, 10))
		rr := httptest.NewRecorder()
		done := s.writeChunk(rr, r, u)
		return rr, done
	}

	rr, done := patch(data[:10], 0, "application/octet-stream")
	assert.False(t, done)
	assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code)

	rr, done = patch(data[:1024*1024+1], 0, tusContentType)
	assert.False(t, done)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)

	rr, done = patch(data[:1024*1024], 0, tusContentType)
	assert.False(t, done)
	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, fmt.Sprint(1024*1024), rr.Header().Get(tusUploadOffsetHeader))

	rr, done = patch(data[1024*1024:], 10, tusContentType)
	assert.False(t, done)
	assert.Equal(t, http.StatusConflict, rr.Code)

	_, done = patch(data[1024*1024:], 1024*1024, tusContentType)
	assert.True(t, done)
	assert.Equal(t, chunkedUploadStateProcessing, u.State)

	rr, done = patch([]byte("x"), int64(len(data)), tusContentType)
	assert.False(t, done)
	assert.Equal(t, http.StatusConflict, rr.Code)

	stored, err := os.ReadFile(u.TempFile)
	require.NoError(t, err)
	assert.Equal(t, data, stored)
}
