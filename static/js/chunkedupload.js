/*
 * Copyright (C) 2026 Lucas Joblin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, version 3.
 *
 * Resumable chunked uploads for the SFTPGo WebClient and public shares.
 * It implements the client side of the tus 1.0.0 subset exposed by SFTPGo
 * (creation, PATCH, HEAD, termination) plus the SFTPGo status endpoint used
 * to wait for the file to be moved to the storage backend.
 *
 * Each chunk is sent in a separate request so uploads work behind proxies
 * limiting the request body size (e.g. Cloudflare, 100 MB on free plans).
 */
"use strict";

var SFTPGoChunkedUpload = (function () {
    const TUS_VERSION = "1.0.0";
    const RETRY_DELAYS = [1000, 3000, 5000, 10000, 20000, 30000];
    const STATUS_POLL_INTERVAL = 1500;

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    function makeError(status, message) {
        let err = new Error(message || "upload failed");
        err.response = { status: status || 0 };
        return err;
    }

    function getStatus(error) {
        if (error && error.response && error.response.status) {
            return error.response.status;
        }
        return 0;
    }

    // errors that will not be fixed retrying the same request
    function isFatal(status) {
        return status >= 400 && status < 500 && status !== 409 && status !== 423 && status !== 429;
    }

    function create(opts) {
        let headers = Object.assign({}, opts.headers, {
            "Tus-Resumable": TUS_VERSION,
            "Upload-Length": String(opts.file.size)
        });
        return axios.post(opts.createURL, null, {
            headers: headers,
            validateStatus: function (status) {
                return status === 201;
            }
        }).then(function (response) {
            let location = response.headers["location"];
            if (!location) {
                throw makeError(500, "missing upload location");
            }
            return new URL(location, new URL(opts.createURL, window.location.href)).href;
        });
    }

    function getOffset(uploadURL, opts) {
        return axios.head(uploadURL, {
            headers: Object.assign({}, opts.headers, { "Tus-Resumable": TUS_VERSION }),
            validateStatus: function (status) {
                return status === 200;
            }
        }).then(function (response) {
            let offset = parseInt(response.headers["upload-offset"], 10);
            if (isNaN(offset)) {
                throw makeError(500, "invalid upload offset");
            }
            return offset;
        });
    }

    function sendChunk(uploadURL, offset, opts) {
        let end = Math.min(offset + opts.chunkSize, opts.file.size);
        // the content type is set on the blob too, some axios adapters derive the header from it
        let chunk = opts.file.slice(offset, end, "application/offset+octet-stream");
        return axios.patch(uploadURL, chunk, {
            headers: Object.assign({}, opts.headers, {
                "Tus-Resumable": TUS_VERSION,
                "Upload-Offset": String(offset),
                "Content-Type": "application/offset+octet-stream"
            }),
            onUploadProgress: function (progressEvent) {
                if (opts.onProgress) {
                    opts.onProgress(Math.min(offset + progressEvent.loaded, opts.file.size), opts.file.size);
                }
            },
            validateStatus: function (status) {
                return status === 204;
            }
        }).then(function (response) {
            let newOffset = parseInt(response.headers["upload-offset"], 10);
            if (isNaN(newOffset)) {
                throw makeError(500, "invalid upload offset");
            }
            return newOffset;
        });
    }

    async function waitForStorage(uploadURL, opts) {
        let errors = 0;
        for (;;) {
            await sleep(STATUS_POLL_INTERVAL);
            let data;
            try {
                let response = await axios.get(uploadURL, {
                    headers: opts.headers,
                    validateStatus: function (status) {
                        return status === 200;
                    }
                });
                data = response.data;
                errors = 0;
            } catch (error) {
                errors++;
                if (isFatal(getStatus(error)) || errors > RETRY_DELAYS.length) {
                    throw error;
                }
                continue;
            }
            if (data.status === "completed") {
                return;
            }
            if (data.status === "failed") {
                throw makeError(data.error_code || 500, data.error);
            }
        }
    }

    async function upload(opts) {
        let uploadURL = await create(opts);
        let offset = 0;
        let retries = 0;
        let first = true;

        try {
            while (first || offset < opts.file.size) {
                first = false;
                try {
                    offset = await sendChunk(uploadURL, offset, opts);
                    retries = 0;
                } catch (error) {
                    let status = getStatus(error);
                    if (isFatal(status) || retries >= RETRY_DELAYS.length) {
                        throw error;
                    }
                    await sleep(RETRY_DELAYS[retries]);
                    retries++;
                    // resume from the offset stored on the server
                    offset = await getOffset(uploadURL, opts);
                    first = offset === 0 && opts.file.size === 0;
                }
            }
        } catch (error) {
            // best effort, free the server side resources
            axios.delete(uploadURL, {
                headers: Object.assign({}, opts.headers, { "Tus-Resumable": TUS_VERSION })
            }).catch(function () {});
            throw error;
        }

        if (opts.onProcessing) {
            opts.onProcessing();
        }
        await waitForStorage(uploadURL, opts);
    }

    return {
        /**
         * Uploads a file in chunks.
         * opts: {
         *   createURL: upload creation URL including the target path query parameters,
         *   file: the File/Blob to upload,
         *   chunkSize: chunk size in bytes,
         *   headers: additional headers sent with each request (CSRF token, mtime),
         *   onProgress(loaded, total): optional progress callback,
         *   onProcessing(): optional, called when all the chunks are uploaded and
         *                   the server is moving the file to the storage backend
         * }
         * Returns a Promise, on error the rejection value has a response.status
         * property as axios errors.
         */
        upload: upload
    };
})();
