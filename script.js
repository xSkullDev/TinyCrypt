// --- UTIL: konversi string <-> byte array ---
function strToBytes(str) {
    const encoder = new TextEncoder();
    return Array.from(encoder.encode(str));
}

function bytesToStr(bytes) {
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

function u32ToBytes(n) {
    return [ (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff ];
}

function bytesToU32(b, offset=0) {
    return ((b[offset] << 24) >>> 0) + ((b[offset+1] << 16) >>> 0) + ((b[offset+2] << 8) >>> 0) + (b[offset+3] >>> 0);
}

// --- PKCS7 padding for block size 8 ---
function pkcs7Pad(bytes, blockSize = 8) {
    const padLen = blockSize - (bytes.length % blockSize);
    const pad = new Array(padLen).fill(padLen);
    return bytes.concat(pad);
}

function pkcs7Unpad(bytes) {
    if (!bytes || bytes.length === 0) return bytes;
    const padLen = bytes[bytes.length - 1];
    // validate padLen
    if (padLen <= 0 || padLen > 8 || padLen > bytes.length) return bytes;
    // verify all padding bytes are equal to padLen
    for (let i = bytes.length - padLen; i < bytes.length; i++) {
        if (bytes[i] !== padLen) return bytes; // invalid padding, return raw
    }
    return bytes.slice(0, bytes.length - padLen);
}

// --- TEA implementation (64-bit block, 128-bit key) ---
// Works on Uint8 arrays. ECB mode for simplicity; we add a simple IV-based chaining externally if needed.
function teaEncryptBlock(v0, v1, k) {
    let sum = 0;
    const delta = 0x9E3779B9 >>> 0;
    for (let i = 0; i < 32; i++) {
        sum = (sum + delta) >>> 0;
        v0 = (v0 + ((((v1 << 4) >>> 0) + k[0]) ^ (v1 + sum) ^ (((v1 >>> 5) >>> 0) + k[1]))) >>> 0;
        v1 = (v1 + ((((v0 << 4) >>> 0) + k[2]) ^ (v0 + sum) ^ (((v0 >>> 5) >>> 0) + k[3]))) >>> 0;
    }
    return [v0 >>> 0, v1 >>> 0];
}

function teaDecryptBlock(v0, v1, k) {
    const delta = 0x9E3779B9 >>> 0;
    let sum = (delta * 32) >>> 0;
    for (let i = 0; i < 32; i++) {
        v1 = (v1 - ((((v0 << 4) >>> 0) + k[2]) ^ (v0 + sum) ^ (((v0 >>> 5) >>> 0) + k[3]))) >>> 0;
        v0 = (v0 - ((((v1 << 4) >>> 0) + k[0]) ^ (v1 + sum) ^ (((v1 >>> 5) >>> 0) + k[1]))) >>> 0;
        sum = (sum - delta) >>> 0;
    }
    return [v0 >>> 0, v1 >>> 0];
}

function keyToUint32s(keyStr) {
    // Convert key string to UTF-8 bytes, ensure exactly 16 bytes (pad with zeros or truncate)
    const kb = strToBytes(keyStr || '');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = kb[i] || 0;
    const k = [];
    for (let i = 0; i < 16; i += 4) k.push(bytesToU32(Array.from(bytes), i));
    return k;
}

// --- helper: base64 <-> bytes ---
function base64ToBytes(b64) {
    try {
        const raw = atob(b64);
        const out = new Array(raw.length);
        for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    } catch (e) {
        return [];
    }
}

function bytesToBase64(bytes) {
    const s = String.fromCharCode(...bytes);
    return btoa(s);
}

function teaEncrypt(plainText, keyStr) {
    const data = pkcs7Pad(strToBytes(plainText), 8);
    const k = keyToUint32s(keyStr);
    const out = [];
    for (let i = 0; i < data.length; i += 8) {
        const v0 = bytesToU32(data, i);
        const v1 = bytesToU32(data, i+4);
        const [e0, e1] = teaEncryptBlock(v0, v1, k);
        out.push(...u32ToBytes(e0), ...u32ToBytes(e1));
    }
    return btoa(String.fromCharCode(...out)); // return base64 ciphertext
}

function teaDecrypt(b64Cipher, keyStr) {
    const raw = atob(b64Cipher);
    const bytes = Array.from(raw, c => c.charCodeAt(0));
    const k = keyToUint32s(keyStr);
    const out = [];
    for (let i = 0; i < bytes.length; i += 8) {
        const v0 = bytesToU32(bytes, i);
        const v1 = bytesToU32(bytes, i+4);
        const [d0, d1] = teaDecryptBlock(v0, v1, k);
        out.push(...u32ToBytes(d0), ...u32ToBytes(d1));
    }
    const unpadded = pkcs7Unpad(out);
    return bytesToStr(unpadded);
}

// --- LSB Steganography ---
// Embed base64 string into imageData using 1 bit per color channel (R,G,B), skip alpha.
// We store a 32-bit length header (number of bytes) followed by the payload bytes.
function lsbEmbed(imageData, payloadBytes) {
    const data = imageData.data;
    const capacity = Math.floor((data.length / 4) * 3 / 8); // bytes
    if (payloadBytes.length + 4 > capacity) throw new Error('Pesan terlalu besar untuk gambar ini.');

    // build bytes sequence: 4-byte length big-endian + payload
    const lenBytes = u32ToBytes(payloadBytes.length);
    const all = lenBytes.concat(payloadBytes);

    let bitIdx = 0;
    for (let i = 0; i < all.length; i++) {
        const byte = all[i];
        for (let b = 7; b >= 0; b--) {
            const bit = (byte >> b) & 1;
            // find the channel to modify: each pixel has R G B A, we use R,G,B (3 bits per pixel)
            const pixel = Math.floor(bitIdx / 3);
            const channel = bitIdx % 3; // 0->R,1->G,2->B
            const idx = pixel * 4 + channel;
            data[idx] = (data[idx] & 0xFE) | bit;
            bitIdx++;
        }
    }
    return imageData;
}

function lsbExtract(imageData) {
    const data = imageData.data;
    const totalBits = Math.floor((data.length / 4) * 3);
    // first read 32-bit length
    let bitIdx = 0;
    function readBits(n) {
        let val = 0;
        for (let i = 0; i < n; i++) {
            const pixel = Math.floor(bitIdx / 3);
            const channel = bitIdx % 3;
            const idx = pixel * 4 + channel;
            const bit = data[idx] & 1;
            val = (val << 1) | bit;
            bitIdx++;
        }
        return val;
    }

    if (totalBits < 32) throw new Error('Gambar terlalu kecil.');
    const len = readBits(32);
    if (len <= 0 || len > Math.floor(totalBits / 8)) throw new Error('Tidak ada pesan yang valid.');
    const bytes = [];
    for (let i = 0; i < len; i++) {
        const b = readBits(8);
        bytes.push(b);
    }
    return bytes;
}

document.getElementById('encryptButton').addEventListener('click', async function() {
    const imageFile = document.getElementById('imageInput').files[0];
    const message = document.getElementById('messageInput').value || '';
    const key = document.getElementById('keyInput').value || '';

    if (!imageFile || message.length === 0 || key.length !== 16) {
        alert('Pilih gambar, masukkan pesan, dan masukkan kunci 16 karakter.');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(ev) {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = async function() {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            try {
                const cipherB64 = teaEncrypt(message, key);
                // convert base64 string to bytes (use helper)
                const payload = base64ToBytes(cipherB64);
                const stego = lsbEmbed(imageData, payload);
                ctx.putImageData(stego, 0, 0);
                const encDataUrl = canvas.toDataURL('image/png');
                // draw to canvases: original from image, encrypted by copying the working canvas to the visible encryptedCanvas
                drawToCanvas(img, 'originalCanvas');
                const visibleEnc = document.getElementById('encryptedCanvas');
                if (visibleEnc) {
                    visibleEnc.width = canvas.width;
                    visibleEnc.height = canvas.height;
                    const vctx = visibleEnc.getContext('2d');
                    vctx.clearRect(0, 0, visibleEnc.width, visibleEnc.height);
                    vctx.drawImage(canvas, 0, 0);
                } else {
                    // fallback: try to set via data URL
                    if (encDataUrl) drawToCanvasDataUrl(encDataUrl, 'encryptedCanvas');
                }
                // fill metadata for original and encrypted
                setImageMeta('metaOriginal', img.width, img.height, imageFileSize(imageFile));
                setImageMeta('metaEncrypted', canvas.width, canvas.height, dataUrlSize(encDataUrl));
                // store original image dataURL in memory for later restoration on decrypt
                try { window.__tinycrypt_original_dataurl = ev.target.result; } catch (e) { /* ignore */ }
                        // compute and show diagram/heatmap/histogram
                        try {
                            // prepare hidden canvas for download using stego data (full resolution)
                            const hidden = document.getElementById('hiddenStegoCanvas');
                            if (hidden) {
                                hidden.width = canvas.width;
                                hidden.height = canvas.height;
                                const hctx = hidden.getContext('2d');
                                hctx.putImageData(stego, 0, 0);
                            }
                            // enable download buttons
                            document.getElementById('downloadStego').disabled = false;
                            // histogram download (renamed)
                            const dlHistBtn = document.getElementById('downloadHistogram');
                            if (dlHistBtn) dlHistBtn.disabled = false;
                            document.getElementById('downloadReport').disabled = false;
                            // draw histograms for original and stego (use hidden full-res stego canvas when available)
                            try {
                                const origVis = document.getElementById('originalCanvas');
                                const visibleEnc = document.getElementById('encryptedCanvas');
                                const hiddenStego = document.getElementById('hiddenStegoCanvas');
                                // prefer hidden full-resolution stego for histogram accuracy
                                if (origVis && hiddenStego && hiddenStego.width > 0 && hiddenStego.height > 0) {
                                    drawBothHistograms(origVis, hiddenStego);
                                } else if (origVis && visibleEnc) {
                                    drawBothHistograms(origVis, visibleEnc);
                                }
                            } catch (e) { console.warn('Histogram draw failed', e); }
                            // store minimal metadata
                            window.__tinycrypt_last_stats = { imageWidth: canvas.width, imageHeight: canvas.height };
                        } catch (e) {
                            console.warn('Histogram generation failed:', e);
                        }
                alert('Pesan berhasil disisipkan ke gambar.');
            } catch (e) {
                alert('Error: ' + e.message);
            }
        };
        // set src after assigning onload to avoid race conditions
        img.src = ev.target.result;
        // try to ensure image fully decoded in browsers that support decode()
        if (img.decode) img.decode().catch(() => {/* ignore decode errors, onload will still fire */});
    };
    reader.readAsDataURL(imageFile);
});

// Download button handlers
document.getElementById('downloadStego').addEventListener('click', function() {
    const hidden = document.getElementById('hiddenStegoCanvas');
    if (!hidden || hidden.width === 0 || hidden.height === 0) {
        alert('Tidak ada gambar stego yang dapat didownload. Silakan lakukan enkripsi terlebih dahulu.');
        return;
    }
    try {
        const url = hidden.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = 'stego.png';
        a.click();
    } catch (e) {
        alert('Gagal membuat file PNG: ' + e.message);
    }
});

document.getElementById('downloadHistogram').addEventListener('click', function() {
    const canvas = document.getElementById('histStego');
    if (!canvas || canvas.width === 0 || canvas.height === 0) { alert('Tidak ada histogram untuk didownload.'); return; }
    try {
        const url = canvas.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = 'histogram_stego.png';
        a.click();
    } catch (e) {
        alert('Gagal membuat file histogram: ' + e.message);
    }
});

// compute luminance histogram (0..255) from a canvas element and return Uint32Array[256]
function computeLumaHistogramFromCanvas(canvas) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    if (!w || !h) return new Uint32Array(256);
    const img = ctx.getImageData(0, 0, w, h).data;
    const hist = new Uint32Array(256);
    for (let i = 0; i < img.length; i += 4) {
        // luminance approximation
        const r = img[i], g = img[i+1], b = img[i+2];
        const l = Math.round(0.2126 * r + 0.7152 * g + 0.0722 * b);
        hist[l]++;
    }
    return hist;
}

function drawHistogramToCanvas(canvasId, hist, color = '#2563eb') {
    const c = document.getElementById(canvasId);
    if (!c) return;
    // ensure pixel width 256 for one-pixel bins, scale to canvas height
    const bins = 256;
    const cssWidth = c.clientWidth || 256;
    const cssHeight = c.clientHeight || 120;
    // set internal canvas resolution BEFORE getting context
    c.width = bins;
    c.height = cssHeight;
    const ctx = c.getContext('2d');
    ctx.clearRect(0, 0, c.width, c.height);
    const max = Math.max(...hist) || 1;
    const H = c.height || cssHeight;
    for (let i = 0; i < bins; i++) {
        const hgt = Math.round((hist[i] / max) * H);
        ctx.fillStyle = color;
        ctx.fillRect(i, H - hgt, 1, hgt);
    }
    // scale back visually via CSS (canvas element will be stretched)
}

function drawBothHistograms(origCanvas, stegoCanvas) {
    // create temporary canvases scaled down to reasonable sample size if needed
    // use full resolution of visual canvases
    const oW = origCanvas.width, oH = origCanvas.height;
    const sW = stegoCanvas.width, sH = stegoCanvas.height;
    // draw to in-memory canvases to ensure we sample pixel data
    const tmpO = document.createElement('canvas'); tmpO.width = oW; tmpO.height = oH; tmpO.getContext('2d').drawImage(origCanvas, 0, 0);
    const tmpS = document.createElement('canvas'); tmpS.width = sW; tmpS.height = sH; tmpS.getContext('2d').drawImage(stegoCanvas, 0, 0);
    const histO = computeLumaHistogramFromCanvas(tmpO);
    const histS = computeLumaHistogramFromCanvas(tmpS);
    drawHistogramToCanvas('histOriginal', histO, '#2563eb');
    drawHistogramToCanvas('histStego', histS, '#10b981');
}

document.getElementById('downloadReport').addEventListener('click', function() {
    const stats = window.__tinycrypt_last_stats;
    if (!stats) { alert('Tidak ada laporan tersedia. Silakan lakukan enkripsi terlebih dahulu.'); return; }
    const payload = JSON.stringify(stats, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'stego_report.json';
    a.click();
    URL.revokeObjectURL(url);
});

document.getElementById('decryptButton').addEventListener('click', function() {
    const imageFile = document.getElementById('imageInput').files[0];
    const key = document.getElementById('keyInput').value || '';
    if (!imageFile || key.length !== 16) { alert('Pilih gambar dan masukkan kunci 16 karakter.'); return; }

    const reader = new FileReader();
    reader.onload = function(ev) {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = async function() {
            // draw the input image to the decrypt input canvas (left side of decrypt row)
            drawToCanvas(img, 'decryptInputCanvas');
            setImageMeta('metaDecryptInput', img.width, img.height, imageFileSize(imageFile));

            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            try {
                const bytes = lsbExtract(imageData);
                const b64 = bytesToBase64(bytes);
                const plain = teaDecrypt(b64, key);
                // draw decrypted (visual) to canvas (right side)
                const decCanvas = document.getElementById('decryptedCanvas');
                if (decCanvas) {
                    decCanvas.width = canvas.width;
                    decCanvas.height = canvas.height;
                    const dctx = decCanvas.getContext('2d');
                    // just show the original image as the visual result (image content is unchanged by LSB)
                    dctx.clearRect(0,0,decCanvas.width, decCanvas.height);
                    dctx.drawImage(img, 0, 0);
                }
                setImageMeta('metaDecrypted', img.width, img.height, imageFileSize(imageFile));
                // show message in textarea
                document.getElementById('messageInput').value = plain;
                // display decrypted key & message in decryptInfo
                const info = document.getElementById('decryptInfo');
                if (info) {
                    info.innerHTML = `<small>Kunci: <strong>${escapeHtml(key)}</strong></small><br><small>Pesan: <strong>${escapeHtml(plain)}</strong></small>`;
                }
                // reveal decrypt row
                const decryptRow = document.getElementById('decryptRow');
                if (decryptRow) decryptRow.style.display = 'flex';
                alert('Pesan berhasil diekstrak.');
            } catch (e) {
                alert('Error: ' + e.message);
            }
        };
        img.src = ev.target.result;
        if (img.decode) img.decode().catch(() => {/* ignore decode errors */});
    };
    reader.readAsDataURL(imageFile);
});

 

// Draw an HTMLImageElement to a canvas by id
function drawToCanvas(imgElem, canvasId) {
    const c = document.getElementById(canvasId);
    if (!c) return;
    c.width = imgElem.naturalWidth;
    c.height = imgElem.naturalHeight;
    const ctx = c.getContext('2d');
    ctx.clearRect(0, 0, c.width, c.height);
    ctx.drawImage(imgElem, 0, 0);
}

// Draw from a dataURL into a canvas
function drawToCanvasDataUrl(dataUrl, canvasId) {
    if (!dataUrl) {
        console.warn('drawToCanvasDataUrl: empty dataUrl for', canvasId);
        return;
    }
    const img = new Image();
    img.onload = function() { drawToCanvas(img, canvasId); };
    img.onerror = function(e) { console.warn('drawToCanvasDataUrl failed to load image', e); };
    img.src = dataUrl;
}

// small helper to escape HTML when inserting into DOM
function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/[&<>"'`]/g, function (c) {
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c];
    });
}

function imageFileSize(file) {
    try { return file.size || 0; } catch (e) { return 0; }
}

function dataUrlSize(dataUrl) {
    if (!dataUrl) return 0;
    const idx = dataUrl.indexOf(',');
    if (idx === -1) return 0;
    const meta = dataUrl.substring(0, idx);
    const isBase64 = meta.indexOf(';base64') !== -1;
    const data = dataUrl.substring(idx + 1);
    if (isBase64) {
        const padding = (data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0);
        return Math.floor((data.length * 3) / 4) - padding;
    }
    return decodeURIComponent(data).length;
}

function setImageMeta(elementId, width, height, byteSize) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const kb = (byteSize / 1024).toFixed(1);
    el.innerHTML = `<small>Ukuran: ${width}×${height}px • ${kb} KB</small>`;
}
