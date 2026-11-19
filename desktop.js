(function () {
    'use strict';

    var fs = require('fs');
    var path = require('path');
    var os = require('os');
    var http = require('http');
    var https = require('https');
    var crypto = require('crypto');

    var DESKTOP_PATH = path.join(os.homedir(), 'Desktop');

    // QR Session State
    var qrServer = null;
    var qrSessionId = '';
    var qrPendingScans = [];
    var qrScannedCodes = new Set();
    var qrRepName = '';
    var qrPort = 0;
    var qrSessionData = [];
    var qrCloseRequested = false;

    function getLocalIP() {
        var interfaces = os.networkInterfaces();
        var keys = Object.keys(interfaces);
        for (var i = 0; i < keys.length; i++) {
            var ifaces = interfaces[keys[i]];
            for (var j = 0; j < ifaces.length; j++) {
                var iface = ifaces[j];
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
        return '127.0.0.1';
    }

    function findAvailablePort(startPort) {
        return new Promise(function (resolve, reject) {
            var net = require('net');
            var server = net.createServer();
            server.listen(startPort, function () {
                var port = server.address().port;
                server.close(function () { resolve(port); });
            });
            server.on('error', function () {
                resolve(findAvailablePort(startPort + 1));
            });
        });
    }

    function escapeHtml(str) {
        return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function readBody(req) {
        return new Promise(function (resolve) {
            var body = '';
            req.on('data', function (chunk) { body += chunk; });
            req.on('end', function () { resolve(body); });
        });
    }

    function sendJson(res, status, data) {
        res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify(data));
    }

    function sendHtml(res, html) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
        res.end(html);
    }

    // ===================== SELF-SIGNED CERT GENERATION =====================
    function asn1Tag(tag, content) {
        var len = content.length;
        var lenBytes;
        if (len < 128) lenBytes = Buffer.from([len]);
        else if (len < 256) lenBytes = Buffer.from([0x81, len]);
        else if (len < 65536) lenBytes = Buffer.from([0x82, (len >> 8) & 0xFF, len & 0xFF]);
        else lenBytes = Buffer.from([0x83, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF]);
        return Buffer.concat([Buffer.from([tag]), lenBytes, content]);
    }
    function asn1Sequence(contents) { return asn1Tag(0x30, Buffer.concat(contents)); }
    function asn1Integer(buf) {
        var b = buf;
        while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
        if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
        return asn1Tag(0x02, b);
    }
    function asn1OID(oid) {
        var parts = oid.split('.').map(Number);
        var buf = [40 * parts[0] + parts[1]];
        for (var i = 2; i < parts.length; i++) {
            var v = parts[i];
            var enc = [];
            do { enc.unshift((v & 0x7F) | (enc.length ? 0x80 : 0)); v >>= 7; } while (v > 0);
            buf = buf.concat(enc);
        }
        return asn1Tag(0x06, Buffer.from(buf));
    }
    function asn1BitString(buf) { return asn1Tag(0x03, Buffer.concat([Buffer.from([0x00]), buf])); }
    function asn1UTF8String(s) { return asn1Tag(0x0C, Buffer.from(s, 'utf8')); }
    function asn1PrintableString(s) { return asn1Tag(0x13, Buffer.from(s, 'ascii')); }
    function asn1Null() { return Buffer.from([0x05, 0x00]); }
    function asn1Explicit(tag, content) { return asn1Tag(0xA0 | tag, content); }
    function asn1Explicit3(content) { return asn1Tag(0xA3, content); }
    function buildPEM(label, der) {
        var b64 = der.toString('base64');
        var lines = [];
        for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
        return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----\n';
    }
    function rsaOID() {
        return asn1Sequence([asn1OID('1.2.840.113549.1.1.1'), asn1Null()]);
    }
    function sha256WithRSAOID() {
        return asn1Sequence([asn1OID('1.2.840.113549.1.1.11'), asn1Null()]);
    }
    function buildName() {
        var cn = asn1Sequence([asn1OID('2.5.4.3'), asn1UTF8String('QR Session Server')]);
        var set = asn1Tag(0x31, cn);
        return asn1Sequence([set]);
    }
    function buildValidity(notBefore, notAfter) {
        function toUTCTime(d) {
            var s = d.getUTCFullYear().toString().slice(2) +
                ('0' + (d.getUTCMonth() + 1)).slice(-2) +
                ('0' + d.getUTCDate()).slice(-2) +
                ('0' + d.getUTCHours()).slice(-2) +
                ('0' + d.getUTCMinutes()).slice(-2) +
                ('0' + d.getUTCSeconds()).slice(-2) + 'Z';
            return asn1Tag(0x17, Buffer.from(s));
        }
        return asn1Sequence([toUTCTime(notBefore), toUTCTime(notAfter)]);
    }
    function generateSelfSignedCert() {
        var keys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'der' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        var serialBuf = crypto.randomBytes(8);
        serialBuf[0] &= 0x7F;
        var now = new Date();
        var expiry = new Date(now.getTime() + 10 * 365 * 24 * 60 * 60 * 1000);
        var tbs = asn1Sequence([
            asn1Explicit(0, asn1Integer(Buffer.from([2]))),
            asn1Integer(serialBuf),
            sha256WithRSAOID(),
            buildName(),
            buildValidity(now, expiry),
            buildName(),
            keys.publicKey
        ]);
        var sign = crypto.createSign('sha256');
        sign.update(tbs);
        var sig = sign.sign(keys.privateKey);
        var cert = asn1Sequence([tbs, sha256WithRSAOID(), asn1BitString(sig)]);
        return { cert: buildPEM('CERTIFICATE', cert), key: keys.privateKey };
    }

    var desktopAPI = {
        isDesktopApp: true,

        // ===================== FILE OPERATIONS =====================

        saveExcelToDesktop: function (opts) {
            try {
                var filePath = path.join(DESKTOP_PATH, opts.name);
                fs.writeFileSync(filePath, Buffer.from(opts.data));
                return Promise.resolve({ success: true, path: filePath });
            } catch (err) {
                return Promise.resolve({ success: false, message: err.message });
            }
        },

        readFileAsBuffer: function (opts) {
            try {
                if (!opts.path) return Promise.resolve({ success: false, message: 'No path provided' });
                var data = fs.readFileSync(opts.path);
                return Promise.resolve({ success: true, data: new Uint8Array(data) });
            } catch (err) {
                return Promise.resolve({ success: false, message: err.message });
            }
        },

        saveToOriginalPath: function (opts) {
            try {
                if (!opts.path) return Promise.resolve({ success: false, message: 'No path provided' });
                fs.writeFileSync(opts.path, Buffer.from(opts.data));
                return Promise.resolve({ success: true, path: opts.path });
            } catch (err) {
                return Promise.resolve({ success: false, message: err.message });
            }
        },

        exportToRepsFolder: function (files) {
            try {
                var folderPath = path.join(DESKTOP_PATH, 'المناديب');
                if (!fs.existsSync(folderPath)) {
                    fs.mkdirSync(folderPath, { recursive: true });
                }
                for (var i = 0; i < files.length; i++) {
                    var f = files[i];
                    fs.writeFileSync(path.join(folderPath, f.name), Buffer.from(f.data));
                }
                return Promise.resolve({ success: true });
            } catch (err) {
                return Promise.resolve({ success: false, message: err.message });
            }
        },

        exportToSendersFolder: function (files) {
            try {
                var folderPath = path.join(DESKTOP_PATH, 'الراسلين');
                if (!fs.existsSync(folderPath)) {
                    fs.mkdirSync(folderPath, { recursive: true });
                }
                for (var i = 0; i < files.length; i++) {
                    var f = files[i];
                    fs.writeFileSync(path.join(folderPath, f.name), Buffer.from(f.data));
                }
                return Promise.resolve({ success: true });
            } catch (err) {
                return Promise.resolve({ success: false, message: err.message });
            }
        },

        // ===================== WINDOW MANAGEMENT =====================

        getWindow: function () {
            return typeof nw !== 'undefined' && nw.Window ? nw.Window.get() : null;
        },

        onRequestCloseDialog: function (callback) {
            var win = this.getWindow();
            if (!win) { console.warn('[Desktop] nw.Window not available'); return; }
            win.on('close', function () {
                callback();
            });
            desktopAPI.forceClose = function () {
                win.close(true);
            };
        },

        forceClose: function () {
            var win = this.getWindow();
            if (win) win.close(true);
        },

        // ===================== QR SESSION =====================

        startQrSession: function (opts) {
            return Promise.resolve().then(function () {
                if (qrServer) {
                    return desktopAPI.stopQrSession();
                }
            }).then(function () {
                qrRepName = opts.repName || '';
                qrSessionData = opts.rows || [];
                qrPendingScans = [];
                qrScannedCodes = new Set();
                qrCloseRequested = false;
                qrSessionId = crypto.randomUUID ? crypto.randomUUID() : (Math.random().toString(36).slice(2) + Date.now().toString(36));

                var tlsCreds = generateSelfSignedCert();

                return findAvailablePort(3000).then(function (port) {
                    qrPort = port;
                    var localIP = getLocalIP();
                    var sessionUrl = 'https://' + localIP + ':' + qrPort + '/scan/' + qrSessionId;

                    qrServer = https.createServer({ key: tlsCreds.key, cert: tlsCreds.cert }, function (req, res) {
                        res.setHeader('Access-Control-Allow-Origin', '*');
                        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
                        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

                        if (req.method === 'OPTIONS') {
                            res.writeHead(204);
                            res.end();
                            return;
                        }

                        var urlParts = req.url.split('/');
                        // /scan/{sessionId} or /scan/{sessionId}/submit or /scan/{sessionId}/state

                        if (req.method === 'GET' && urlParts[1] === 'scan' && urlParts[2] === qrSessionId && !urlParts[3]) {
                            sendHtml(res, getPhoneScanPage());
                        } else if (req.method === 'POST' && urlParts[1] === 'scan' && urlParts[2] === qrSessionId && urlParts[3] === 'submit') {
                            handleScanSubmit(req, res);
                        } else if (req.method === 'GET' && urlParts[1] === 'scan' && urlParts[2] === qrSessionId && urlParts[3] === 'state') {
                            sendJson(res, 200, {
                                active: true,
                                phoneConnected: true,
                                scanCount: qrScannedCodes.size,
                                repName: qrRepName
                            });
                        } else {
                            res.writeHead(404);
                            res.end('Not found');
                        }
                    });

                    return new Promise(function (resolve, reject) {
                        qrServer.listen(qrPort, function () {
                            resolve({ url: sessionUrl, port: qrPort, sessionId: qrSessionId });
                        });
                        qrServer.on('error', function (err) { reject(err); });
                    });
                });
            });
        },

        getQrSessionState: function () {
            if (!qrServer) return Promise.resolve({ active: false });
            var phoneConnected = qrPendingScans.length > 0 || qrScannedCodes.size > 0;
            return Promise.resolve({
                active: true,
                phoneConnected: phoneConnected,
                scanCount: qrScannedCodes.size,
                repName: qrRepName,
                warning: qrCloseRequested ? 'انتهت الجلسة. افتح QR من جديد.' : ''
            });
        },

        getQrPendingScans: function () {
            var scans = qrPendingScans.slice(0);
            qrPendingScans = [];
            return Promise.resolve(scans.map(function (s) { return { row: s.row }; }));
        },

        stopQrSession: function () {
            return new Promise(function (resolve) {
                if (qrServer) {
                    try { qrServer.close(); } catch (e) { }
                    qrServer = null;
                }
                qrSessionId = '';
                qrPendingScans = [];
                qrScannedCodes = new Set();
                resolve({ success: true });
            });
        },

        checkQrSaveRequest: function () {
            return Promise.resolve({ saveRequested: false });
        }
    };

    function getPhoneScanPage() {
        var repName = escapeHtml(qrRepName);
        var totalCount = qrSessionData.length;
        return '<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"><title>مسح - ' + repName + '</title><style>' +
            '*{margin:0;padding:0;box-sizing:border-box}' +
            'body{font-family:Tahoma,Arial,sans-serif;background:#0f172a;color:#f8fafc;padding:12px;direction:rtl}' +
            'h1{font-size:1.1rem;text-align:center;color:#3b82f6;margin-bottom:4px}' +
            '.sub{text-align:center;color:#94a3b8;font-size:0.8rem;margin-bottom:10px}' +
            '.warning-box{background:#1e293b;border:1px solid #f59e0b;border-radius:10px;padding:8px 12px;margin-bottom:10px;font-size:0.75rem;color:#fbbf24;text-align:center}' +
            '#videoWrap{position:relative;background:#000;border-radius:12px;overflow:hidden;margin-bottom:10px}' +
            '#videoWrap video{width:100%;display:block}' +
            '#scanOverlay{position:absolute;top:0;left:0;right:0;bottom:0;border:3px solid rgba(59,130,246,0.5);border-radius:12px;pointer-events:none}' +
            '#scanOverlay::after{content:"";position:absolute;top:50%;left:10%;right:10%;height:2px;background:#3b82f6;opacity:0.6}' +
            '.scan-box{background:#1e293b;border-radius:12px;padding:12px;margin-bottom:10px}' +
            '.scan-input-wrap{display:flex;gap:8px}' +
            '#codeInput{flex:1;padding:10px;border-radius:8px;border:2px solid #334155;background:#0f172a;color:#f8fafc;font-size:0.95rem;text-align:center}' +
            '#codeInput:focus{border-color:#3b82f6;outline:none}' +
            '#scanBtn{padding:10px 20px;border-radius:8px;background:#3b82f6;color:#fff;border:none;font-size:0.95rem;font-weight:bold;cursor:pointer;white-space:nowrap}' +
            '#scanBtn:active{background:#1d4ed8}' +
            '.camera-btn{display:block;width:100%;padding:10px;border-radius:8px;background:#10b981;color:#fff;border:none;font-size:0.95rem;font-weight:bold;cursor:pointer;margin-bottom:10px;text-align:center}' +
            '.camera-btn:active{background:#059669}' +
            '.camera-btn.off{background:#6b7280}' +
            '#result{text-align:center;font-size:0.9rem;margin-top:8px;min-height:24px}' +
            '.count-badge{text-align:center;color:#94a3b8;font-size:0.8rem;margin-top:6px}' +
            '#scannedList{margin-top:8px}' +
            '.scanned-item{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:8px 10px;margin:4px 0;display:flex;justify-content:space-between;align-items:center}' +
            '.scanned-item .code{color:#3b82f6;font-weight:bold;font-size:0.8rem}' +
            '.scanned-item .info{color:#f8fafc;font-size:0.85rem}' +
            '.scanned-item .time{color:#6b7280;font-size:0.7rem}' +
            '#camOffBtn{position:absolute;top:6px;left:6px;z-index:10;background:rgba(0,0,0,0.6);color:#fff;border:none;border-radius:50%;width:28px;height:28px;font-size:14px;cursor:pointer}' +
            '</style></head><body>' +
            '<h1>مسح الشحنات</h1>' +
            '<div class="sub">المندوب: ' + repName + ' | ' + totalCount + ' شحنة</div>' +
            '<div class="warning-box">🔒 اتصال مشفر (HTTPS). سيظهر تحذير "اتصال غير خاص" - اضغط على "متابعة" أو "تخطي" لتأكيد الدخول، ثم اسمح بتشغيل الكاميرا.</div>' +
            '<div id="videoWrap" style="display:none">' +
            '<button id="camOffBtn" type="button">✕</button>' +
            '<video id="video" playsinline autoplay muted></video>' +
            '<div id="scanOverlay"></div>' +
            '</div>' +
            '<button id="camToggleBtn" class="camera-btn">📷 تشغيل الكاميرا للمسح التلقائي</button>' +
            '<div class="scan-box">' +
            '<div class="scan-input-wrap">' +
            '<input type="text" id="codeInput" placeholder="ادخل كود الشحنة يدوياً..." autofocus>' +
            '<button id="scanBtn">مسح</button>' +
            '</div>' +
            '<div id="result"></div>' +
            '<div class="count-badge">تم المسح: <strong id="scanCount">0</strong></div>' +
            '</div>' +
            '<div id="scannedList"></div>' +
            '<script>' +
            'var sc=0;var scanTimer=null;var stream=null;var scannedLocally=new Set();' +
            'function submitCode(c){c=c||document.getElementById("codeInput").value.trim();if(!c)return;' +
            'if(scannedLocally.has(c)){document.getElementById("codeInput").value="";return;}' +
            'fetch("/scan/' + qrSessionId + '/submit",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:c})})' +
            '.then(function(r){return r.json()}).then(function(d){' +
            'scannedLocally.add(c);' +
            'if(d.found){sc++;document.getElementById("scanCount").innerText=sc;' +
            'document.getElementById("result").innerHTML="<span style=\'color:#10b981;font-weight:bold\'>&#10003; "+c+" - "+(d.row.customerName||"")+"</span>";' +
            'var el=document.createElement("div");el.className="scanned-item";' +
            'var t=new Date().toLocaleTimeString("ar-SA",{hour:"2-digit",minute:"2-digit"});' +
            'el.innerHTML="<span class=\'info\'>"+(d.row.customerName||"")+"</span><span class=\'code\'>"+c+" <span class=\'time\'>"+t+"</span></span>";' +
            'document.getElementById("scannedList").prepend(el);' +
            'if(stream){navigator.vibrate&&navigator.vibrate(200);}' +
            '}else{' +
            'document.getElementById("result").innerHTML="<span style=\'color:#ef4444\'>✗ "+c+" - كود غير موجود في قاعدة البيانات</span>";' +
            '}' +
            'document.getElementById("codeInput").value="";document.getElementById("codeInput").focus()' +
            '}).catch(function(){document.getElementById("result").innerHTML="<span style=\'color:#ef4444\'>خطأ في الاتصال بالخادم</span>"})}' +
            'function startCamera(){' +
            'if(stream){return;}' +
            'document.getElementById("result").innerHTML="<span style=\'color:#94a3b8\'>جاري تشغيل الكاميرا...</span>";' +
            'if(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia){' +
            'navigator.mediaDevices.getUserMedia({video:{facingMode:"environment",width:{ideal:640},height:{ideal:480}}}).then(function(s){' +
            'stream=s;var v=document.getElementById("video");v.srcObject=s;v.play();' +
            'document.getElementById("videoWrap").style.display="block";' +
            'document.getElementById("camToggleBtn").className="camera-btn off";' +
            'document.getElementById("camToggleBtn").innerHTML="📷 إيقاف الكاميرا";' +
            'document.getElementById("result").innerHTML="<span style=\'color:#10b981\'>الكاميرا تعمل. وجّه الكاميرا إلى الباركود على الشحنة.</span>";' +
            'startBarcodeScanning();' +
            '}).catch(function(e){' +
            'document.getElementById("result").innerHTML="<span style=\'color:#ef4444\'>تعذر تشغيل الكاميرا: "+(e.message||"")+". استخدم الإدخال اليدوي.</span>";' +
            '})}else{' +
            'document.getElementById("result").innerHTML="<span style=\'color:#ef4444\'>المتصفح لا يدعم الكاميرا. استخدم الإدخال اليدوي.</span>";' +
            '}}' +
            'function stopCamera(){' +
            'if(scanTimer){cancelAnimationFrame(scanTimer);scanTimer=null;}' +
            'if(stream){stream.getTracks().forEach(function(t){t.stop()});stream=null;}' +
            'document.getElementById("videoWrap").style.display="none";' +
            'document.getElementById("camToggleBtn").className="camera-btn";' +
            'document.getElementById("camToggleBtn").innerHTML="📷 تشغيل الكاميرا للمسح التلقائي";' +
            '}' +
            'function startBarcodeScanning(){' +
            'var v=document.getElementById("video");' +
            'if(!v||!v.videoWidth){scanTimer=requestAnimationFrame(startBarcodeScanning);return;}' +
            'if("BarcodeDetector" in window){' +
            'var fmts;try{fmts=["qr_code","ean_13","code_128","code_39","aztec","pdf417"];new BarcodeDetector({formats:fmts})}catch(e){fmts=void 0}' +
            'var detector=new BarcodeDetector({formats:fmts});' +
            'var lastCode="";var lastTime=0;' +
            '(function scan(){scanTimer=requestAnimationFrame(scan);' +
            'if(!stream||!v.videoWidth)return;' +
            'detector.detect(v).then(function(barcodes){' +
            'if(barcodes.length>0){' +
            'var code=barcodes[0].rawValue.trim();' +
            'var now=Date.now();' +
            'if(code&&code!==lastCode||now-lastTime>3000){' +
            'lastCode=code;lastTime=now;' +
            'submitCode(code);' +
            '}' +
            '}else{lastCode="";}' +
            '}).catch(function(){});' +
            '})();' +
            '}else{' +
            'document.getElementById("result").innerHTML="<span style=\'color:#f59e0b\'>المتصفح لا يدعم المسح التلقائي. استخدم الإدخال اليدوي.</span>";' +
            '}}' +
            'document.getElementById("scanBtn").onclick=function(){submitCode()};' +
            'document.getElementById("codeInput").onkeydown=function(e){if(e.key==="Enter")submitCode()};' +
            'document.getElementById("camToggleBtn").onclick=function(){if(stream){stopCamera()}else{startCamera()}};' +
            'document.getElementById("camOffBtn").onclick=function(){stopCamera()};' +
            '<\/script></body></html>';
    }

    function handleScanSubmit(req, res) {
        readBody(req).then(function (body) {
            try {
                var data = JSON.parse(body);
                var code = (data.code || '').trim();
                if (!code || qrScannedCodes.has(code)) {
                    sendJson(res, 200, { found: false, duplicate: !!qrScannedCodes.has(code) });
                    return;
                }
                var found = null;
                for (var i = 0; i < qrSessionData.length; i++) {
                    if (qrSessionData[i].code === code) { found = qrSessionData[i]; break; }
                }
                if (found) {
                    qrScannedCodes.add(code);
                    qrPendingScans.push({ code: code, row: found, time: Date.now() });
                    sendJson(res, 200, { found: true, row: found });
                } else {
                    sendJson(res, 200, { found: false });
                }
            } catch (e) {
                sendJson(res, 400, { error: 'Invalid JSON' });
            }
        });
    }

    window.desktopAPI = desktopAPI;
    console.log('[Desktop] NW.js API initialized');
})();
