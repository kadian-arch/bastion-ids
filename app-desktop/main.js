import { app, BrowserWindow, shell, ipcMain, dialog } from 'electron';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import net from 'net';
import http from 'http';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
let backendProcess = null;
let win = null;   // module-level so ipcMain handlers can reference it

// ── Startup logging (diagnoses launch failures on clean machines/VMs) ───────
const LAUNCH_LOG   = path.join(os.tmpdir(), 'BastionIDS-launch.log');
const BACKEND_LOG  = path.join(os.tmpdir(), 'BastionIDS-backend.log');
function logLaunch(msg) {
  try {
    fs.appendFileSync(LAUNCH_LOG,
      `[${new Date().toISOString()}] ${msg}\n`);
  } catch { /* never let logging crash the app */ }
}
// Clear the backend log each launch so it only contains the current session.
try { fs.writeFileSync(BACKEND_LOG, `=== Backend log ${new Date().toISOString()} ===\n`); } catch {}
logLaunch(`=== Bastion IDS launch | packaged=${app.isPackaged} | ` +
          `platform=${process.platform} ${os.release()} | electron=${process.versions.electron} ===`);
process.on('uncaughtException',  (e) => logLaunch('UNCAUGHT: ' + (e && e.stack || e)));
process.on('unhandledRejection', (e) => logLaunch('UNHANDLED REJECTION: ' + (e && e.stack || e)));

// VMs / Windows Server / RDP sessions frequently have no usable GPU, which can
// stop the Electron (Chromium) window from ever appearing. Software rendering
// is reliable everywhere and costs nothing for this UI.
try { app.disableHardwareAcceleration(); } catch { /* ignore */ }
app.commandLine.appendSwitch('disable-gpu');
app.commandLine.appendSwitch('disable-software-rasterizer');

const BACKEND_PORT = 48217;            // Bastion API (uncommon, conflict-safe)
const BACKEND_URL  = `http://127.0.0.1:${BACKEND_PORT}`;
const DEV_URL      = 'http://localhost:48218';   // Vite dev server (development only)

/** TCP check — just tells us if something is bound to the port already. */
function isPortOpen() {
  return new Promise((resolve) => {
    const client = new net.Socket();
    client.setTimeout(800);
    client.connect(BACKEND_PORT, '127.0.0.1', () => { client.destroy(); resolve(true); });
    client.on('error',   () => { client.destroy(); resolve(false); });
    client.on('timeout', () => { client.destroy(); resolve(false); });
  });
}

/**
 * HTTP check — confirms the backend is actually serving HTTP responses.
 * The port can be open (TCP) while FastAPI is still loading models;
 * a real HTTP 200 means it's ready to serve the UI.
 */
function isBackendReady() {
  return new Promise((resolve) => {
    const req = http.get(
      { hostname: '127.0.0.1', port: BACKEND_PORT, path: '/api/v1/health',
        headers: { 'x-authority': 'BASTION-KADIAN-SEC-0x42' }, timeout: 2000 },
      (res) => { resolve(res.statusCode < 500); }
    );
    req.setTimeout(2000, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

/** Status messages shown on the splash screen at timed intervals (ms elapsed). */
const SPLASH_MESSAGES = [
  [0,      'Starting detection engine...'],
  [8000,   'Loading signature database — 47,357 rules...'],
  [20000,  'Initialising ML models (RF + XGBoost + CatBoost)...'],
  [40000,  'Loading deep neural network specialist...'],
  [55000,  'Loading anomaly sentinel (Autoencoder + IForest)...'],
  [75000,  'Almost there — finalising engine startup...'],
  [100000, 'Still loading — large models take time on first run. Hang tight...'],
  [140000, 'Nearly ready. Thank you for your patience...'],
];

/**
 * Poll until the backend passes an HTTP health check, or until timeout.
 * Updates the splash message automatically as time passes.
 */
async function waitForBackend(timeoutMs = 180000) {
  const start = Date.now();
  let msgIdx = 0;
  while (Date.now() - start < timeoutMs) {
    const elapsed = Date.now() - start;
    // Advance the message when the next time-threshold is crossed
    while (msgIdx < SPLASH_MESSAGES.length - 1 &&
           elapsed >= SPLASH_MESSAGES[msgIdx + 1][0]) {
      msgIdx++;
      updateSplashMsg(SPLASH_MESSAGES[msgIdx][1]);
    }
    if (await isBackendReady()) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

/** Branded loading screen — professional animated splash with updateable status line. */
function splashHtml(initialMsg = 'Starting detection engine...') {
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{height:100vh;display:flex;flex-direction:column;align-items:center;
  justify-content:center;background:#080f1c;color:#fff;
  font-family:'Segoe UI',system-ui,sans-serif;-webkit-user-select:none;
  -webkit-app-region:drag;position:relative;overflow:hidden}
.bg-grid{position:absolute;inset:0;opacity:0.04;
  background-image:linear-gradient(#00c8ff 1px,transparent 1px),
  linear-gradient(90deg,#00c8ff 1px,transparent 1px);
  background-size:40px 40px}
.logo{font-size:40px;font-weight:900;letter-spacing:3px;position:relative;z-index:1}
.logo span{color:#c99a06}
.by{margin-top:6px;font-size:10px;color:#2d4a6a;letter-spacing:5px;
  text-transform:uppercase;position:relative;z-index:1}
.rings{margin-top:44px;position:relative;width:64px;height:64px;z-index:1}
.r1{position:absolute;inset:0;border:2px solid #0d2a4a;border-top:2px solid #c99a06;
  border-radius:50%;animation:sp .9s linear infinite}
.r2{position:absolute;inset:10px;border:1.5px solid #0d2a4a;border-top:1.5px solid #00c8ff;
  border-radius:50%;animation:sp .6s linear infinite reverse}
.r3{position:absolute;inset:22px;border:1px solid #0d2a4a;border-top:1px solid #c99a06;
  border-radius:50%;animation:sp .4s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.bar-wrap{margin-top:36px;width:300px;height:2px;background:#0d1f38;
  border-radius:2px;overflow:hidden;z-index:1}
.bar{height:100%;width:35%;background:linear-gradient(90deg,transparent,#c99a06,#00c8ff,transparent);
  animation:sweep 2s ease-in-out infinite;border-radius:2px}
@keyframes sweep{0%{margin-left:-35%}100%{margin-left:100%}}
.msg{margin-top:20px;font-size:11px;color:#3a5a7a;letter-spacing:1.5px;
  text-align:center;min-height:18px;z-index:1;transition:opacity .4s}
.footer{position:absolute;bottom:20px;font-size:8px;color:#141e2e;
  letter-spacing:4px;text-transform:uppercase}
</style></head>
<body>
  <div class="bg-grid"></div>
  <div class="logo">BASTION <span>IDS</span></div>
  <div class="by">by Kadian Inc</div>
  <div class="rings"><div class="r1"></div><div class="r2"></div><div class="r3"></div></div>
  <div class="bar-wrap"><div class="bar"></div></div>
  <div class="msg" id="msg">${initialMsg}</div>
</body></html>`);
}

/** Update the status line on the splash without reloading the whole page. */
function updateSplashMsg(msg) {
  if (win && !win.isDestroyed()) {
    win.webContents.executeJavaScript(
      `var el=document.getElementById('msg');if(el){el.style.opacity=0;setTimeout(()=>{el.textContent=${JSON.stringify(msg)};el.style.opacity=1},200)}`
    ).catch(() => {});
  }
}

async function createWindow() {
  logLaunch('createWindow: start');
  const _iconPath = path.join(__dirname, 'build', 'icon.ico');
  const _winOpts = {
    width:  1440,
    height: 900,
    title:  'Bastion IDS',
    frame:  false,
    show:   false,
    backgroundColor: '#0d2b55',
    webPreferences: {
      nodeIntegration:   true,
      contextIsolation:  false,
    },
  };
  // Only set a custom icon if the file is actually present (a missing/locked
  // icon path can abort window creation on some systems).
  try { if (fs.existsSync(_iconPath)) _winOpts.icon = _iconPath; } catch { /* ignore */ }
  win = new BrowserWindow(_winOpts);
  logLaunch('createWindow: BrowserWindow created');

  // Show a branded splash immediately so the window is never blank.
  win.loadURL(splashHtml('Starting detection engine...'));
  win.once('ready-to-show', () => { logLaunch('window ready-to-show'); win.show(); });
  // Safety net: force-show after 2s even if ready-to-show never fires.
  setTimeout(() => { try { if (win && !win.isVisible()) win.show(); } catch {} }, 2000);

  // ── Window control IPC (custom titlebar — frame:false) ─────────────────
  ipcMain.removeAllListeners('window-minimize');
  ipcMain.removeAllListeners('window-maximize');
  ipcMain.removeAllListeners('window-close');
  ipcMain.on('window-minimize', () => { try { win && win.minimize(); } catch {} });
  ipcMain.on('window-maximize', () => {
    try { if (win) win.isMaximized() ? win.unmaximize() : win.maximize(); } catch {}
  });
  ipcMain.on('window-close', () => { try { win && win.close(); } catch {} });

  // ── Start the backend if nothing is already listening ──────────────────
  // If the user launched the admin backend separately, reuse it. Otherwise
  // spawn the bundled engine (packaged) or system python (development).
  const alreadyUp = await isPortOpen();
  if (!alreadyUp) {
    let pyExe, apiPath, cwd;
    if (app.isPackaged) {
      const res = process.resourcesPath;                 // ...\resources
      pyExe   = path.join(res, 'pybackend', 'python.exe');
      apiPath = path.join(res, 'backend', 'api_server.py');
      cwd     = path.join(res, 'backend');
    } else {
      pyExe   = 'python';
      apiPath = path.join(__dirname, '..', 'api_server.py');
      cwd     = path.join(__dirname, '..');
    }
    logLaunch(`spawn backend: pyExe=${pyExe} | apiPath=${apiPath} | exists=${fs.existsSync(pyExe)}/${fs.existsSync(apiPath)}`);
    try {
      backendProcess = spawn(pyExe, [apiPath], {
        cwd,
        env: { ...process.env, PYTHONNOUSERSITE: '1' },
      });
    } catch (e) {
      logLaunch('SPAWN FAILED: ' + (e && e.stack || e));
      win.loadURL(splashHtml('Engine failed to start. Check the launch log.'));
      return;
    }
    backendProcess.on('error', (e) => logLaunch('backend spawn error: ' + e));
    let _errBuf = '';
    backendProcess.stdout.on('data', (d) => {
      const s = d.toString();
      process.stdout.write(`[API] ${s}`);
      try { fs.appendFileSync(BACKEND_LOG, s); } catch {}
    });
    backendProcess.stderr.on('data', (d) => {
      const s = d.toString();
      process.stderr.write(`[API-ERR] ${s}`);
      _errBuf += s; if (_errBuf.length > 4000) _errBuf = _errBuf.slice(-4000);
      try { fs.appendFileSync(BACKEND_LOG, '[STDERR] ' + s); } catch {}
    });
    backendProcess.on('exit', (code) => {
      logLaunch(`backend exited code=${code}`);
      if (code !== 0 && _errBuf) logLaunch('backend stderr tail: ' + _errBuf.slice(-1500));
    });

    // Wait until the backend passes a real HTTP health check.
    // Dynamic splash messages update automatically inside waitForBackend.
    const ready = await waitForBackend(180000);
    logLaunch(`waitForBackend -> ${ready}`);
    if (!ready) {
      updateSplashMsg('Engine failed to start. Check BastionIDS-launch.log in your Temp folder.');
      logLaunch('Backend did not become ready within timeout — staying on splash.');
      return; // Don't load the UI — backend isn't running
    }
  } else {
    logLaunch('[Electron] Backend already running on :' + BACKEND_PORT + ' — reusing it');
    updateSplashMsg('Detection engine found — connecting...');
    // Still do one HTTP check to confirm it's serving properly
    await waitForBackend(30000);
  }

  // ── Download handler (will-download) ───────────────────────────────────────
  // Fires for every download Electron intercepts.  Shows a native Save As
  // dialog so the user chooses where to save the file.  If the dialog is
  // cancelled the download is aborted cleanly.
  win.webContents.session.on('will-download', (_event, item) => {
    const filename   = item.getFilename();
    const defaultDir = app.getPath('downloads');
    const ext        = path.extname(filename).slice(1).toUpperCase() || 'FILE';

    // Build file-type filters based on extension
    const filters = [
      { name: `${ext} Files`, extensions: [path.extname(filename).slice(1) || '*'] },
      { name: 'All Files',    extensions: ['*'] },
    ];

    const savePath = dialog.showSaveDialogSync(win, {
      title:       'Save Report',
      defaultPath: path.join(defaultDir, filename),
      filters,
      properties:  ['showOverwriteConfirmation'],
    });

    if (!savePath) {
      // User cancelled — abort the download
      item.cancel();
      return;
    }

    item.setSavePath(savePath);
    item.once('done', (_e, state) => {
      if (state === 'completed') {
        shell.showItemInFolder(savePath);
        if (win && !win.isDestroyed()) win.focus();
      } else if (state !== 'cancelled') {
        console.error(`[Download] failed — state: ${state}`);
      }
    });
  });

  // ── IPC download channel ────────────────────────────────────────────────────
  // Renderer calls ipcRenderer.invoke('download-report', filename).
  // webContents.downloadURL() is the authoritative Electron API — it bypasses
  // cross-origin restrictions that prevent <a download> from working when the
  // page origin (localhost:48218) differs from the API origin (127.0.0.1:48217).
  ipcMain.handle('download-report', (_event, filename) => {
    const url = `http://127.0.0.1:48217/api/v1/reports/download/${encodeURIComponent(filename)}`;
    if (win && !win.isDestroyed()) {
      win.webContents.downloadURL(url);
    }
    return true;
  });

  // ── Blob save channel ───────────────────────────────────────────────────────
  // Renderer sends an ArrayBuffer + suggested filename; main process writes it
  // via a native Save As dialog.  Avoids the blank-screen bug where Electron
  // navigates to a blob: URL instead of downloading it.
  ipcMain.handle('save-file-data', async (_event, { buffer, name }) => {
    const ext        = path.extname(name).slice(1) || '*';
    const defaultDir = app.getPath('downloads');
    const result     = await dialog.showSaveDialog(win, {
      title:       'Save File',
      defaultPath: path.join(defaultDir, name),
      filters:     [{ name: `${ext.toUpperCase()} Files`, extensions: [ext] },
                    { name: 'All Files', extensions: ['*'] }],
      properties:  ['showOverwriteConfirmation'],
    });
    if (result.canceled || !result.filePath) return false;
    fs.writeFileSync(result.filePath, Buffer.from(buffer));
    shell.showItemInFolder(result.filePath);
    if (win && !win.isDestroyed()) win.focus();
    return true;
  });

  // Load the real UI. Packaged: the backend serves the built dist directly.
  // Development: try the Vite dev server first, fall back to the backend.
  if (app.isPackaged) {
    win.loadURL(BACKEND_URL);
  } else {
    win.loadURL(DEV_URL).catch(() => win.loadURL(BACKEND_URL));
  }

  // Open DevTools only in development
  if (process.env.NODE_ENV === 'development') {
    win.webContents.openDevTools({ mode: 'detach' });
  }
}

app.whenReady()
  .then(() => { logLaunch('app ready'); return createWindow(); })
  .then(() => logLaunch('createWindow resolved'))
  .catch((e) => {
    logLaunch('FATAL during startup: ' + (e && e.stack || e));
    try {
      dialog.showErrorBox('Bastion IDS failed to start',
        'Startup error logged to:\n' + LAUNCH_LOG + '\n\n' + (e && e.message || e));
    } catch { /* ignore */ }
  });

app.on('window-all-closed', () => {
  if (backendProcess) {
    backendProcess.kill();
    backendProcess = null;
  }
  app.quit();
});
