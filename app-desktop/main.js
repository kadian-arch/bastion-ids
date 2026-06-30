import { app, BrowserWindow, shell, ipcMain, dialog } from 'electron';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import net from 'net';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
let backendProcess = null;
let win = null;   // module-level so ipcMain handlers can reference it

// ── Startup logging (diagnoses launch failures on clean machines/VMs) ───────
const LAUNCH_LOG = path.join(os.tmpdir(), 'BastionIDS-launch.log');
function logLaunch(msg) {
  try {
    fs.appendFileSync(LAUNCH_LOG,
      `[${new Date().toISOString()}] ${msg}\n`);
  } catch { /* never let logging crash the app */ }
}
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

/** Check whether the Bastion backend port is already bound and listening. */
function isBackendRunning() {
  return new Promise((resolve) => {
    const client = new net.Socket();
    client.setTimeout(800);
    client.connect(BACKEND_PORT, '127.0.0.1', () => {
      client.destroy();
      resolve(true);   // something is already listening
    });
    client.on('error', () => { client.destroy(); resolve(false); });
    client.on('timeout', () => { client.destroy(); resolve(false); });
  });
}

/** Poll until the backend is accepting connections, or until timeout (ms). */
async function waitForBackend(timeoutMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await isBackendRunning()) return true;
    await new Promise((r) => setTimeout(r, 600));
  }
  return false;
}

/** Branded loading screen shown while the detection engine initialises. */
function splashHtml(msg) {
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(`
    <html><body style="margin:0;height:100vh;display:flex;flex-direction:column;
      align-items:center;justify-content:center;background:#0d2b55;color:#fff;
      font-family:Segoe UI,Arial,sans-serif;-webkit-user-select:none;">
      <div style="font-size:46px;font-weight:800;letter-spacing:1px;">BASTION <span style="color:#c99a06;">IDS</span></div>
      <div style="margin-top:6px;color:#aac4e0;font-size:14px;">by Kadian Inc</div>
      <div style="margin-top:34px;width:240px;height:4px;background:#102a4d;border-radius:4px;overflow:hidden;">
        <div style="width:40%;height:100%;background:#c99a06;animation:l 1.1s infinite ease-in-out;"></div></div>
      <div style="margin-top:18px;color:#7d93b3;font-size:13px;">${msg}</div>
      <style>@keyframes l{0%{margin-left:-40%}100%{margin-left:100%}}</style>
    </body></html>`);
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

  // ── Start the backend if nothing is already listening ──────────────────
  // If the user launched the admin backend separately, reuse it. Otherwise
  // spawn the bundled engine (packaged) or system python (development).
  const alreadyUp = await isBackendRunning();
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
      backendProcess = spawn(pyExe, [apiPath], { cwd });
    } catch (e) {
      logLaunch('SPAWN FAILED: ' + (e && e.stack || e));
      win.loadURL(splashHtml('Engine failed to start. Check the launch log.'));
      return;
    }
    backendProcess.on('error', (e) => logLaunch('backend spawn error: ' + e));
    let _errBuf = '';
    backendProcess.stdout.on('data', (d) => process.stdout.write(`[API] ${d}`));
    backendProcess.stderr.on('data', (d) => {
      const s = d.toString();
      process.stderr.write(`[API-ERR] ${s}`);
      _errBuf += s; if (_errBuf.length > 4000) _errBuf = _errBuf.slice(-4000);
    });
    backendProcess.on('exit', (code) => {
      logLaunch(`backend exited code=${code}`);
      if (code !== 0 && _errBuf) logLaunch('backend stderr tail: ' + _errBuf.slice(-1500));
    });

    // Wait until the engine is actually accepting connections (models load in ~30-60s).
    const ready = await waitForBackend(150000);
    logLaunch(`waitForBackend -> ${ready}`);
    if (!ready) {
      win.loadURL(splashHtml('Engine is taking longer than expected. Please wait...'));
    }
  } else {
    console.log('[Electron] Backend already running on :' + BACKEND_PORT + ' — reusing it');
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
