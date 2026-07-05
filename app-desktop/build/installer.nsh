; Bastion IDS - custom NSIS installer hooks (Kadian Inc)
; Runs Defender exclusions before extraction, then installs VC++ Runtime
; and Npcap silently if they are not already present on the machine.

!macro customInit
  ; Add Defender exclusions BEFORE extraction begins.
  ; customInstall runs after files are already on disk — too late.
  ; Defender quarantines .pyd and .dll files the moment they land.
  ; We cover the default Program Files path and the root of every drive.
  Exec 'powershell.exe -NonInteractive -WindowStyle Hidden -Command "try { Add-MpPreference -ExclusionPath \"$PROGRAMFILES64\Bastion IDS\" -ErrorAction Stop } catch {}; foreach ($$d in (Get-PSDrive -PSProvider FileSystem).Root) { try { Add-MpPreference -ExclusionPath ($$d + \"Bastion IDS\") -ErrorAction Stop } catch {} }"'
!macroend

!macro customHeader
  ShowInstDetails show
  ShowUninstDetails show
!macroend

!macro customInstall
  ; Belt-and-suspenders: add $INSTDIR exclusion now that real path is known.
  nsExec::ExecToLog 'powershell.exe -NonInteractive -WindowStyle Hidden -Command "try { Add-MpPreference -ExclusionPath \"$INSTDIR\" -ErrorAction Stop } catch {}"'
  DetailPrint "----------------------------------------------------------------"
  DetailPrint "Bastion IDS by Kadian - core files installed."
  DetailPrint "Bundled engine: Python + TensorFlow + trained models."
  DetailPrint "----------------------------------------------------------------"

  ; --- Visual C++ 2022 Runtime (required for TensorFlow / DNN layer) ---
  ; ALWAYS run the redistributable. It is idempotent: if a NEWER runtime is
  ; already present it self-skips in seconds. The old "skip if vcruntime140.dll
  ; exists" check was wrong — an OUTDATED vcruntime140.dll is present but still
  ; too old for TensorFlow, so we must let the installer decide, not a file test.
  DetailPrint "Ensuring Visual C++ 2022 Runtime is up to date..."
  !if /FileExists "${BUILD_RESOURCES_DIR}\vc_redist.x64.exe"
    File "/oname=$PLUGINSDIR\vc_redist.x64.exe" "${BUILD_RESOURCES_DIR}\vc_redist.x64.exe"
    ExecWait '"$PLUGINSDIR\vc_redist.x64.exe" /install /quiet /norestart' $0
    DetailPrint "  VC++ Runtime installer finished (exit code: $0)."
  !else
    DetailPrint "  VC++ Runtime not bundled. If the DNN layer shows offline, install:"
    DetailPrint "  https://aka.ms/vs/17/release/vc_redist.x64.exe"
  !endif
  DetailPrint "----------------------------------------------------------------"

  ; --- Npcap packet-capture driver (required for live packet capture) ---
  ; The FREE Npcap redistributable forbids /S silent installation (that flag is
  ; reserved for the paid Npcap OEM edition and pops a rejection dialog). So we
  ; run its normal wizard INTERACTIVELY — exactly how Wireshark ships it. The
  ; user clicks through a couple of prompts; still fully in-box, no download.
  DetailPrint "Checking for Npcap packet-capture driver..."
  !if /FileExists "${BUILD_RESOURCES_DIR}\npcap-installer.exe"
    IfFileExists "$SYSDIR\Npcap\wpcap.dll" npcap_present 0
    IfFileExists "$SYSDIR\wpcap.dll" npcap_present 0
      DetailPrint "  Npcap not found - launching its installer (needed for live capture)."
      DetailPrint "  Please click through the Npcap setup prompts when they appear."
      MessageBox MB_OK|MB_ICONINFORMATION "Bastion IDS needs the Npcap driver for live packet capture.$\r$\n$\r$\nThe Npcap installer will now open — please click through its prompts (the defaults are fine). Live capture will not work without it."
      File "/oname=$PLUGINSDIR\npcap-installer.exe" "${BUILD_RESOURCES_DIR}\npcap-installer.exe"
      ExecWait '"$PLUGINSDIR\npcap-installer.exe"' $0
      DetailPrint "  Npcap installer finished (exit code: $0)."
      Goto npcap_done
    npcap_present:
      DetailPrint "  Npcap already installed - skipping."
    npcap_done:
  !else
    DetailPrint "  Npcap not bundled. Install from https://npcap.com"
    DetailPrint "  if live packet capture is needed on this machine."
  !endif
  DetailPrint "----------------------------------------------------------------"
  DetailPrint "Installation complete. (c) 2026 Kadian Inc. by KING KAD."
!macroend
