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
  DetailPrint "Checking for Visual C++ 2022 Runtime..."
  !if /FileExists "${BUILD_RESOURCES_DIR}\vc_redist.x64.exe"
    IfFileExists "$SYSDIR\vcruntime140.dll" vcpp_present 0
      DetailPrint "  VC++ Runtime not found - installing (required for TensorFlow)..."
      File "/oname=$PLUGINSDIR\vc_redist.x64.exe" "${BUILD_RESOURCES_DIR}\vc_redist.x64.exe"
      ExecWait '"$PLUGINSDIR\vc_redist.x64.exe" /install /quiet /norestart' $0
      DetailPrint "  VC++ Runtime installer finished (exit code: $0)."
      Goto vcpp_done
    vcpp_present:
      DetailPrint "  Visual C++ Runtime already installed - skipping."
    vcpp_done:
  !else
    DetailPrint "  VC++ Runtime not bundled. If TensorFlow fails to load, download:"
    DetailPrint "  https://aka.ms/vs/17/release/vc_redist.x64.exe"
  !endif
  DetailPrint "----------------------------------------------------------------"

  ; --- Npcap packet-capture driver (required for live packet capture) ---
  DetailPrint "Checking for Npcap packet-capture driver..."
  !if /FileExists "${BUILD_RESOURCES_DIR}\npcap-installer.exe"
    IfFileExists "$SYSDIR\Npcap\wpcap.dll" npcap_present 0
    IfFileExists "$SYSDIR\wpcap.dll" npcap_present 0
      DetailPrint "  Npcap not found - installing (required for live capture)..."
      File "/oname=$PLUGINSDIR\npcap-installer.exe" "${BUILD_RESOURCES_DIR}\npcap-installer.exe"
      ExecWait '"$PLUGINSDIR\npcap-installer.exe" /S' $0
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
