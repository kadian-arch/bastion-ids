; Bastion IDS - custom NSIS installer hooks (Kadian Inc)
; Shows per-file install detail so the user sees progress instead of a frozen
; bar during the multi-GB embedded-runtime extraction. Also installs Npcap
; silently if the bundled installer is present and not already on the machine.

!macro customInit
  ; Add Windows Defender exclusion for the install directory BEFORE extraction.
  ; Without this, Defender quarantines bundled Python packages mid-extraction on
  ; fresh Win 10/11 machines, causing "Error decompressing data" failures.
  nsExec::ExecToLog 'powershell.exe -NonInteractive -WindowStyle Hidden -Command "try { Add-MpPreference -ExclusionPath \"$PROGRAMFILES64\Bastion IDS\" -ErrorAction Stop } catch {}"'
  nsExec::ExecToLog 'powershell.exe -NonInteractive -WindowStyle Hidden -Command "try { Add-MpPreference -ExclusionPath \"C:\Program Files\Bastion IDS\" -ErrorAction Stop } catch {}"'
!macroend

!macro customHeader
  ; Reveal the per-file install log by default (NSIS hides it otherwise, which
  ; is why a large install looks "stuck"). User can still toggle it.
  ShowInstDetails show
  ShowUninstDetails show
!macroend

!macro customInstall
  DetailPrint "----------------------------------------------------------------"
  DetailPrint "Bastion IDS by Kadian Inc - core files installed."
  DetailPrint "Bundled engine: Python + TensorFlow + 911 MB trained models."
  DetailPrint "----------------------------------------------------------------"
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
    DetailPrint "  Npcap installer not bundled. Install from https://npcap.com"
    DetailPrint "  if live packet capture is needed on this machine."
  !endif
  DetailPrint "----------------------------------------------------------------"
  DetailPrint "Installation complete. (c) 2026 Kadian Inc. by KING KAD."
!macroend
