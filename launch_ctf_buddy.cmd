@echo off
set "ROOT=%~dp0"
powershell -NoExit -ExecutionPolicy Bypass -File "%ROOT%launch_ctf_buddy.ps1"
