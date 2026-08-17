@echo off
rem Launch the BENCpass extension runner without arguing with PowerShell.
rem
rem A .cmd file is not subject to the execution policy, and -ExecutionPolicy
rem Bypass applies to the child process only -- so nothing on the machine is
rem reconfigured and nothing is left changed afterwards.
rem
rem Usage:
rem   tools\run-extension.cmd
rem   tools\run-extension.cmd -Browser "C:\Path\To\zen.exe"
rem   tools\run-extension.cmd -Port 9000

setlocal

rem Prefer PowerShell 7 when it is installed; fall back to the one Windows ships.
set "PSEXE=powershell"
where pwsh >nul 2>&1 && set "PSEXE=pwsh"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-extension.ps1" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo.
  echo If that failed with an execution-policy error rather than a real one,
  echo the policy is being set by Group Policy, which -ExecutionPolicy cannot
  echo override. Check which scope is responsible:
  echo.
  echo     Get-ExecutionPolicy -List
  echo.
  echo A script read from stdin is not governed by the policy at all:
  echo.
  echo     Get-Content -Raw "%~dp0run-extension.ps1" ^| %PSEXE% -NoProfile -Command -
  echo.
)

endlocal & exit /b %RC%
