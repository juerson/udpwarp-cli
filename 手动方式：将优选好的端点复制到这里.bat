chcp 936
@echo off & setlocal enabledelayedexpansion

:loop
cls
echo ��ѡ��Ҫ���õ�WARP���Э�飺
echo ��1��MASQUE
echo ��2��WireGuard
set /p choice="�������ѡ��(1��2)��"

rem ѡ�����Э��
if "!choice!"=="1" (
  set "tunnelProtocol=MASQUE"
  ) else if "!choice!"=="2" (
  set "tunnelProtocol=WireGuard"
  ) else (
  goto loop
)

rem �������Э��
warp-cli tunnel protocol set %tunnelProtocol%

cls rem ��տ���̨����
echo $ warp-cli tunnel protocol set %tunnelProtocol%

rem ������ѭ���������û������endpoint
:endpointLoop
set /p endpoint="������Endpoint��ֵ(����'exit'�˳�)��"
if /i "!endpoint!"=="exit" (
  echo �˳�����
  exit /b
)

if defined endpoint (
  warp-cli disconnect
  warp-cli tunnel endpoint reset
  warp-cli tunnel endpoint set %endpoint%
  warp-cli connect
  cls rem ��տ���̨����
  echo $ warp-cli tunnel protocol set %tunnelProtocol%
  echo $ warp-cli tunnel endpoint set %endpoint%
)
goto endpointLoop
