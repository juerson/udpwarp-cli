chcp 936
@echo off & setlocal enabledelayedexpansion

:loop
cls
echo 请选择要设置的WARP隧道协议：
echo 【1】MASQUE
echo 【2】WireGuard
set /p choice="输入你的选择(1或2)："

rem 选择隧道协议
if "!choice!"=="1" (
  set "tunnelProtocol=MASQUE"
  ) else if "!choice!"=="2" (
  set "tunnelProtocol=WireGuard"
  ) else (
  goto loop
)

rem 设置隧道协议
warp-cli tunnel protocol set %tunnelProtocol%

cls rem 清空控制台内容
echo $ warp-cli tunnel protocol set %tunnelProtocol%

rem 进入死循环，捕获用户输入的endpoint
:endpointLoop
set /p endpoint="请输入Endpoint的值(输入'exit'退出)："
if /i "!endpoint!"=="exit" (
  echo 退出程序。
  exit /b
)

if defined endpoint (
  warp-cli disconnect
  warp-cli tunnel endpoint reset
  warp-cli tunnel endpoint set %endpoint%
  warp-cli connect
  cls rem 清空控制台内容
  echo $ warp-cli tunnel protocol set %tunnelProtocol%
  echo $ warp-cli tunnel endpoint set %endpoint%
)
goto endpointLoop
