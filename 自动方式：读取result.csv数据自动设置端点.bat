chcp 936
cls
@echo off & setlocal enabledelayedexpansion

set "endpoint="
set "loss="
set "protocol="
set "delay="
set "foundIP=false"

for /f "skip=1 tokens=1,2,5,6 delims=," %%a in (result.csv) do (
    if "!foundIP!"=="false" (
        set "csvValue1=%%a"
        set "csvValue2=%%b"
        set "csvValue3=%%c"
        set "csvValue4=%%d"
        set "csvValue3=!csvValue3: =!"
        set "csvValue3=!csvValue3:"=!"  REM 去掉引号

        if not "!csvValue3!"=="100%%" (
            set "endpoint=!csvValue1!"
            set "protocol=!csvValue2!"
            set "loss=!csvValue3!"
            set "delay=!csvValue4!"
            set "foundIP=true"
        )
    )
)

REM 判断是否找到数据
if defined endpoint (
    echo.:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    echo.::                                                                 ::
    echo.       根据result.csv结果自动设置端点为%endpoint%
    echo.		     丢包率 %loss% 平均延迟 %delay% ms                
    echo.::                                                                 ::
    echo.:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	echo $ warp-cli tunnel protocol set %protocol%
    warp-cli tunnel protocol set %protocol%
	
	echo $ warp-cli tunnel endpoint reset
	warp-cli tunnel endpoint reset
	
	echo $ warp-cli tunnel endpoint set %endpoint%
    warp-cli tunnel endpoint set %endpoint%
) else (
    echo 扫描到的result.csv文件的endpoint数据不可用。
)
pause
exit