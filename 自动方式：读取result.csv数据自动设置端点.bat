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
        set "csvValue3=!csvValue3:"=!"  REM ȥ������

        if not "!csvValue3!"=="100%%" (
            set "endpoint=!csvValue1!"
            set "protocol=!csvValue2!"
            set "loss=!csvValue3!"
            set "delay=!csvValue4!"
            set "foundIP=true"
        )
    )
)

REM �ж��Ƿ��ҵ�����
if defined endpoint (
    echo.:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    echo.::                                                                 ::
    echo.       ����result.csv����Զ����ö˵�Ϊ%endpoint%
    echo.		     ������ %loss% ƽ���ӳ� %delay% ms                
    echo.::                                                                 ::
    echo.:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	echo $ warp-cli tunnel protocol set %protocol%
    warp-cli tunnel protocol set %protocol%
	
	echo $ warp-cli tunnel endpoint reset
	warp-cli tunnel endpoint reset
	
	echo $ warp-cli tunnel endpoint set %endpoint%
    warp-cli tunnel endpoint set %endpoint%
) else (
    echo ɨ�赽��result.csv�ļ���endpoint���ݲ����á�
)
pause
exit