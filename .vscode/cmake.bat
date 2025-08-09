@echo off

:: 激活 MSVC 环境
pushd "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

call "C:\opt\Qt\5.15.2\msvc2019_64\bin\qtenv2.bat"
popd

cmake %*
@echo on