start %~sdp0VMProtect_Con.exe %~sdp0NetBarAD.vmp %~sdp0NetBarAD.vm
echo �ȴ��������...
ping -n 15 127.0.0.1>nul
del %~sdp0NetBarAD.dll /q
move %~sdp0NetBarAD.vm %~sdp0NetBarAD.dll
echo �������...
exit

