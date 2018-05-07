@echo off
del *.sdf
rmdir /Q /S ipch

cd ComputerNetworks
rmdir /Q /S Debug
rmdir /Q /S Release
cd ..

cd DeviceInfo
rmdir /Q /S Debug
rmdir /Q /S Release
cd ..

cd PacketCapture
rmdir /Q /S Debug
rmdir /Q /S Release
cd ..

cd PassHash
rmdir /Q /S Debug
rmdir /Q /S Release
cd ..

cd RipListener
rmdir /Q /S Debug
rmdir /Q /S Release
cd ..

cd Debug
del *.lib
del *.ilk
del *.exp
del *.pdb