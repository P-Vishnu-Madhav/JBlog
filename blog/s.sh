#!/bin/bash
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz -P /tmp/
tar -zxvf pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
sudo cp /tmp/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz /opt/
cd /opt
tar -zxvf pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
ln -s /opt/pin-3.7-97619-g0d0c92f4f-gcc-linux /opt/pin-dir
cd /opt/pin-dir/source/tools
make all
make all TARGET=ia32
cd ManualExamples/obj-intel64
./pin -t /opt/pin-dir/source/tools/ManualExamples/obj-intel64/inscount0.so -- ~/prog
