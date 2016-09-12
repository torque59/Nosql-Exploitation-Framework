#Written as a quirk for macosx/Kali . Plse do file a bug in case of a failure

pip install -r requirements.txt
tar -xzvf reqs/macosx/libdnet-1.12.tgz
cd libdnet-1.12
./configure
make
sudo make install
cd python 
sudo python setup.py install
cd ../../
sudo rm -rf libdnet-1.12
echo "Cleaning up.Framework should nw run"
echo "Run nosqlframework.py --help"
