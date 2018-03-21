# Electrum timestamp plugin with sign-to-contract

Instruction to run the Electrum plugin producing sign-to-contract proof with OpenTimestamps.

**Beware:** this is highly experimental, run it at your own risk. 

## Getting started

Assuming running on Linux.
 
You need to use the custom library by apoelstra that integrate OpSecp256k1Commitment in OpenTimestamps.
You need to download electrum from source and integrate it with the timestamp plugin. 
 
``` 
git clone https://github.com/apoelstra/python-opentimestamps.git
git clone https://github.com/LeoComandini/electrum-timestamp-plugin.git
git clone git://github.com/spesmilo/electrum.git
```

Now go to the sign-to-contract (s2c) branch, 
copy the plugin file in the local electrum directory, 
then copy a temporary version of setup.py in the custom version of python-opentimestamps just downloaded.
```
cd electrum-timestamp-plugin
git checkout s2c
cd ..
cp -r electrum-timestamp-plugin/timestamp electrum/plugins
cp electrum-timestamp-plugin/setup.py python-opentimestamps
```

Install the custom library.
```
pip3 install python-opentimestamps/
```

Follow an adapted version of [Electrum README](https://github.com/spesmilo/electrum#development-version).

Electrum is a pure python application. 
If you want to use the Qt interface, install the Qt dependencies:
```
sudo apt-get install python3-pyqt5
sudo apt-get install python3-setuptools
cd electrum
python3 setup.py install
```

Compile the icons file for Qt:
```
sudo apt-get install pyqt5-dev-tools
pyrcc5 icons.qrc -o gui/qt/icons_rc.py
```

If you tried the version of the plugin without s2c remove the db storing the info for generating the proof.
```
rm db_file.json
``` 

Run on `testnet`
```
./electrum --testnet
```

Run on `mainnet`
```
./electrum
```

## Create timestamps with your transactions
1) Enable the plugin:
    - `Tools -> Plugins -> Timestamp`, tick the checkbox
    - by clicking to `Settings` you can switch from `op_return` to `sign-to-contract`, stay on the latter
    - close and restart Electrum to abilitate the plugin
2) Visualize your timestamp history list:
    - `Tools -> Timestamps` 
3) Start tracking the file(s) to timestamp:
    - click on `Add New File` and select the file
4) Create and broadcast a bitcoin transaction including the timestamp:
    - on the `Send Tab` select outputs, amount, fee
    (select a fee > 1 sat/byte) 
    - click on `Preview`  
    - click on `S2C`, insert the password, this will insert a commitment to the file you selected in the signature using sign-to-contract.
    - click on `Broadcast`
5) Check the timestamp history:
    - `Tools -> Timestamps`, the file now is an pending state.
6) Wait until the transaction is confirmed (6 blocks), you can now create the timestamp proof (`file_name.ots`):
    - `Tools -> Timestamps`, 
click on `Upgrade`,
the timestamp now is complete

You can find the timestamp proof next to the file(s):
```
/path/file_name.txt
/path/file_name.txt.ots
```

Note that the `.ots` contains a OpSecp256k1Commitment so the standard ots library won't recognize it.
Verify it manually using the python library just installed,
for instance by conveniently modifying `ots-info.py`
