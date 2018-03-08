# Electrum timestamp plugin
Electrum plugin to create timestamp proofs with your transactions. 
Proofs are made using OpenTimestamps.

*Note:* creating a timestamp in this way has a cost. 
You can timestamp for free using the public calendars, 
more details at [OpenTimestamps.org](https://opentimestamps.org)

## Getting started
Adapted from [Electrum README](https://github.com/spesmilo/electrum#development-version)


Install plugin requirements:
```
$ pip3 install opentimestamps
```

Clone the Electrum source code, then include the plugin files:
```
$ git clone https://github.com/spesmilo/electrum.git
$ git clone https://github.com/LeoComandini/electrum-timestamp-plugin.git
$ cp -r electrum-timestamp-plugin/timestamp electrum/plugins
$ cd electrum
$ python3 setup.py install
```

Compile the icons file for Qt:
```
sudo apt-get install pyqt5-dev-tools
pyrcc5 icons.qrc -o gui/qt/icons_rc.py
```

To run on `mainnet`
```
$ ./electrum
```

To run on `testnet` 
```
$ ./electrum --testnet
```

## Create timestamps with your transactions
1) Enable the plugin:
    - `Tools -> Plugins -> Timestamp`, tick the checkbox
    - close and restart Electrum to abilitate the plugin
2) Visualize your timestamp history list:
    - `Tools -> Timestamps` 
3) Start tracking the file(s) to timestamp:
    - click on `Add New File` and select the file
4) Create and broadcast a bitcoin transaction including the timestamp:
    - on the `Send Tab` select outputs, amount, fee
    (select a fee > 1 sat/byte) 
    - click on `Preview`  
    - click on `Timestamp`, this write a commitment to your file(s) in the transaction 
    - confirm the changes in the transaction 
    (if fee is too low th transaction won't be relayed or mined)
    - sign and broadcast the transaction (`Sign`, `Broadcast`)
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
