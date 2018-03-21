#!/usr/bin/env python3
#
# Electrum Timstamp Plugin
# Copyright (C) 2018 Leonardo Comandini
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# based on
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 Thomas Voegtlin

from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum_gui.qt import EnterButton, QRadioButton, HelpButton, Buttons, OkButton, CancelButton
from electrum_gui.qt.util import WindowModalDialog
from electrum_gui.qt.transaction_dialog import show_transaction
from electrum.util import timestamp_to_datetime, bh2u, InvalidPassword
from electrum.bitcoin import public_key_from_private_key, regenerate_key, MySigningKey, Hash
from .timestamp_list import TimestampList

from ecdsa.curves import SECP256k1
from ecdsa.rfc6979 import generate_k
from ecdsa.util import sigencode_der, sigdecode_der

from PyQt5.QtWidgets import QVBoxLayout, QGridLayout, QPushButton, QFileDialog, QMessageBox, QInputDialog, QLineEdit
from functools import partial
import json
import base64
import binascii
import os
import hashlib

try:
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile, make_merkle_tree, cat_sha256d
    from opentimestamps.core.op import Op, OpAppend, OpPrepend, OpSHA256, OpSecp256k1Commitment
    from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext
    from opentimestamps.core.notary import UnknownAttestation, BitcoinBlockHeaderAttestation
    from opentimestamps.timestamp import nonce_timestamp
    ots_imported = True
except ImportError:
    ots_imported = False

# TODO: external timestamping for calendars
# TODO: include s2c (segwit txs imply extra work for the electrum server)

# REM: A non-segwit tx can be malleated by someone who relays it.
#      If it happens the related timestamps will be not upgradable

# REM: There is no easy way to timestamp raw data directly.
#      A possible solution is to include those data in a file.

# REM: If a reorg of more than `default_blocks_until_confirmed` (6) blocks happens some timestamps may become invalid


json_path_file = "db_file.json"
default_blocks_until_confirmed = 6
default_folder = os.path.expanduser("~")
default_commitment_method = "s2c"  # alternative "op_return"

# util


def x(h):
    return binascii.unhexlify(h.encode('utf-8'))


def lx(h):
    return binascii.unhexlify(h.encode('utf-8'))[::-1]


def bytes_to_b64string(b):
    return base64.b64encode(b).decode('utf-8')


def b64string_to_bytes(s):
    return base64.b64decode(s.encode('utf-8'))


def proof_from_txid_to_block(txid, height, network):
    merkle_path = network.synchronous_get(('blockchain.transaction.get_merkle', [txid, height]))
    timestamp = Timestamp(lx(txid))
    pos = merkle_path["pos"]
    t_old = t_new = timestamp
    for c in merkle_path["merkle"]:
        t_new = cat_sha256d(t_old, Timestamp(lx(c))) if pos % 2 == 0 else cat_sha256d(Timestamp(lx(c)), t_old)
        pos //= 2
        t_old = t_new
    t_new.attestations.add(BitcoinBlockHeaderAttestation(height))
    return timestamp


def roll_timestamp(t):
    # REM: if there is one or more ops then this function rolls into the first one
    try:
        return roll_timestamp(sorted(t.ops.items())[0][1])
    except IndexError:
        return t


def pre_serialize(t):
    ft = roll_timestamp(t)
    if len(ft.attestations) == 0:
        ft.attestations.add(UnknownAttestation(b'incompl.', b''))


def post_deserialize(t):
    ft = roll_timestamp(t)
    fa = ft.attestations.copy()
    for a in fa:
        if isinstance(a, UnknownAttestation):
            ft.attestations.remove(a)


# data containers


class FileData:

    def __init__(self):
        self.path = None
        self.status = None  # tracked, aggregated, pending, completed
        self.agt = None  # aggregation tip
        self.r_s2c = None
        self.padding = None
        self.pivot_pt = None
        self.txid = None
        self.block = None
        self.date = None
        self.detached_timestamp = None

    def from_file(self, path):
        self.path = path
        self.status = "tracked"
        self.agt = None
        self.r_s2c = None
        self.padding = None
        self.pivot_pt = None
        self.txid = None
        self.block = None
        self.date = None
        with open(self.path, "rb") as fo:
            self.detached_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fo)

    def from_db(self, d):
        self.path = d["path"]
        self.status = d["status"]
        self.agt = bytes.fromhex(d["agt"]) if d["agt"] else d["agt"]
        self.r_s2c = d["r_s2c"]
        self.padding = d["padding"]
        self.pivot_pt = d["pivot_pt"]
        self.txid = d["txid"]
        self.block = d["block"]
        self.date = d["date"]
        self.detached_timestamp = DetachedTimestampFile.deserialize(BytesDeserializationContext(b64string_to_bytes(d["detached_timestamp"])))
        post_deserialize(self.detached_timestamp.timestamp)

    def as_dict(self):
        d = dict()
        d["path"] = self.path
        d["status"] = self.status
        d["agt"] = self.agt.hex() if self.agt else self.agt
        d["r_s2c"] = self.r_s2c
        d["padding"] = self.padding
        d["pivot_pt"] = self.pivot_pt
        d["txid"] = self.txid
        d["block"] = self.block
        d["date"] = self.date
        pre_serialize(self.detached_timestamp.timestamp)
        ctx = BytesSerializationContext()
        self.detached_timestamp.serialize(ctx)
        d["detached_timestamp"] = bytes_to_b64string(ctx.getbytes())
        ft = roll_timestamp(self.detached_timestamp.timestamp)
        ft.attestations = set()
        return d

    def write_ots(self):
        assert self.status == "complete"
        assert self.block == sorted(roll_timestamp(self.detached_timestamp.timestamp).attestations)[0].height
        ctx = BytesSerializationContext()
        self.detached_timestamp.serialize(ctx)
        with open(self.path + ".ots", "wb") as fw:
            fw.write(ctx.getbytes())


class ProofsStorage:
    """Container for complete and incomplete proofs"""

    def __init__(self, json_path):
        self.json_path = json_path
        self.db = []  # list of dicts
        self.incomplete_proofs = []  # list of FileData
        self.read_json()

    def read_json(self):
        try:
            with open(self.json_path, "r") as f:
                self.incomplete_proofs = []
                self.db = []
                self.db = json.load(f)
                for d in self.db:
                    if d["status"] != "complete":
                        f = FileData()
                        f.from_db(d)
                        self.incomplete_proofs += [f]
        except FileNotFoundError:
            pass

    def write_json(self):
        with open(self.json_path, 'w') as f:
            json.dump(self.db, f)

    def update_db(self):
        if self.db:
            db_complete = [d for d in self.db if d["status"] == "complete"]
            self.db = db_complete
        else:
            self.db = []
        for i in self.incomplete_proofs:
            self.db += [i.as_dict()]

    def add_proof(self, proof):
        for d in self.db:
            if proof.path == d["path"]:
                return False
        for i in self.incomplete_proofs:
            if proof.path == i.path:
                return False
        self.incomplete_proofs += [proof]
        self.db += [proof.as_dict()]
        self.write_json()
        return True

    def remove_path(self, path):
        self.incomplete_proofs = [i for i in self.incomplete_proofs if i.path != path]
        self.db = [d for d in self.db if d["path"] != path]
        self.write_json()


# plugin


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.proofs_storage_file = ProofsStorage(json_path_file)
        self.timestamp_list = None
        self.commitment_method = default_commitment_method

    def is_available(self):
        return ots_imported

    def track_new_file(self, path):
        f = FileData()
        f.from_file(path)
        return self.proofs_storage_file.add_proof(f)

    def aggregate_timestamps(self):
        file_timestamps = []
        for f in self.proofs_storage_file.incomplete_proofs:
            if f.status != "pending":
                try:
                    f.from_file(f.path)
                    f.status = "aggregated"
                    file_timestamps += [nonce_timestamp(f.detached_timestamp.timestamp)]
                except FileNotFoundError:
                    pass
        if not file_timestamps:
            return None
        else:
            t = make_merkle_tree(file_timestamps)
            for f in self.proofs_storage_file.incomplete_proofs:
                if f.status == "aggregated":
                    f.agt = roll_timestamp(f.detached_timestamp.timestamp).msg
            self.update_storage()
        return t.msg

    def timestamp_op_return(self, tx):
        commit = self.aggregate_timestamps()
        if commit:
            script = bytes.fromhex("6a") + len(commit).to_bytes(1, "big") + commit
            tx.add_outputs([(2, script.hex(), 0)])

    def sign_to_contract(self, pwd, tx, wallet, contract):
        """Sign with sign-to-contract

        we mimic the standard signing procedure trying to stick to electrum steps"""

        # FIXME: password and private keys should be managed in a separate thread

        i, j = 0, 0  # first input, first signature (is an arbitrary choice)
        txin = tx.inputs()[i]
        keystore = wallet.keystore
        keystore.check_password(pwd)  # decode the xprv
        keypairs = keystore.get_tx_derivations(tx)  # keypairs are the keys corresponding to the inputs of the txl
        for k, v in keypairs.items():
            keypairs[k] = keystore.get_private_key(v, pwd)  # picking all the private keys
        pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
        x_pubkey = x_pubkeys[j]
        sec, compressed = keypairs.get(x_pubkey)
        pubkey = public_key_from_private_key(sec, compressed)
        pkey = regenerate_key(sec)
        secexp = pkey.secret
        private_key = MySigningKey.from_secret_exponent(secexp, curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        pre_hash = Hash(bytes.fromhex(tx.serialize_preimage(i)))  # what this "i" means?
        k = generate_k(order=private_key.curve.generator.order(), secexp=secexp, hash_func=hashlib.sha256,
                       data=pre_hash)
        pivot_pt = k * SECP256k1.generator
        pivot_pt_encoded = bytearray(pivot_pt.x().to_bytes(33, "big"))
        pivot_pt_encoded[0] = 2 if pivot_pt.y() % 2 == 0 else 3

        while True:
            # the r part of the signature must be 32 bytes to have the output of secp256k1commitment explicitly in the
            # transaction, if the r is smaller than 32 bytes (1 time out of 512) we repeat the signature prepending
            # b'\x00' to the contract
            padding = b''
            hasher = hashlib.sha256()
            hasher.update(pivot_pt_encoded)
            hasher.update(padding + contract)
            tweak = int.from_bytes(hasher.digest(), "big")
            k_tweaked = (k + tweak) % SECP256k1.order
            sig = private_key.sign_digest(pre_hash, sigencode=sigencode_der, k=k_tweaked)
            if sig[3] >= 32:
                break
            padding += b'\x00'

        ephemeral_pubkey_x = sig[4:(4 + 32)] if sig[3] == 32 else sig[5:(5 + 32)]  # manage DER encoding
        assert ephemeral_pubkey_x == (k_tweaked * SECP256k1.generator).x().to_bytes(32, "big")

        # conclude the signature in the standard way
        assert public_key.verify_digest(sig, pre_hash, sigdecode=sigdecode_der)
        txin['signatures'][j] = bh2u(sig) + '01'
        txin['pubkeys'][j] = pubkey  # needed for fd keys # ?
        tx._inputs[i] = txin
        tx.raw = tx.serialize()
        # sign normally the other inputs
        wallet.sign_transaction(tx, pwd)  # this should not overwrite the signature just made
        # write on db the info to upgrade timestamps, upgrade is done later, when tx is broadcasted
        for f in self.proofs_storage_file.incomplete_proofs:
            tf = roll_timestamp(f.detached_timestamp.timestamp)
            if tf.msg == contract:
                f.padding = padding.hex()
                f.pivot_pt = pivot_pt_encoded.hex()
                f.r_s2c = ephemeral_pubkey_x.hex()
        self.update_storage()

    def upgrade_timestamps_txs(self, wallet):
        for txid, tx in wallet.transactions.items():
            if txid in wallet.verified_tx.keys():
                self.upgrade_timestamps_tx(tx)

    def upgrade_timestamps_tx(self, tx):
        # op_return
        for category, script, amount in tx.outputs():
            if category == 2:  # agt -> txid
                agt = script[4:]  # drop "6a20" op_return and op_pushdata(32)
                tx_raw = tx.serialize(witness=False)
                if len(x(tx_raw)) <= Op.MAX_MSG_LENGTH:
                    i = tx_raw.find(agt)
                    prepend = x(tx_raw[:i])
                    append = x(tx_raw[i + len(agt):])
                    t_agt = Timestamp(x(agt))
                    t = t_agt.ops.add(OpPrepend(prepend))
                    t = t.ops.add(OpAppend(append))
                    t = t.ops.add(OpSHA256())
                    t = t.ops.add(OpSHA256())  # txid in little endian
                    for f in self.proofs_storage_file.incomplete_proofs:
                        tf = roll_timestamp(f.detached_timestamp.timestamp)
                        if tf.msg == x(agt):
                            tf.merge(t_agt)
                            f.status = "pending"
                            f.txid = t.msg[::-1].hex()
        # s2c
        for f in self.proofs_storage_file.incomplete_proofs:  # not efficient
            if f.r_s2c is not None:
                r, padding, contract, pivot_pt = (f.r_s2c, x(f.padding), f.agt, x(f.pivot_pt))
                tx_raw = tx.serialize()
                if r in tx_raw:
                    i = tx_raw.find(r)
                    tx_p = x(tx_raw[:i])
                    tx_a = x(tx_raw[i + len(r):])
                    # contract -> txid
                    t_c = Timestamp(contract)
                    t = t_c.ops.add(OpPrepend(padding)) if len(padding) > 0 else t_c
                    t = t.ops.add(OpPrepend(pivot_pt))
                    t = t.ops.add(OpSecp256k1Commitment())
                    t = t.ops.add(OpPrepend(tx_p))
                    t = t.ops.add(OpAppend(tx_a))
                    t = t.ops.add(OpSHA256())
                    t = t.ops.add(OpSHA256())  # txid in little endian
                    tf = roll_timestamp(f.detached_timestamp.timestamp)
                    if tf.msg == contract:
                        tf.merge(t_c)
                        f.status = "pending"
                        f.txid = t.msg[::-1].hex()

        self.update_storage()

    def upgrade_timestamps_block(self, wallet, network):
        local_height = network.get_local_height()
        txid_pending = set([f.txid for f in self.proofs_storage_file.incomplete_proofs if f.status == "pending"])
        for txid in txid_pending:
            try:
                tx_height, timestamp, _ = wallet.verified_tx[txid]
                is_upgradable = (local_height - tx_height >= default_blocks_until_confirmed)
            except KeyError:
                is_upgradable = False
            if is_upgradable:  # txid -> block
                t = proof_from_txid_to_block(txid, tx_height, network)
                for f in self.proofs_storage_file.incomplete_proofs:
                    tf = roll_timestamp(f.detached_timestamp.timestamp)
                    if tf.msg == t.msg:
                        tf.merge(t)
                        f.status = "complete"
                        f.block = tx_height
                        f.date = timestamp_to_datetime(timestamp).strftime("%-d %B %Y")
                        f.write_ots()
                        # f.detached_timestamp = None
        self.update_storage()

    def update_storage(self):
        self.proofs_storage_file.update_db()
        self.proofs_storage_file.write_json()
        self.proofs_storage_file.read_json()  # drop timestamps common structure to stay more general

    @hook
    def transaction_dialog(self, d):
        if self.commitment_method == "op_return":
            d.timestamp_button = t = QPushButton(_("Timestamp"))
            t.clicked.connect(lambda: self.add_op_return_commitment(d))
            d.buttons.insert(0, t)
        if self.commitment_method == "s2c":
            d.s2c_button = s = QPushButton(_("S2C"))
            s.clicked.connect(lambda: self.add_s2c_commitment(d))
            d.buttons.insert(0, s)
        b = d.buttons[2]  # broadcast button
        b.clicked.connect(lambda: self.upgrade_timestamps_tx(d.tx))

    def add_op_return_commitment(self, d):
        fee_before = d.tx.get_fee() / d.tx.estimated_size()
        fee_after = d.tx.get_fee() / (d.tx.estimated_size() + 43)
        question = _("Including a timestamp increase the transaction size of 43 bytes.\n" +
                     " - Expected fee: " + str(fee_before)[:6] + " sat/vbyte\n" +
                     " - Actual fee: " + str(fee_after)[:6] + " sat/vbyte\n" +
                     "A lower fee may slow down confirmation time.\n"
                     "Note: you can timestamp for free using the public calendars, " +
                     "see https://opentimestamps.org\n\n" +
                     "Are you sure to include a timestamp in your transaction?")
        answer = QMessageBox.question(d, _("Transaction size increase"), question, QMessageBox.Ok, QMessageBox.Cancel)
        if answer == QMessageBox.No:
            return
        self.timestamp_op_return(d.tx)
        d.close()
        show_transaction(d.tx, d.main_window)

    def add_s2c_commitment(self, d):
        # FIXME: unsecure way of asking the password
        password, okPressed = QInputDialog.getText(d, "Password dialog", "Your password:", QLineEdit.Password, "")
        if okPressed and password != '':
            try:
                d.wallet.check_password(password)
            except InvalidPassword:
                return
        else:
            return
        contract = self.aggregate_timestamps()
        self.sign_to_contract(password, d.tx, d.wallet, contract)
        d.update()

    @hook
    def transaction_dialog_update(self, d):
        tp = [i for i in self.proofs_storage_file.incomplete_proofs if i.status in ["tracked", "aggregated"]]
        if self.commitment_method == "op_return":
            if len(tp) == 0 or any([o[0] == 2 for o in d.tx.outputs()]) or d.tx.is_complete():
                d.timestamp_button.setDisabled(True)
        if self.commitment_method == "s2c":
            if len(tp) == 0 or d.tx.is_complete() or d.tx.is_segwit():
                d.s2c_button.setDisabled(True)
                # actually a segwit tx with a non segwit input would allow s2c in the standard way, but we skip on that

    @hook
    def init_menubar_tools(self, window, tools_menu):
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Timestamps…"), partial(self.timestamp_dialog, window))

    def timestamp_dialog(self, window):
        d = WindowModalDialog(window, _("Timestamps"))
        d.setMinimumSize(900, 100)
        vbox = QVBoxLayout(d)
        self.timestamp_list = TimestampList(window, self.proofs_storage_file)
        vbox.addWidget(self.timestamp_list)
        button_add_file = EnterButton(_('Add New File'), partial(self.open_file, window))
        button_upgrade = EnterButton(_('Upgrade'), partial(self.do_upgrade, window))
        button_close = EnterButton(_('Close'), d.close)
        grid = QGridLayout()
        grid.addWidget(button_add_file, 0, 0)
        grid.addWidget(button_upgrade, 0, 1)
        grid.addWidget(button_close, 0, 2)
        vbox.addLayout(grid)
        return bool(d.exec_())

    def open_file(self, window):
        filename, __ = QFileDialog.getOpenFileName(window, "Select a new file to timestamp", default_folder)
        if not filename:
            return
        if self.track_new_file(filename):
            self.timestamp_list.on_update()
        else:
            question = _("Duplicate files cannot be added to the timestamp storage.")
            answer = QMessageBox.question(window, _("Duplicate file"), question, QMessageBox.Ok)
            if answer == QMessageBox.Ok:
                return

    def do_upgrade(self, window):
        self.upgrade_timestamps_txs(window.wallet)  # useful only if the tx is broadcasted without the plugin
        self.upgrade_timestamps_block(window.wallet, window.network)
        self.timestamp_list.db = self.proofs_storage_file.db
        self.timestamp_list.on_update()

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Timestamp settings"))
        vbox = QVBoxLayout(d)
        grid = QGridLayout()

        def check_state_opr():
            if c_opr.isChecked():
                self.commitment_method = "op_return"

        def check_state_s2c():
            if not c_opr.isChecked():
                self.commitment_method = "s2c"

        c_opr = QRadioButton(_('Use OP_RETURN'))
        c_opr.setChecked(self.commitment_method == "op_return")
        c_opr.toggled.connect(check_state_opr)
        c_s2c = QRadioButton(_('Use sign-to-contract'))
        c_s2c.setChecked(self.commitment_method == "s2c")
        c_s2c.toggled.connect(check_state_s2c)
        h_opr = HelpButton("Include commitment inside a OP_RETURN. "
                           "\nThis will make your transaction 43 bytes longer, nevertheless the amounts (and hence the "
                           "fees) won't be modified, as result you will obtain a transaction with lower sat/vbytes "
                           "which may slow down its confirmation time.")
        h_s2c = HelpButton("Include commitment inside the signature using sign-to-contract, with zero marginal cost"
                           "\nFor now, it does not work with segwit transactions")
        grid.addWidget(c_opr, 1, 1)
        grid.addWidget(h_opr, 1, 2)
        grid.addWidget(c_s2c, 2, 1)
        grid.addWidget(h_s2c, 2, 2)
        vbox.addLayout(grid)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d), CancelButton(d)))
        return bool(d.exec_())
