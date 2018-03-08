from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum_gui.qt import EnterButton
from electrum_gui.qt.util import WindowModalDialog
from electrum_gui.qt.transaction_dialog import show_transaction
from electrum.util import timestamp_to_datetime
from .timestamp_list import TimestampList

from PyQt5.QtWidgets import QVBoxLayout, QGridLayout, QPushButton, QFileDialog, QMessageBox
from functools import partial
import json
import base64
import binascii
import os

try:
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile, make_merkle_tree, cat_sha256d
    from opentimestamps.core.op import Op, OpAppend, OpPrepend, OpSHA256
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
default_folder = os.path.expanduser("~user")


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
        self.txid = None
        self.block = None
        self.date = None
        self.detached_timestamp = None

    def from_file(self, path):
        self.path = path
        self.status = "tracked"
        self.agt = None
        self.txid = None
        self.block = None
        self.date = None
        with open(self.path, "rb") as fo:
            self.detached_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fo)

    def from_db(self, d):
        self.path = d["path"]
        self.status = d["status"]
        self.agt = bytes.fromhex(d["agt"]) if d["agt"] else d["agt"]
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

    def upgrade_timestamps_txs(self, wallet):
        for txid, tx in wallet.transactions.items():
            if txid in wallet.verified_tx.keys():
                self.upgrade_timestamps_tx(tx)

    def upgrade_timestamps_tx(self, tx):
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
                        f.date = str(timestamp_to_datetime(timestamp))
                        f.write_ots()
                        # f.detached_timestamp = None
        self.update_storage()

    def update_storage(self):
        self.proofs_storage_file.update_db()
        self.proofs_storage_file.write_json()
        self.proofs_storage_file.read_json()  # drop timestamps common structure to stay more general

    @hook
    def transaction_dialog(self, d):
        d.timestamp_button = t = QPushButton(_("Timestamp"))
        t.clicked.connect(lambda: self.add_op_return_commitment(d))
        d.buttons.insert(0, t)
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

    @hook
    def transaction_dialog_update(self, d):
        tp = [i for i in self.proofs_storage_file.incomplete_proofs if i.status in ["tracked", "aggregated"]]
        if len(tp) == 0 or any([o[0] == 2 for o in d.tx.outputs()]) or d.tx.is_complete():
            d.timestamp_button.setDisabled(True)

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
