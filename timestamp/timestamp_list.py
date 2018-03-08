from electrum.i18n import _
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView, QTreeWidgetItem, QMenu, QMessageBox
from electrum_gui.qt.util import MyTreeWidget


class TimestampList(MyTreeWidget):
    filter_columns = [0, 1]

    def __init__(self, parent, proofs_storage):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Path'), _('Date')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.proofs_storage = proofs_storage
        if self.proofs_storage.db:
            self.on_update()

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        path = item.data(0, Qt.UserRole)
        menu = QMenu()
        menu.addAction(_("Remove…"), lambda: self.remove(path))
        menu.exec_(self.viewport().mapToGlobal(position))

    def remove(self, path):
        question = _("Are you sure you want to remove this timestamp?")
        answer = QMessageBox.question(self.parent, _("Please confirm"), question, QMessageBox.Ok, QMessageBox.Cancel)
        if answer == QMessageBox.Ok:
            self.proofs_storage.remove_path(path)
            self.on_update()

    def on_update(self):
        item = self.currentItem()
        current_path = item.data(0, Qt.UserRole) if item else None
        self.clear()
        for d in ordered_db(self.proofs_storage.db):
            path = d["path"]
            date = d["date"] if d["date"] else "Yet to be confirmed"
            status = d["status"]
            agt = d["agt"] if d["agt"] else ""
            txid = d["txid"] if d["txid"] else ""
            block = str(d["block"]) if d["block"] else ""
            tool_tip = "Status: " + status + \
                       "\nAggregation tip: " + agt + \
                       "\nTXID: " + txid + \
                       "\nBlock: " + block
            item = QTreeWidgetItem([path, date])
            # use a selection of the available icons
            if status == "tracked":
                pic = "status_connected_proxy.png"  # blue circle
            elif status == "aggregated":
                pic = "status_lagging.png"  # brown circle
            elif status == "pending":
                pic = "unconfirmed.png"
            else:  # confirmed
                pic = "confirmed.png"
            icon = QIcon(":icons/" + pic)
            item.setIcon(0, icon)
            item.setToolTip(0, tool_tip)
            item.setData(0, Qt.UserRole, path)
            self.addTopLevelItem(item)
            if path == current_path:
                self.setCurrentItem(item)


def ordered_db(db):
    odb = []
    for s in ["tracked", "aggregated", "pending"]:
        odb += sorted([d for d in db if d["status"] == s], key=lambda b: b["path"])
    odb += sorted([d for d in db if d["status"] == "complete"], key=lambda b: b["date"], reverse=True)
    return odb
