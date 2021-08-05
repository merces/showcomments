# Skeleton based on https://github.com/x64dbg/x64dbgida/blob/master/x64dbgida.py - thanks for that :)

from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
import idautils
import idaapi

class ShowComments(PluginForm):
    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()


    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # table 
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(3)
        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.table.setHorizontalHeaderLabels(["Address", "Type", "Comment"])
        self.table.setSortingEnabled(True)

        item_index=0
        for ea in idautils.Heads():
        	  # Check if the address contains a regular (non-repeatable) comment
            cmt = idaapi.get_cmt(ea, False)
            if cmt:
                self.table.insertRow(self.table.rowCount());
                self.table.setItem(item_index, 0, QtWidgets.QTableWidgetItem(hex(ea)))
                self.table.setItem(item_index, 1, QtWidgets.QTableWidgetItem("Regular"))
                self.table.setItem(item_index, 2, QtWidgets.QTableWidgetItem(cmt))
                item_index += 1           
            # Now check if it contains a repeatable comment
            cmt = idaapi.get_cmt(ea, True)
            if cmt:
                self.table.insertRow(self.table.rowCount());
                self.table.setItem(item_index, 0, QtWidgets.QTableWidgetItem(hex(ea)))
                self.table.setItem(item_index, 1, QtWidgets.QTableWidgetItem("Repeatable"))
                self.table.setItem(item_index, 2, QtWidgets.QTableWidgetItem(cmt))
                item_index += 1
                
        self.table.resizeColumnsToContents()
        self.table.doubleClicked.connect(self.fn_get_cell_Value)
        layout.addWidget(self.table)

        # make our created layout the dialogs layout
        self.parent.setLayout(layout)


    def fn_get_cell_Value(self, index):
        # If the user clicked an address, follow it in IDA View
        if index.column() == 0:
            value =  index.data()
            idaapi.jumpto(int(value, base=16), 0, 0)

 
    def OnClose(self, form):
        pass



class showcomments_plugin_t(idaapi.plugin_t):
    comment = "ShowComments"
    version = "v0.2"
    website = "https://github.com/merces/showcomments"
    help = ""
    wanted_name = "ShowComments"
    wanted_hotkey = "Ctrl-Alt-C"
    flags = idaapi.PLUGIN_OK

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = ShowComments()
        plg.Show(self.comment + " " + self.version)
        pass

    def term(self):
        return


def PLUGIN_ENTRY():
    return showcomments_plugin_t()