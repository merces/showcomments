# Skeleton based on https://github.com/x64dbg/x64dbgida/blob/master/x64dbgida.py - thanks for that :)

from idaapi import PluginForm
import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets
import idautils
import idaapi
import idc

class ShowComments(PluginForm):

    matching_items = None
    matching_index = 0

    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # search query
        self.query = QtWidgets.QLineEdit()
        self.query.setPlaceholderText("Search...")
        self.query.textChanged.connect(self.search)
        self.query.returnPressed.connect(self.search_next)

        # table 
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(4)
        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.table.setHorizontalHeaderLabels(["Address", "Type", "Comment", "Function Name"])
        self.table.setSortingEnabled(True)

        item_index = 0
        current_function_name = None

        for ea in idautils.Heads():
            # Check if the first address of a function contains a function (repeatable) comment
            # IDAPython cheatsheet (https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c)
            function_name = idaapi.get_func_name(ea)
            if function_name != current_function_name:
                function_cmt = idc.get_func_cmt(ea, True)
                if function_cmt:
                    item_index = self.add_row(item_index, ea, function_cmt, "Function", function_name)
                current_function_name = function_name

                # Check if the address contains a regular (non-repeatable) comment
            cmt = idaapi.get_cmt(ea, False)
            if cmt:
                item_index = self.add_row(item_index, ea, cmt, "Regular", function_name)
            # Now check if it contains a repeatable comment
            cmt = idaapi.get_cmt(ea, True)
            if cmt:
                item_index = self.add_row(item_index, ea, cmt, "Repeatable", function_name)
                
        self.table.resizeColumnsToContents()
        self.table.doubleClicked.connect(self.fn_get_cell_Value)
        layout.addWidget(self.table)
        layout.addWidget(self.query)

        # make our created layout the dialogs layout
        self.parent.setLayout(layout)

    def add_row(self, item_index, ea, cmt, cmt_type, function_name):
        self.table.insertRow(self.table.rowCount())
        self.table.setItem(item_index, 0, QtWidgets.QTableWidgetItem(hex(ea)))
        self.table.setItem(item_index, 1, QtWidgets.QTableWidgetItem(cmt_type))
        self.table.setItem(item_index, 2, QtWidgets.QTableWidgetItem(cmt))
        self.table.setItem(item_index, 3, QtWidgets.QTableWidgetItem(function_name))
        item_index += 1
        return item_index
    
    def search(self, s):
        global matching_items
        global matching_index
        if not s:
            self.table.setCurrentItem(None)
            matching_items = None
            return
        matching_items = self.table.findItems(s, QtCore.Qt.MatchContains)
        if matching_items:
            matching_index = 0
            self.table.setCurrentItem(matching_items[0])
    
    def search_next(self):
        # If the user pressed Enter in search query, select next matching item
        global matching_index
        if matching_items:
            if matching_index == len(matching_items) - 1:
                matching_index = 0
                self.table.setCurrentItem(matching_items[0])
            else:
                matching_index += 1
                self.table.setCurrentItem(matching_items[matching_index])

    def fn_get_cell_Value(self, index):
        # If the user clicked an address, follow it in IDA View
        if index.column() == 0:
            value = index.data()
            ida_kernwin.jumpto(int(value, base=16))
 
    def OnClose(self, form):
        pass


class showcomments_plugin_t(idaapi.plugin_t):
    comment = "ShowComments"
    version = "v0.4"
    website = "https://github.com/merces/showcomments"
    help = ""
    wanted_name = "ShowComments"
    wanted_hotkey = "Ctrl-Alt-C"
    flags = idaapi.PLUGIN_OK

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = ShowComments()
        plg.Show("Comments")
        pass

    def term(self):
        return


def PLUGIN_ENTRY():
    return showcomments_plugin_t()