# Skeleton based on https://github.com/x64dbg/x64dbgida/blob/master/x64dbgida.py - thanks for that :)

from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
import idautils
import idaapi
import idc


class ShowComments(PluginForm):

    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()


    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # Create input for keyword
        self.filter_input = QtWidgets.QLineEdit(self.parent)
        self.filter_input.textChanged.connect(self.filter_comments)
        layout.addWidget(self.filter_input)


        # table 
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(4)
        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.table.setHorizontalHeaderLabels(["Address", "Type", "Comment", "Function Name"])
        self.table.setSortingEnabled(True)

        self.reset_and_populate()
        self.table.doubleClicked.connect(self.fn_get_cell_Value)
        layout.addWidget(self.table)

        # make our created layout the dialogs layout
        self.parent.setLayout(layout)
    def add_row(self, item_index, ea, cmt, cmt_type, function_name):
        self.table.insertRow(self.table.rowCount());
        self.table.setItem(item_index, 0, QtWidgets.QTableWidgetItem(hex(ea)))
        self.table.setItem(item_index, 1, QtWidgets.QTableWidgetItem(cmt_type))
        self.table.setItem(item_index, 2, QtWidgets.QTableWidgetItem(cmt))
        self.table.setItem(item_index, 3, QtWidgets.QTableWidgetItem(function_name))
        item_index += 1
        return item_index
    def filter_comments(self):
        keyword = self.filter_input.text()
        if not keyword:
            # No keyword to filter on, repopulate the whole table
            self.reset_and_populate()
            return

        # Clear the current table
        self.table.setRowCount(0)

        item_index = 0
        current_function_name = None

        for ea in idautils.Heads():
            function_name = idaapi.get_func_name(ea)
            function_cmt = idc.get_func_cmt(ea, True)
            if function_name != current_function_name and function_cmt:
                if keyword.lower() in function_cmt.lower():
                    item_index = self.add_row(item_index, ea, function_cmt, "Function", function_name)
                current_function_name = function_name

            # Check for regular and repeatable comments
            cmt = idaapi.get_cmt(ea, False)
            repeat_cmt = idaapi.get_cmt(ea, True)

            if cmt and keyword.lower() in cmt.lower():
                item_index = self.add_row(item_index, ea, cmt, "Regular", function_name)
            elif repeat_cmt and keyword.lower() in repeat_cmt.lower():
                item_index = self.add_row(item_index, ea, repeat_cmt, "Repeatable", function_name)
    def reset_and_populate(self):
        self.table.setRowCount(0)  
        item_index = 0
        current_function_name = None
        for ea in idautils.Heads():
            function_name = idaapi.get_func_name(ea)
            if function_name != current_function_name:
                function_cmt = idc.get_func_cmt(ea, True)
                if function_cmt:
                    item_index = self.add_row(item_index, ea, function_cmt, "Function", function_name)
                current_function_name = function_name

            cmt = idaapi.get_cmt(ea, False)
            if cmt:
                item_index = self.add_row(item_index, ea, cmt, "Regular", function_name)

            cmt = idaapi.get_cmt(ea, True)
            if cmt:
                item_index = self.add_row(item_index, ea, cmt, "Repeatable", function_name)

        self.table.resizeColumnsToContents()
    def fn_get_cell_Value(self, index):
        # If the user clicked an address, follow it in IDA View
        if index.column() == 0:
            value =  index.data()
            idaapi.jumpto(int(value, base=16), 0, 0)
 
    def OnClose(self, form):
        pass


class showcomments_plugin_t(idaapi.plugin_t):
    comment = "ShowComments"
    version = "v0.3"
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