from idaapi import PluginForm
import ida_kernwin
from PyQt5 import QtCore, QtWidgets
import idautils
import idaapi
import idc

class Comment:
    def __init__(self, address, comment_type, comment, function_name):
        self.address = address
        self.comment_type = comment_type
        self.comment = comment
        self.function_name = function_name

class CommentTableModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None, *args):
        super(CommentTableModel, self).__init__()
        self.table_data = []

    def append(self, comment):
        self.beginInsertRows(QtCore.QModelIndex(), len(self.table_data), len(self.table_data))
        self.table_data.append(comment)
        self.endInsertRows()

    def columnCount(self, parent=QtCore.QModelIndex()):
        return 4

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if (not index.isValid()) or (role != QtCore.Qt.DisplayRole):
            return QtCore.QVariant()
        
        comment = self.table_data[index.row()]
        match index.column():
            case 0:
                return comment.address
            case 1:
                return comment.comment_type
            case 2:
                return comment.comment
            case 3:
                return comment.function_name
            case _:
                return QtCore.QVariant()

    def dataAt(self, index):
        return self.table_data[index.row()]

    def headerData(self, column, orientation, role):
        if (orientation != QtCore.Qt.Horizontal) or (role != QtCore.Qt.DisplayRole):
            return QtCore.QVariant()
        
        match column:
            case 0:
                return "Address"
            case 1:
                return "Type"
            case 2:
                return "Comment"
            case 3:
                return "Function Name"
            case _:
                return QtCore.QVariant()

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.table_data)

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
        self.filter_input.setPlaceholderText("Search...")
        self.filter_input.returnPressed.connect(self.filter_comments)
        layout.addWidget(self.filter_input)
        # table 
        self.table = QtWidgets.QTableView()
        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        # populate table
        self.reset_and_populate()
        self.table.doubleClicked.connect(self.fn_get_cell_Value)
        layout.addWidget(self.table)
        # make our created layout the dialogs layout
        self.parent.setLayout(layout)

    def add_row(self, item_index, ea, cmt, cmt_type, function_name):
        self.table_model.append(Comment(hex(ea), cmt_type, cmt, function_name))
        item_index += 1
        return item_index

    def filter_comments(self):
        if keyword := self.filter_input.text():
            self.proxy_model.setFilterRegularExpression(keyword)
        else:
            self.proxy_model.setFilterRegularExpression(".*")

    def populate_with_comments(self, item_index):
        current_function_name = None
        for ea in idautils.Heads():
            # Check if the first address of a function contains a function (repeatable) comment
            # IDAPython cheatsheet (https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c)
            function_name = idaapi.get_func_name(ea)
            if function_name != current_function_name:
                if function_cmt := idc.get_func_cmt(ea, True):
                    item_index = self.add_row(item_index, ea, function_cmt, "Function", function_name)
                current_function_name = function_name
            # Check if the address contains a regular (non-repeatable) comment
            if cmt := idaapi.get_cmt(ea, False):
                item_index = self.add_row(item_index, ea, cmt, "Regular", function_name)
            # Now check if it contains a repeatable comment
            if cmt := idaapi.get_cmt(ea, True):
                item_index = self.add_row(item_index, ea, cmt, "Repeatable", function_name)
            # Now check if it contains an anterior comment
            cmt_data = []
            cmt_idx = 0
            while cmt := idaapi.get_extra_cmt(ea, idaapi.E_PREV + cmt_idx):
                cmt_data.append(cmt)
                cmt_idx += 1
            if cmt_data:
                item_index = self.add_row(item_index, ea, " ".join(cmt_data), "Anterior", function_name)
            # Finally, check if it contains a posterior comment
            cmt_data = []
            cmt_idx = 0
            while cmt := idaapi.get_extra_cmt(ea, idaapi.E_NEXT + cmt_idx):
                cmt_data.append(cmt)
                cmt_idx += 1
            if cmt_data:
                item_index = self.add_row(item_index, ea, " ".join(cmt_data), "Posterior", function_name)

    def reset_and_populate(self):
        # reset
        try:
            self.proxy_model.clear()
            self.table.setModel(None)
        except AttributeError:
            pass
        item_index = 0
        # populate
        self.table_model = CommentTableModel(self.table)
        self.populate_with_comments(item_index)
        # make proxy model
        self.proxy_model = QtCore.QSortFilterProxyModel(self.table)
        self.proxy_model.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(2)
        self.proxy_model.setSourceModel(self.table_model)
        # use proxy model and resize
        self.table.setModel(self.proxy_model)
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(1)
        self.table.resizeColumnToContents(2)
        self.table.horizontalHeader().setStretchLastSection(True)

    def fn_get_cell_Value(self, index):
        # If the user clicked an address, follow it in IDA View
        if index.column() == 0:
            value = index.data()
            ida_kernwin.jumpto(int(value, base=16))
 
    def OnClose(self, form):
        pass

class showcomments_plugin_t(idaapi.plugin_t):
    comment = "ShowComments"
    version = "0.5.0"
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
