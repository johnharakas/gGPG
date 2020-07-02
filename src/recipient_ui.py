# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'recipient_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtWidgets


class Ui_Recipient_Dialog(object):
    def setupUi(self, Recipient_Dialog):
        Recipient_Dialog.setObjectName("Recipient_Dialog")
        Recipient_Dialog.resize(400, 381)
        self.buttonBox = QtWidgets.QDialogButtonBox(Recipient_Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(40, 330, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.list_recipients = QtWidgets.QListWidget(Recipient_Dialog)
        self.list_recipients.setGeometry(QtCore.QRect(20, 30, 351, 261))
        self.list_recipients.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.list_recipients.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectItems)
        self.list_recipients.setObjectName("list_recipients")

        self.retranslateUi(Recipient_Dialog)
        self.buttonBox.accepted.connect(Recipient_Dialog.accept)
        self.buttonBox.rejected.connect(Recipient_Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Recipient_Dialog)

    def retranslateUi(self, Recipient_Dialog):
        _translate = QtCore.QCoreApplication.translate
        Recipient_Dialog.setWindowTitle(_translate("Recipient_Dialog", "Recipients"))
