# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'KeyViewer.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_KeyViewer(object):
    def setupUi(self, KeyViewer):
        KeyViewer.setObjectName("KeyViewer")
        KeyViewer.resize(601, 516)
        self.key_textOutput = QtWidgets.QPlainTextEdit(KeyViewer)
        self.key_textOutput.setGeometry(QtCore.QRect(20, 70, 551, 401))
        font = QtGui.QFont()
        font.setFamily("Fira Mono")
        self.key_textOutput.setFont(font)
        self.key_textOutput.setObjectName("key_textOutput")
        self.armor_check = QtWidgets.QCheckBox(KeyViewer)
        self.armor_check.setGeometry(QtCore.QRect(30, 40, 90, 31))
        self.armor_check.setObjectName("armor_check")
        self.widget = QtWidgets.QWidget(KeyViewer)
        self.widget.setGeometry(QtCore.QRect(20, 10, 551, 27))
        self.widget.setObjectName("widget")
        self.gridLayout = QtWidgets.QGridLayout(self.widget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.label_key = QtWidgets.QLabel(self.widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_key.sizePolicy().hasHeightForWidth())
        self.label_key.setSizePolicy(sizePolicy)
        self.label_key.setObjectName("label_key")
        self.gridLayout.addWidget(self.label_key, 0, 0, 1, 1)
        self.combo_keyList = QtWidgets.QComboBox(self.widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.combo_keyList.sizePolicy().hasHeightForWidth())
        self.combo_keyList.setSizePolicy(sizePolicy)
        self.combo_keyList.setObjectName("combo_keyList")
        self.gridLayout.addWidget(self.combo_keyList, 0, 1, 1, 1)
        self.widget1 = QtWidgets.QWidget(KeyViewer)
        self.widget1.setGeometry(QtCore.QRect(200, 480, 168, 27))
        self.widget1.setObjectName("widget1")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget1)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.button_save = QtWidgets.QPushButton(self.widget1)
        self.button_save.setObjectName("button_save")
        self.horizontalLayout.addWidget(self.button_save)
        self.button_close = QtWidgets.QPushButton(self.widget1)
        self.button_close.setObjectName("button_close")
        self.horizontalLayout.addWidget(self.button_close)

        self.retranslateUi(KeyViewer)
        QtCore.QMetaObject.connectSlotsByName(KeyViewer)

    def retranslateUi(self, KeyViewer):
        _translate = QtCore.QCoreApplication.translate
        KeyViewer.setWindowTitle(_translate("KeyViewer", "Key Viewer"))
        self.armor_check.setText(_translate("KeyViewer", "Armor"))
        self.label_key.setText(_translate("KeyViewer", "Key:   "))
        self.button_save.setText(_translate("KeyViewer", "Save"))
        self.button_close.setText(_translate("KeyViewer", "Close"))
