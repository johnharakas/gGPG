import sys
from functools import partial
from pathlib import Path

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication, QFileDialog, QDialog, QPlainTextEdit

import gpg_utils
from ggpg_ui import Ui_TabWindow
from recipient_ui import Ui_Recipient_Dialog


class Recipient_Ui(QDialog, Ui_Recipient_Dialog):
    def __init__(self, pubkeys):
        super(Recipient_Ui, self).__init__()
        self.setupUi(self)
        self.pubkeys_loaded = pubkeys
        self.selected = []
        self.get_recipients()
        self.show()

    def get_recipients(self):
        """
        Create list widget of recipients.
        :return: None
        """
        for idx, key in enumerate(self.pubkeys_loaded):
            item = QtWidgets.QListWidgetItem()
            item.setCheckState(QtCore.Qt.Unchecked)
            item.setText(key)
            self.list_recipients.addItem(item)
        self.buttonBox.clicked.connect(self.return_recipients)

    def return_recipients(self):
        """
        Select checked recipients and return to the main window.
        :return: selected - list of dictionary keys for App.pubkeys_loaded
        """
        print('RECIPIENTS')
        for index in range(self.list_recipients.count()):
            item = self.list_recipients.item(index)
            print('Item {} {}'.format(item.checkState(),item.text()))
            if item.checkState() == QtCore.Qt.Checked:
                self.selected.append(item.text())
        self.accept()


class App(QtWidgets.QMainWindow, Ui_TabWindow):
    def __init__(self, parent=None):
        super(App, self).__init__(parent)
        self.setupUi(self)
        self.actionQuit.triggered.connect(self.close)

        self.main_labelGPGversion.setText(gpg_utils.gpg_version)
        self.main_buttonSelectHome.clicked.connect(self.set_homedir)
        self.home_dir = str(Path.home())
        self.text_logOutput.appendPlainText('setting homedir: {}'.format(self.home_dir))
        self.main_labelHomeDir.setText(self.home_dir)

        self.encrypt_buttonImport.clicked.connect(partial(self.import_file, 'encrypt_textInput'))
        self.encrypt_buttonRecipients.clicked.connect(self.select_recipients)
        self.encrypt_buttonEncrypt.clicked.connect(self.encrypt_text)

        self.decrypt_buttonImport.clicked.connect(partial(self.import_file, 'decrypt_textInput'))
        self.decrypt_buttonDecrypt.clicked.connect(self.decrypt_text)

        self.sign_buttonSign.clicked.connect(self.sign_text)
        self.sign_buttonImport.clicked.connect(partial(self.import_file, 'sign_textInput'))

        self.verify_buttonImport.clicked.connect(partial(self.import_file, 'verify_textInput'))
        self.verify_buttonVerify.clicked.connect(self.verify_text)

        self.keyring_buttonImportKey.clicked.connect(self.import_public_key)
        self.keyring_buttonImport.clicked.connect(partial(self.import_file, 'keyring_textInput'))

        self.current_key = ()
        self.pubkeys_loaded = {}
        self.privkeys_loaded = {}
        self.lookup_keys()
        self.combo_currentKey.currentIndexChanged.connect(self.update_current_key)

    def set_homedir(self):
        path = QFileDialog.getExistingDirectory(self,
                                                    "Open Directory",
                                                    str(Path.home()),
                                                    QFileDialog.ShowDirsOnly
                                                    | QFileDialog.DontResolveSymlinks)
        if path:
            self.home_dir = path
            print(path)
            self.main_labelHomeDir.setText(self.home_dir)
        gpg_utils.gpg = gpg_utils.set_homedir(dir=self.home_dir)
        print('setting gpg homedir:')
        print(gpg_utils.gpg.gnupghome)
        self.text_logOutput.appendPlainText('setting homedir: {}'.format(self.home_dir))
        return

    def lookup_keys(self):
        # Lookup private keys
        self.privkeys_loaded = gpg_utils.keyring_info(private=True)
        print('Found {} key(s)'.format(len(self.privkeys_loaded)))
        for idx, key in enumerate(self.privkeys_loaded):
            print(key)
            self.combo_currentKey.addItem("")
            self.combo_currentKey.setItemText(idx, key)

        self.pubkeys_loaded = gpg_utils.keyring_info(private=False)
        self.update_current_key()

    def update_current_key(self):
        self.current_key = self.privkeys_loaded[self.combo_currentKey.currentText()]
        print('Current Key: {} {}'.format(self.current_key['uids'], self.current_key['keyid']))

    def import_file(self, box):
        child = self.findChild(QPlainTextEdit, box)
        text = self.select_file()
        child.setPlainText(text)

    def import_public_key(self):
        self.text_logOutput.appendPlainText('importing new public key...')
        pubkey = self.keyring_textInput.toPlainText()
        imported = gpg_utils.import_key(pubkey)
        self.text_logOutput.appendPlainText(imported.stderr)
        return

    def encrypt_text(self):
        if not hasattr(self, 'selected_recipients'):
            self.select_recipients()
        recipients = []
        for recip in self.recipientDialog.selected:
            recipients.append(self.pubkeys_loaded[recip]['uids'][0])
        if len(recipients) > 0:
            data = self.encrypt_textInput.toPlainText()
            self.text_logOutput.appendPlainText('encrypting data: {} chars'.format(len(data)))
            encrypted = gpg_utils.encrypt_text(data=data, recipients=recipients)
            self.text_logOutput.appendPlainText(encrypted.stderr)
            self.encrypt_textOutput.setPlainText(encrypted.data.decode())

    def select_recipients(self):
        self.encrypt_listRecipient.clear()
        self.recipientDialog = Recipient_Ui(pubkeys=self.pubkeys_loaded)
        if self.recipientDialog.exec_():
            self.selected_recipients = self.recipientDialog.selected
            for recip in self.selected_recipients:
                print(recip)
                item = QtWidgets.QListWidgetItem()
                item.setText(recip)
                self.encrypt_listRecipient.addItem(item)
                self.text_logOutput.appendPlainText('adding recipient: {}'.format(recip))
            return self.selected_recipients

    def decrypt_text(self):
        print('decrypting')
        data = self.decrypt_textInput.toPlainText()
        decrypted = gpg_utils.decrypt_text(data)
        print(decrypted.data.decode())
        self.text_logOutput.appendPlainText(decrypted.stderr)
        self.decrypt_textOutput.setPlainText(decrypted.data.decode())
        return

    def verify_text(self):
        data = self.verify_textInput.toPlainText()
        verified = gpg_utils.verify_signature(data)
        if verified:
            id = next(iter(verified.sig_info.keys()))
            sig_info = verified.sig_info[id] # Get the dict key

            form = '''VERIFIED\n'''
            form += 'timestamp (formatted) {}\n'.format(gpg_utils.format_time(sig_info['timestamp']))
            for key in sig_info:
                form += (key + ':' + str(sig_info[key]) + '\n')
                print(key, ':', sig_info[key])
        else:
            form = '''UNVERIFIED'''
        self.text_logOutput.appendPlainText(verified.stderr)
        self.verify_textOutput.setPlainText(form)

    def sign_text(self):
        keyid = self.current_key['keyid']
        data = self.sign_textInput.toPlainText()
        if data:
            signed_data = gpg_utils.sign_data(data, keyid=keyid)
            if signed_data:
                print(signed_data.data.decode())
                self.sign_textOutput.setPlainText(signed_data.data.decode())
            self.text_logOutput.appendPlainText(signed_data.stderr)

    def select_file(self):
        filename = QFileDialog.getOpenFileName(self, 'Open File', str(Path.home()))
        if filename[0]:
            print(filename)
            with open(filename[0], 'r') as file:
                text = file.read()
                return text
        return


def main():
    app = QApplication(sys.argv)
    form = App()
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()