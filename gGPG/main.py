import logging
import os
import sys
from functools import partial
from pathlib import Path

import magic
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication, QFileDialog, QDialog, QPlainTextEdit

import gpg_utils
from ggpg_ui import Ui_TabWindow
from gpg_utils import GPG_Handler
from keyView_ui import Ui_KeyViewer
from recipient_ui import Ui_Recipient_Dialog

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
logger.addHandler(handler)


class KeyView_Ui(QDialog, Ui_KeyViewer):
    def __init__(self, gpg, keys):
        super(KeyView_Ui, self).__init__()
        self.setupUi(self)

        self.button_close.clicked.connect(self.close)
        self.button_save.clicked.connect(self.save_key)
        self.gpg = gpg
        self.keys = keys
        self.current_key = None
        self.load_keys()
        self.combo_keyList.currentIndexChanged.connect(self.update_current_key)
        self.show()

    def update_current_key(self):
        self.current_key = self.keys[self.combo_keyList.currentText()]
        logger.debug('Current key changed to: {}{}'.format(self.current_key['keyid'], self.current_key['uids']))
        self.key_textOutput.setPlainText(self.current_key['keyblock'])

    def load_keys(self):
        for idx, key in enumerate(self.keys):
            # Get the block for each key in self.keys
            # Create new dictionary field 'keyblock'
            self.keys[key]['keyblock'] = self.gpg.handle_export(self.keys[key], armor=True)
            self.combo_keyList.addItem("")
            self.combo_keyList.setItemText(idx, key)
        self.update_current_key()

    def save_key(self):
        default_name = self.current_key['uids'][0] + '.gpg'
        if self.armor_check.isChecked():
            text = self.current_key['keyblock']
        else:
            text = self.gpg.handle_export(self.current_key, armor=False)
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename, _ = QFileDialog.getSaveFileName(self, "Open", default_name, "All Files (*.*)", options=options)
        logger.debug('saving key to: {}'.format(filename))

        flags = 'w'
        if type(text) is bytes:
            flags += 'b'
        if filename:
            with open(filename, flags) as file:
                file.write(text)
        return


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
        for index in range(self.list_recipients.count()):
            item = self.list_recipients.item(index)
            if item.checkState() == QtCore.Qt.Checked:
                self.selected.append(item.text())
        self.accept()


class App(QtWidgets.QMainWindow, Ui_TabWindow):
    def __init__(self, parent=None):
        super(App, self).__init__(parent)
        logger.debug('Creating class %s' % self)

        self.default_home = str(Path.home())

        if os.path.exists(self.default_home + '/.gnupg'):
            self.home_dir = self.default_home + '/.gnupg'
        else:
            self.home_dir = self.default_home
        logger.debug('Using directory %s' % self.home_dir)

        self.gpg = GPG_Handler(homedir=self.home_dir)
        logger.debug('GPG Handler created.')

        self.setupUi(self)
        self.actionQuit.triggered.connect(self.close)

        self.main_labelGPGversion.setText(self.gpg.gpg_version)
        self.main_buttonSelectHome.clicked.connect(self.set_homedir)
        self.text_logOutput.appendPlainText('setting gpg homedir: {}'.format(self.home_dir))
        self.main_exportPubkey.clicked.connect(self.view_key)
        self.main_labelHomeDir.setText(self.home_dir)


        self.encrypt_buttonImport.clicked.connect(partial(self.import_file, 'encrypt_textInput'))
        self.encrypt_buttonRecipients.clicked.connect(self.select_recipients)
        self.encrypt_buttonEncrypt.clicked.connect(self.encrypt_text)
        self.encrypt_buttonSave.clicked.connect(partial(self.save_file, 'encrypt_textOutput'))

        self.symmetric_buttonImport.clicked.connect(partial(self.import_file, 'symmetric_textInput'))
        self.symmetric_buttonEncrypt.clicked.connect(self.encrypt_symmetric)
        self.symmetric_buttonSave.clicked.connect(partial(self.save_file, 'symmetric_textOutput'))

        self.decrypt_buttonImport.clicked.connect(partial(self.import_file, 'decrypt_textInput'))
        self.decrypt_buttonDecrypt.clicked.connect(self.decrypt_text)
        self.decrypt_buttonSave.clicked.connect(partial(self.save_file, 'decrypt_textOutput'))

        self.sign_buttonSign.clicked.connect(self.sign_text)
        self.sign_buttonImport.clicked.connect(partial(self.import_file, 'sign_textInput'))
        self.sign_buttonSave.clicked.connect(partial(self.save_file, 'sign_textOutput'))

        self.verify_buttonImport.clicked.connect(partial(self.import_file, 'verify_textInput'))
        self.verify_buttonVerify.clicked.connect(self.verify_text)
        self.verify_buttonSave.clicked.connect(partial(self.save_file, 'verify_textOutput'))

        self.keyring_buttonSelectKeyring.clicked.connect(self.select_keyring)
        self.keyring_buttonImportKey.clicked.connect(self.import_public_key)
        self.keyring_buttonImport.clicked.connect(partial(self.import_file, 'keyring_textInput'))

        self.keyrings = []
        self.current_key = ()
        self.pubkeys_loaded = {}
        self.privkeys_loaded = {}
        self.lookup_secret_keys()
        self.lookup_public_keys()
        self._output_buffer = []

        self.combo_currentKey.currentIndexChanged.connect(self.update_current_key)

    def log(self, msg):
        self.text_logOutput.appendPlainText(msg)

    def set_homedir(self):
        old_dir = self.home_dir

        path = QFileDialog.getExistingDirectory(self,
                                                    "Open Directory",
                                                    str(Path.home()),
                                                    QFileDialog.ShowDirsOnly
                                                    | QFileDialog.DontResolveSymlinks)
        if path:
            self.home_dir = path
            print(path)
            self.main_labelHomeDir.setText(self.home_dir)

        # TODO: better way to handle when a new home dir isn't valid
        # backup just in case.
        try:
            self.gpg.set_homedir(homedir=self.home_dir, keyring=[])
            self.lookup_secret_keys()
            self.lookup_public_keys()
        except KeyError as k:
            # If its not valid gpg homedir, will throw a keyerror
            self.log('not a valid gpg homedir: {}'.format(self.home_dir))
            self.log('switching back to: {}'.format(old_dir))
            self.home_dir = old_dir
            self.gpg.set_homedir(homedir=self.home_dir, keyring=[])
            self.lookup_secret_keys()
            self.lookup_public_keys()



        print(self.gpg.gnupghome)
        self.text_logOutput.appendPlainText('setting homedir: {}'.format(self.home_dir))
        return

    def lookup_public_keys(self):
        self.pubkeys_loaded = self.gpg.keyring_info(private=False)
        print('Found {} public key(s)'.format(len(self.privkeys_loaded)))

    def lookup_secret_keys(self):
        self.privkeys_loaded = self.gpg.keyring_info(private=True)
        print('Found {} secret key(s)'.format(len(self.privkeys_loaded)))
        self.combo_currentKey.blockSignals(True)
        self.combo_currentKey.clear()
        for idx, key in enumerate(self.privkeys_loaded):
            print(key)
            self.combo_currentKey.addItem("")
            self.combo_currentKey.setItemText(idx, key)
        self.combo_currentKey.blockSignals(False)
        self.update_current_key()

    def update_current_key(self):
        self.current_key = self.privkeys_loaded[self.combo_currentKey.currentText()]
        logger.debug('Current key changed to: {}{}'.format(self.current_key['keyid'], self.current_key['uids']))

    def import_file(self, box):
        child = self.findChild(QPlainTextEdit, box)
        filename = QFileDialog.getOpenFileName(self, 'Open File', str(Path.home()))
        logger.debug('{}: importing file: {}'.format(box, filename))
        if filename[0]:
            self.log('opening {}'.format(filename[0]))
            filetype = magic.from_file(filename[0], mime=True)
            if filetype == 'text/plain':
                with open(filename[0], 'r') as file:
                    text = file.read()
                self.log('ok')
            else:
                text = ''
                self.log('could not open file type: {}'.format(filetype))
        child.setPlainText(text)

    def save_buffer(self, data):
        # If saving binary stuff, send it here first.
        # The save function will
        # if box:
        #     child = self.findChild(QPlainTextEdit, box)
        #     logger.debug('{}: saving file'.format(box))
        #     data = child.toPlainText()

        self._output_buffer.append(data)
        return

    def save_file(self, box):
        if len(self._output_buffer) > 0:
            text = self._output_buffer.pop()
        else:
            child = self.findChild(QPlainTextEdit, box)
            logger.debug('{}: saving file'.format(box))
            text = child.toPlainText()

        print(type(text))

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename, _ = QFileDialog.getSaveFileName(self, "Open", "", "All Files (*.*)", options=options)
        logger.debug('{}: saving file: {}'.format(box, filename))

        flags = 'w'
        if type(text) is bytes:
            flags += 'b'

        if filename:
            with open(filename, flags) as file:
                file.write(text)

    def view_key(self):
        self.key_viewer = KeyView_Ui(self.gpg, self.pubkeys_loaded)

    def select_keyring(self):
        self.print_info()
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        dialog = QFileDialog()
        dialog.setFilter(QtCore.QDir.AllEntries | QtCore.QDir.Hidden)
        filename = dialog.getOpenFileName(self, 'Open File', str(Path.home()), options=options)
        logger.debug('select_keyring: opening keyring file'.format(filename))
        if filename[0]:
            # Fix this to make sure is a valid keyring file.
            if filename[0].endswith('.gpg') or filename[0].endswith('.kbx'):
                self.log('using keyring: {}'.format(filename[0]))
                # Add keyring to list
                self.keyrings.append(filename[0])
                self.gpg.keyring.append(filename[0])
                self.keyring_labelCurrentKeyPath.setText(filename[0])

                self.home_dir = os.path.dirname(filename[0])
                self.gpg.set_homedir(homedir=self.home_dir)
                self.lookup_secret_keys()
                self.lookup_public_keys()
                self.gpg.print_keys(private=False)

            else:
                self.log('ERROR {}: keyring must have extension .gpg or .kbx'.format(filename[0]))
            self.print_info()

    def import_public_key(self):
        self.text_logOutput.appendPlainText('importing new public key...')
        pubkey = self.keyring_textInput.toPlainText()
        imported = self.gpg.handle_import(pubkey)
        self.log(imported.stderr)
        return

    def encrypt_text(self):
        if not hasattr(self, 'selected_recipients'):
            self.select_recipients()
        recipients = []
        for recip in self.recipientDialog.selected:
            recipients.append(self.pubkeys_loaded[recip]['uids'][0])
        if len(recipients) > 0:

            data = self.encrypt_textInput.toPlainText()
            self.log('encrypting data.')
            armor = self.encrypt_checkArmor.isChecked()
            self.log('armor = {}'.format(armor))

            encrypted = self.gpg.handle_encrypt(data=data, recipients=recipients, armor=armor)

            logger.debug('armor = {}'.format(armor))
            if armor:
                logger.debug('encrypted text should be ascii')
                self.encrypt_textOutput.setPlainText(encrypted.data.decode())
            else:
                logger.debug('encrypted text should be binary')
                logger.debug('putting encrypted data in buffer to save')
                self.save_buffer(data=encrypted.data)
                self.encrypt_textOutput.setPlainText('Preview not available - Binary output. Save to a file.')
            self.log(encrypted.stderr)

    def encrypt_symmetric(self):
        logger.debug('perfoming symmetric encryption')

        armor = self.symmetric_checkArmor.isChecked()
        logger.debug('armor = {}'.format(armor))

        cipher = self.symmetric_comboCipher.currentText()
        logger.debug('cipher = {}'.format(cipher))

        data = self.symmetric_textInput.toPlainText()

        encrypted = self.gpg.handle_encrypt_symmetric(data, armor=armor, cipher=cipher)

        self.log(encrypted.stderr)
        self.log(encrypted.status)

        if armor:
            logger.debug('encrypted text should be ascii')
            self.symmetric_textOutput.setPlainText(encrypted.data.decode())
        else:
            logger.debug('putting encrypted data in buffer to save')
            self.save_buffer(data=encrypted.data)
            self.symmetric_textOutput.setPlainText('Preview not available - Binary output. Save to a file.')

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
                self.log('adding recipient: {}'.format(recip))
            return self.selected_recipients

    def decrypt_text(self):
        print('decrypting')
        data = self.decrypt_textInput.toPlainText()
        decrypted = self.gpg.handle_decrypt(data)
        print(decrypted.data.decode())
        self.log(decrypted.stderr)
        self.decrypt_textOutput.setPlainText(decrypted.data.decode())
        return

    def verify_text(self):
        data = self.verify_textInput.toPlainText()
        verified = self.gpg.handle_verify(data)
        if verified:
            id = next(iter(verified.sig_info.keys()))
            sig_info = verified.sig_info[id] # Get the dict key

            form = 'VERIFIED\n'
            form += 'timestamp (formatted) {}\n'.format(gpg_utils.format_time(sig_info['timestamp']))
            for key in sig_info:
                form += (key + ':' + str(sig_info[key]) + '\n')
        else:
            form = 'UNVERIFIED'
        self.text_logOutput.appendPlainText(verified.stderr)
        self.verify_textOutput.setPlainText(form)

    def sign_text(self):
        keyid = self.current_key['keyid']
        data = self.sign_textInput.toPlainText()
        if data:
            signed_data = self.gpg.handle_sign(data, keyid=keyid)
            if signed_data:
                print(signed_data.data.decode())
                self.sign_textOutput.setPlainText(signed_data.data.decode())
            self.text_logOutput.appendPlainText(signed_data.stderr)

    def print_info(self):
        info = '''
               homedir: {}
               keyring: {}
               current key: {}
               number of private keys: {}
               number of public keys: {}
               '''.format(
            self.gpg.gnupghome,
            self.gpg.keyring,
            self.current_key['uids'],
            len(self.privkeys_loaded),
            len(self.pubkeys_loaded)
        )
        print('-------------------------')
        print(info)
        print('-------------------------')


def main():
    app = QApplication(sys.argv)
    form = App()
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()