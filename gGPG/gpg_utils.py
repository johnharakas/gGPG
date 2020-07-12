from datetime import datetime

import gnupg


def format_time(timestamp):
    return datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')


class GPG_Handler(gnupg.GPG):
    def __init__(self, homedir=None, keyring=[]):
        super().__init__(gnupghome=homedir, keyring=[])
        self.homedir = homedir
        self.gnupghome = self.homedir
        self.gpg_version = '{}.{}.{}'.format(*self.version)

    def print_keys(self, private=False):
        keylist = self.list_keys(private)
        for idx, key in enumerate(keylist):
            uid = str(key['uids'])
            keyid = key['keyid']
            print(uid, keyid)

    def keyring_info(self, private=True):
        """
        return keyring information
        key_dict references the dictionary object for each key
        Dictionary key is concatenated '<keyid> <uid>'.
        :param private: if True, get private keys, else get public keys
        :return: dictionary of keys
        """
        keylist = self.list_keys(private)
        key_dict = {}
        for idx, key in enumerate(keylist):
            uid = str(key['uids'])
            keyid = key['keyid']
            print(uid, keyid)
            newkey = (keyid + ' ' + uid)
            key_dict[newkey] = key
        return key_dict

    def set_homedir(self, homedir, keyring=[]):
        print('Using home dir: {}'.format(homedir))
        print('Using keyring: {}'.format(keyring))
        self.gnupghome = homedir
        self.keyring = keyring

    def handle_import(self, key):
        imported = self.import_keys(key)
        return imported

    def handle_encrypt(self, data, recipients, armor=True, keyring=None):
        extra = ['--keyring ', keyring]
        encr = self.encrypt(data=data, armor=armor, recipients=recipients, extra_args=keyring,)
        return encr

    def handle_encrypt_symmetric(self, data, is_file=False, output=None, armor=False, cipher='AES256'):
        if is_file:
            with open(data, 'rb') as f:
                status = self.encrypt_file(f,
                                           recipients=None,
                                           symmetric=cipher,
                                           armor=armor,
                                           output=output)
                return status
        else:
            status = self.encrypt(data,
                                  recipients=None,
                                  symmetric=cipher,
                                  armor=armor,
                                  output=output)
            return status

    def handle_decrypt(self, text):
        decrypted = self.decrypt(text)
        return decrypted

    def handle_verify(self, data):
        """
        :param data: string
        :return:
        """
        verified = self.verify(data)
        print("Verified" if verified else "Unverified")
        return verified

    def handle_sign(self, data, keyid=None):
        signed_data = self.sign(data, keyid=keyid)
        if signed_data.status == 'signature created':
            return signed_data

    def handle_export(self, key, armor=True):
        print(key)
        return self.export_keys(key['fingerprint'], armor=armor)