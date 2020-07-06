from datetime import datetime

import gnupg

# class GPG_Handler(gnupg.GPG):
#     def __init__(self, homedir):
#         super().__init__()
#         self.homedir = homedir
#         self.gnupghome = self.homedir


print(gnupg.__version__)
homedir = '/home/modp/.gnupg_test'
# homedir = '/home/modp/.gnupg'

try:
    gpg = gnupg.GPG(gnupghome=homedir, keyring=[])
except TypeError:
    gpg = gnupg.GPG(homedir=homedir, keyring=[])
gpg_version = '{}.{}.{}'.format(*gpg.version)


def format_time(timestamp):
    return datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')


def keyring_info(private=True):
    """
    return keyring information
    key_dict references the dictionary object for each key
    Dictionary key is concatenated '<keyid> <uid>'.
    :param private: if True, get private keys, else get public keys
    :return: dictionary of keys
    """
    keylist = gpg.list_keys(private)
    key_dict = {}
    for idx, key in enumerate(keylist):
        uid = str(key['uids'])
        keyid = key['keyid']
        print(uid, keyid)
        newkey = (keyid + ' ' + uid)
        key_dict[newkey] = key
    return key_dict


def print_keys(private=False):
    keylist = gpg.list_keys(private)
    for idx, key in enumerate(keylist):
        uid = str(key['uids'])
        keyid = key['keyid']
        print(uid, keyid)



def set_homedir(homedir='/home/modp/.gnupg_test', keyring=[]):
    try:
        gpg = gnupg.GPG(gnupghome=homedir, keyring=keyring)
    except TypeError:
        gpg = gnupg.GPG(homedir=homedir, keyring=keyring)
    return gpg


def import_key(key):
    imported = gpg.import_keys(key)
    return imported


def encrypt_text(data, recipients, keyring=None):
    extra = ['--keyring ', keyring]
    encr = gpg.encrypt(data=data, recipients=recipients, extra_args=keyring,)
    return encr


def decrypt_text(text):
    decrypted = gpg.decrypt(text)
    return decrypted


def verify_signature(data):
    """
    :param data: string
    :return:
    """
    verified = gpg.verify(data)
    print("Verified" if verified else "Unverified")
    return verified


def sign_data(data, keyid=None):
    signed_data = gpg.sign(data, keyid=keyid)
    if signed_data.status == 'signature created':
        return signed_data