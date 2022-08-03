import os as _os
import yaml as _yaml
from pathlib import Path as _Path
from functools import reduce as _reduce
import nacl.secret as _secret

_MASK_FLAG = "masked configs"

class Config(dict):
    @property
    def filepath(self):
        return self._filepath

    def __init__(self,description = None, filepath = None, defaults = None, secretpath = None, verbose=True, promiscuous=False):
        self.description = description if description else "configurations"
        self._filepath = filepath
        self._interred = None
        self._masks = {}
        self._verbose=verbose
        self._allsecret = description == _MASK_FLAG
        self._promiscuous = promiscuous or (not defaults)

        if secretpath:
            if not filepath:
                self._filepath = secretpath
                self._allsecret = True
            else:
                self._interred = Config(filepath=secretpath,description=_MASK_FLAG,promiscuous=True)

        ### Precedence of YAML over defaults
        if defaults:
            self.update(defaults)
        if self._filepath:
            self.load()

    def dump(self,filepath=None):
        """ Serialize to YAML """
        if filepath:
            self._filepath = filepath

        self._mask()

        store = "%YAML 1.1\n---\n"
        store += "# this file should be located at {}\n".format(_os.path.abspath(self.filepath))
        store += "\n\n"
        store += "###########################################################\n"
        store += "####{: ^50} ####\n".format(self.description)
        store += "###########################################################\n"
        store += "\n\n"
        _yams = _yaml.dump(dict(self.items()),default_flow_style=False,indent=4)
        store += _yams
        store += "\n\n"

        key = self._getcipherkey()
        if key: # encrypt secrets before writing
            box = _secret.SecretBox(key)

            store = box.encrypt(store.encode())
            with open(self.filepath,'wb') as ymlfile:
                ymlfile.write(store.nonce + store.ciphertext)
        else:
            with open(self.filepath,'w') as ymlfile:
                ymlfile.write(store)

        self._unmask()

    def _recursive_strict_update(self,a,b):
        """ Update only items from 'b' which already have a key in 'a'.
            This defines behavior when there is a "schema change".
            a corresponds to canon schema.
            b corresponds to serialized (potentially outdated) YAML file:
              * only items defined in 'a' are kept
              * 'promiscuous' mode: items defined in 'b' are also kept
              * values present in 'b' are given priority
         """
        if not a:
            a.update(b)
            return
        if not b:
            return

        for key in b.keys():
            if isinstance(b[key],dict):
                if not key in a.keys():
                    a[key] = {}
                self._recursive_strict_update(a[key],b[key])
            elif key in a.keys() or self._promiscuous:
                a[key] = b[key]

    def _getcipherkey(self):
        """ return cipherkey environment variable forced to 32-bit bytestring
            return None to indicate no encryption """
        key = _os.getenv("FIGKEY",default="")
        if not key or not self._allsecret:
            return None
        if len(key) > 32:
            return key[:32].encode()
        else:
            return key.ljust(32).encode()

    def load(self):
        """ Load from filepath and overwrite local items. """
        try:
            key = self._getcipherkey()
            if key:
                with open(self.filepath,'rb') as ymlfile:
                    nc = ymlfile.read()
                    nonce = nc[:_secret.SecretBox.NONCE_SIZE]
                    ciphertext = nc[_secret.SecretBox.NONCE_SIZE:]

                box = _secret.SecretBox(key)
                newstuff = box.decrypt(ciphertext=ciphertext,nonce=nonce)
                newstuff = newstuff.decode('utf-8')

            else:
                with open(self.filepath,'r') as ymlfile:
                    newstuff = ymlfile.read()

            newstuff = _yaml.load(newstuff, Loader=_yaml.FullLoader)
            self._recursive_strict_update(self,newstuff)
            self._unmask()
        except Exception as e:
            if self._verbose and hasattr(e,'strerror') and 'No such file' in e.strerror:
                self.dump()
                print(f"Initialized config file '{self.filepath}'")
            elif type(e) is UnicodeDecodeError:
                raise OSError(f"Missing the encryption key for file '{self.filepath}'")
            else:
                raise e

    def _nestupdate(self,key,val):
        cfg = self
        key = key.split('.')
        if len(key) > 1:
            cfg = cfg[key.pop(0)]
        cfg[key[0]] = val

    def _nestread(self,key):
        if len(key.split('.')) > 1:
            return _reduce(dict.get, key.split('.'), self)
        else:
            return self[key]

    def mask(self,cfg_key,mask='*****'):
        """ Good for sensitive credentials.
            Mask is serialized to `self.filepath`.
            True value serialized to `self.secretpath`. """
        if self._interred is None:
            raise Exception('Cannot mask without a secretpath serializing path.')

        self._masks[cfg_key] = mask
        if self._nestread(cfg_key) != mask:
            self._interred[cfg_key] = self._nestread(cfg_key)
        self._unmask()

    def _mask(self):
        if self._masks:

            for key,mask in self._masks.items():
                self._interred[key] = self._nestread(key)
                self._nestupdate(key,mask)

            self._interred.update({'_masks':self._masks})
            self._interred.dump()

    def _unmask(self):
        """ resolve hierarchy: {new_val > interred > mask} """
        if not self._interred:
            return
        self._interred.load()

        try:
            self._masks.update(self._interred.pop('_masks'))
        except KeyError:
            pass

        for key,mask in self._masks.items():
            current = self._nestread(key)

            if current != mask:
                self._interred[key] = current
                self._interred.dump() # write to protected YAML
                self.dump()           # write to external YAML

            try:
                self._nestupdate(key,self._interred[key])
            except KeyError:
                pass

    def __repr__(self):
        str = ('secret ' if self._allsecret else '') + f"config reading from {self._filepath}"
        if self._interred:
            str+= f"\nsecrets stored in {self._interred._filepath}"
        if self._promiscuous:
            str+= "\npromiscuous mode"
        if self._verbose:
            str+= "\nverbose mode"
        str += "\nValues:\n"
        str += super().__repr__()
        return str

with open(_Path(_os.path.abspath(_os.path.dirname(__file__))) / '__doc__','r') as _f:
    __doc__ = _f.read()
