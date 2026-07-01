import os as _os
import copy as _copy
import time as _time
import yaml as _yaml
import contextlib as _contextlib
from pathlib import Path as _Path
import nacl.secret as _secret
import nacl.exceptions as _nacl_exc

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX platform (e.g. Windows)
    _fcntl = None

_MASK_FLAG = "masked configs"

### Process-wide advisory-lock registry, keyed by absolute file path.
### Serializes load()/dump() across separate processes (e.g. gunicorn
### workers) sharing the same file, while staying reentrant *within* a
### single process so the mask()/dump()/_unmask() call chain — which can
### nest load()/dump() calls against the same path — never self-deadlocks.
_lock_registry = {}


@_contextlib.contextmanager
def _file_lock(path):
    path = _os.path.abspath(path)
    entry = _lock_registry.get(path)
    if entry is not None:
        entry[1] += 1
        try:
            yield
        finally:
            entry[1] -= 1
        return

    if _fcntl is None:
        ### No advisory locking available on this platform; degrade to
        ### unlocked access rather than blocking config reads/writes.
        yield
        return

    lockpath = path + '.lock'
    try:
        _os.makedirs(_os.path.dirname(lockpath), exist_ok=True)
        fd = _os.open(lockpath, _os.O_CREAT | _os.O_RDWR)
        _fcntl.flock(fd, _fcntl.LOCK_EX)
    except OSError:
        yield
        return

    _lock_registry[path] = [fd, 1]
    try:
        yield
    finally:
        del _lock_registry[path]
        _fcntl.flock(fd, _fcntl.LOCK_UN)
        _os.close(fd)


class Config(dict):
    ### Public flag: set to True when a dynamic reload pulled in new values.
    ### The user is responsible for observing and clearing this flag.
    changed = False

    @property
    def filepath(self):
        return self._filepath

    def __init__(self, filepath = None, defaults = None, secretpath = None, verbose=True, promiscuous=False, description = None, concise=False, reload_interval=5, strict_secrets=True):
        self.description = description if description else "configurations"
        if filepath:
            self._filepath = _os.path.abspath(_os.path.expanduser(filepath))
        else:
            self._filepath = None
        ### Deep-copy so nested mutations don't alias self with self._defaults
        self._defaults = _copy.deepcopy(defaults) if defaults else defaults
        self._interred = None
        self._masks = {}
        self._verbose=verbose
        self._concise=concise
        self._allsecret = description == _MASK_FLAG
        self._promiscuous = promiscuous or (not defaults)

        ### Dynamic reload state. The public `changed` class attribute is
        ### the user-observable flag (declared at class scope above).
        ### `_reloading` starts True so that overridden read methods invoked
        ### during init (via load()/_recursive_strict_update) skip the reload
        ### check until construction is complete.
        self._reload_interval = reload_interval
        self._last_check = _time.monotonic()
        self._file_mtimes = {}
        self._reloading = True
        ### Depth counter incremented during dump()/_mask()/_unmask() to suppress
        ### _maybe_reload() re-entry while mask/unmask operations are in flight.
        self._masking = 0

        if secretpath:
            if not filepath:
                self._filepath = _os.path.abspath(_os.path.expanduser(secretpath))
                self._allsecret = True
            else:
                ### Inner secrets Config: disable its own reload checking;
                ### the outer Config drives reloads for both files.
                try:
                    self._interred = Config(filepath=secretpath,description=_MASK_FLAG,promiscuous=True,reload_interval=None)
                except OSError as e:
                    ### A missing/mismatched FIGKEY (or corrupt secrets file) means
                    ### secrets can't be decrypted right now. With strict_secrets=True
                    ### (default) that's fatal, matching prior behavior. Otherwise,
                    ### construct without decrypted secrets rather than failing the
                    ### whole outer Config — mask()/_unmask() already treat a missing
                    ### _interred as "nothing to resolve", so masked fields simply
                    ### keep their mask placeholder until the key is restored.
                    if strict_secrets:
                        raise
                    if verbose:
                        print(f"Warning: could not load secrets file '{secretpath}' ({e}); "
                              "continuing without decrypted secrets.")
                    self._interred = None

        ### Precedence of YAML over defaults
        if defaults:
            self.update(_copy.deepcopy(defaults))
        if self._filepath:
            self.load()
        self._refresh_mtimes()
        self._reloading = False

    def dump(self,filepath=None):
        """ Serialize to YAML """
        if filepath:
            self._filepath = filepath
        if not self._filepath:
            raise ValueError("dump() requires a filepath")

        ### Serialize the whole mask + write + unmask cycle against other
        ### processes sharing this file. Reentrant, so the nested _unmask()
        ### call below (which may itself call dump()) does not self-deadlock.
        with _file_lock(self.filepath):
            ### Suppress _maybe_reload() for the mask + write phase so that dict
            ### accesses inside _mask() and the list comprehensions below (self.keys(),
            ### self[k]) do not trigger a file reload — which would recurse back into
            ### _unmask() → dump() infinitely when reload_interval=0.
            self._masking += 1
            try:
                self._mask()

                default_keys = set(self._defaults.keys()) if self._defaults else set()
                used       = [k for k in self.keys() if k in default_keys]
                modified   = {k:self[k] for k in used if self[k] != self._defaults[k]}
                unmodified = {k:self[k] for k in used if self[k] == self._defaults[k]}
                deprecated = {k:self[k] for k in self.keys() if k not in default_keys}

                store = "%YAML 1.1\n---\n"
                _yams = _yaml.dump(modified,default_flow_style=False,indent=4)
                if self._concise:
                    store += _yams
                else:
                    store += "# this file should be located at {}\n".format(self.filepath)
                    store += "\n\n"
                    store += "############################################################\n"
                    store += "#### {: ^50} ####\n".format(self.description)
                    store += "############################################################\n"
                    store += "\n\n"

                    store += "##############################\n"
                    store += "#### {: ^20} ####\n".format('Modified')
                    store += "##############################\n"
                    if modified:
                        store += _yams
                    store += "\n\n"

                    if unmodified and not self._concise:
                        store += "##############################\n"
                        store += "#### {: ^20} ####\n".format('Default')
                        store += "##############################\n"
                        _yams = _yaml.dump(unmodified,default_flow_style=False,indent=4)
                        store += _yams
                        store += "\n\n"

                    if deprecated and not self._concise:
                        store += "##############################\n"
                        store += "#### {: ^20} ####\n".format('Deprecated')
                        store += "##############################\n"
                        _yams = _yaml.dump(deprecated,default_flow_style=False,indent=4)
                        store += _yams
                        store += "\n\n"

                # Store encrypted values
                _os.makedirs(_Path(self.filepath).parent,exist_ok=True)
                key = self._getcipherkey()
                if key: # encrypt secrets before writing
                    box = _secret.SecretBox(key)

                    store = box.encrypt(store.encode())
                    with open(self.filepath,'wb') as ymlfile:
                        ymlfile.write(store.nonce + store.ciphertext)
                else:
                    with open(self.filepath,'w') as ymlfile:
                        ymlfile.write(store)
            finally:
                self._masking -= 1
                ### Refresh mtimes so the _maybe_reload() check in _unmask() (and on
                ### the next dict access) does not see a spurious change and re-trigger.
                self._refresh_mtimes()

            self._unmask()

    def _recursive_strict_update(self,a,b):
        """ Update only items from 'b' which already have a key in 'a'.
            This defines behavior when there is a "schema change".
            a corresponds to canon schema.
            b corresponds to serialized (potentially outdated) YAML file:
              * values present in 'b' preside
              * 'promiscuous=False': only items defined in 'a' are kept
              * 'promiscuous=True' : items defined in 'b' are also kept
        """
        if not b:
            return
        if not a:
            a.update(b)
            return

        for key in b.keys():
            if isinstance(b[key],dict):
                if not isinstance(a.get(key), dict):
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
        with _file_lock(self.filepath):
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
                if isinstance(e, FileNotFoundError):
                    self.dump()
                    if self._verbose:
                        print(f"Initialized config file '{self.filepath}'")
                elif type(e) is UnicodeDecodeError:
                    raise OSError(f"Missing the encryption key for file '{self.filepath}'")
                elif isinstance(e, (_nacl_exc.CryptoError, _nacl_exc.ValueError)):
                    raise OSError(f"Decryption failed for '{self.filepath}': file may be plaintext but FIGKEY is set")
                else:
                    raise e

    def _watched_files(self):
        files = []
        if self._filepath:
            files.append(self._filepath)
        if self._interred and self._interred._filepath:
            files.append(self._interred._filepath)
        return files

    def _refresh_mtimes(self):
        for fp in self._watched_files():
            try:
                self._file_mtimes[fp] = _os.path.getmtime(fp)
            except OSError:
                self._file_mtimes[fp] = None

    def _maybe_reload(self):
        """ If reload_interval has elapsed since last check, compare source
            file mtimes; on change, reload and set `changed` if any value
            actually differs. Guarded against reentry from load()/_unmask(). """
        if self._reloading or self._reload_interval is None or self._masking:
            return
        now = _time.monotonic()
        if now - self._last_check < self._reload_interval:
            return
        self._last_check = now

        file_changed = False
        for fp in self._watched_files():
            try:
                mtime = _os.path.getmtime(fp)
            except OSError:
                continue
            if mtime != self._file_mtimes.get(fp):
                file_changed = True
                break
        if not file_changed:
            return

        self._reloading = True
        try:
            ### Snapshot under guard so dict(self)'s iteration doesn't recurse.
            before = _copy.deepcopy(dict(self))
            self.load()
            after = dict(self)
        finally:
            self._reloading = False
        ### Refresh after load: dump()s triggered inside _unmask() bump mtimes.
        self._refresh_mtimes()
        if after != before:
            self.changed = True

    def __getitem__(self, key):
        self._maybe_reload()
        return super().__getitem__(key)

    def __contains__(self, key):
        self._maybe_reload()
        return super().__contains__(key)

    def get(self, key, default=None):
        self._maybe_reload()
        return super().get(key, default)

    def keys(self):
        self._maybe_reload()
        return super().keys()

    def values(self):
        self._maybe_reload()
        return super().values()

    def items(self):
        self._maybe_reload()
        return super().items()

    def __iter__(self):
        self._maybe_reload()
        return super().__iter__()

    def __len__(self):
        self._maybe_reload()
        return super().__len__()

    def _nestupdate(self,key,val):
        cfg = self
        parts = key.split('.')
        for segment in parts[:-1]:
            cfg = dict.__getitem__(cfg, segment)
        dict.__setitem__(cfg, parts[-1], val)

    def _nestread(self,key):
        cfg = self
        for part in key.split('.'):
            cfg = dict.__getitem__(cfg, part)
        return cfg

    def mask(self,cfg_key,mask='*****'):
        """ Separate flagged variables for storage.
            Replace flagged variables with mask value.
            Good for sensitive credentials.
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
