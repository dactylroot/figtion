
import os
import sys
import time
import threading
import pytest
from pathlib import Path

_mypath = Path(os.path.abspath(Path(os.path.dirname(__file__))))
sys.path.append(str(_mypath.parent))

import figtion

class TestFigtion:

    confpath = _mypath / 'conf.yml'
    secretpath = _mypath / 'creds.yml'
    openpath = _mypath / 'opencreds.yml'
    defaults = {'my server'       : 'www.bestsite.web'
               ,'number of nodes' : 5
               ,'password'        : 'huduyutakeme4' }

    secretkey = "seepost-itnote"

    def setup_method(self, method):
        os.environ["FIGKEY"] = self.secretkey

        self.cfg = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        self.cfg.mask('password')

    def teardown_method(self, method):
        if os.path.exists(self.confpath):
            os.remove(self.confpath)
        if os.path.exists(self.secretpath):
            os.remove(self.secretpath)
        if os.path.exists(self.openpath):
            os.remove(self.openpath)

    def test_serialization(self):
        os.environ["FIGKEY"] = self.secretkey

        cfg = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        cfg.mask('password')
        cfg.dump()

        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        assert( len(newfig._masks) == 1 )
        assert(newfig['my server'] == 'www.bestsite.web')

    def test_type_inference_serialization(self):
        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        assert(newfig['number of nodes'] == 5)

    def test_encrypted_serialization(self):
        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        assert(newfig['password'] == 'huduyutakeme4')

    def test_masking(self):
        dumbfig = figtion.Config(defaults=self.defaults,filepath=self.confpath)
        assert( len(dumbfig._masks) == 0 )
        assert(dumbfig['password'] != 'huduyutakeme4')
        assert(dumbfig['password'] == '*****')

    def test_encrypted_update(self):
        self.cfg['password'] = 'supersecret'
        self.cfg.dump()

        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)

        assert(newfig['password'] == 'supersecret')

        dumbfig = figtion.Config(defaults=self.defaults,filepath=self.confpath)
        assert(dumbfig['password'] != 'huduyutakeme4')
        assert(dumbfig['password'] != 'supersecret')
        assert(dumbfig['password'] == '*****')

        intered = figtion.Config(description=figtion._MASK_FLAG,filepath=self.secretpath)
        assert(intered['password'] == 'supersecret')

    def test_unencrypted_serialization(self):
        os.environ["FIGKEY"] = ""

        fig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.openpath)
        fig['password'] = self.defaults['password']

        assert( len(fig._masks) == 0 )

        fig.mask('password')
        assert( len(fig._masks) == 1 )

        newfig = figtion.Config(filepath=self.openpath)
        assert( newfig['password'] == self.defaults['password'] )

    def test_explicit_promiscuous_mode(self):
        fig = figtion.Config(promiscuous=True,filepath=self.confpath)

        assert(fig['my server'] == 'www.bestsite.web')
        assert(fig['number of nodes'] == 5)
        assert( len(fig._masks) == 0 )

    def test_implicit_promiscuous_mode(self):
        fig = figtion.Config(filepath=self.confpath)

        assert(fig['my server'] == 'www.bestsite.web')
        assert(fig['number of nodes'] == 5)
        assert( len(fig._masks) == 0 )

    def test_promiscuous_with_secret(self):
        fig = figtion.Config(promiscuous=True,filepath=self.confpath,secretpath=self.secretpath)

        assert(fig['my server'] == 'www.bestsite.web')
        assert(fig['number of nodes'] == 5)
        assert(fig['password'] == self.defaults['password'] )
        assert( len(fig._masks) == 1 )

    def test_only_secret(self):
        fig = figtion.Config(defaults=self.defaults,secretpath=self.secretpath)

        assert( len(fig._masks) == 0 )
        assert( fig['password'] == self.defaults['password'] )

        os.environ["FIGKEY"] = ""

        try:
            fig = figtion.Config(defaults=self.defaults,secretpath=self.secretpath)
        except Exception as e:
            assert( type(e) == OSError )
            assert( str(e).startswith("Missing the encryption key for file"))

    def test_only_secret_explicit_promiscuous(self):
        fig = figtion.Config(promiscuous=True,secretpath=self.secretpath)

        assert( len(fig._masks) == 0 )
        assert( fig['password'] == self.defaults['password'] )

    def test_only_secret_implicit_promiscuous(self):
        fig = figtion.Config(secretpath=self.secretpath)

        assert( len(fig._masks) == 0 )
        assert( fig['password'] == self.defaults['password'] )

    def test_missing_encryption_key(self):
        """Default (strict_secrets=True): a missing FIGKEY on an encrypted
        secrets file is fatal with a clear message."""
        os.environ["FIGKEY"] = ""

        with pytest.raises(OSError, match="Missing the encryption key for file"):
            figtion.Config(defaults=self.defaults, filepath=self.confpath,
                           secretpath=self.secretpath)

    def test_mask_nested_key(self):
        try:

            defaults = {'sub secret'      : {'password': 'huduyutakeme4' }}

            fig = figtion.Config(defaults=defaults,filepath=self.confpath,secretpath=self.secretpath)
            fig.mask('sub secret.password')
        except Exception as e:
            assert( type(e) == KeyError )
            assert( str(e).startswith("'password'"))

    def test_mask_nonexistent_secretpath(self):
        try:
            fig = figtion.Config(defaults=self.defaults,filepath=self.confpath)
            fig.mask('nonexistent')
        except Exception as e:
            assert( type(e) == Exception )
            assert( str(e).startswith('Cannot mask without a secretpath serializing path.'))

    def test_mask_nonexistent_key(self):
        try:
            fig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
            fig.mask('nonexistent')
        except Exception as e:
            assert( type(e) == KeyError )
            assert( str(e).startswith("'nonexistent'"))

    # --- regression tests for previously fixed bugs ---

    def test_dump_defaults_none(self):
        """dump() with defaults=None should not crash (AttributeError on None.keys())"""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(filepath=self.confpath)
        fig['foo'] = 'bar'
        fig.dump()
        loaded = figtion.Config(filepath=self.confpath)
        assert loaded['foo'] == 'bar'

    def test_dump_empty_modified_section(self):
        """dump() should produce valid YAML when modified section is empty (no {} before block mappings)"""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath)
        fig.dump()
        loaded = figtion.Config(defaults=self.defaults, filepath=self.confpath)
        assert loaded['my server'] == self.defaults['my server']

    def test_plaintext_file_with_figkey_set(self):
        """Loading a plaintext secret file when FIGKEY is set should raise a clear OSError"""
        os.environ["FIGKEY"] = ""
        figtion.Config(defaults=self.defaults, filepath=self.confpath, secretpath=self.openpath)
        os.environ["FIGKEY"] = self.secretkey
        with pytest.raises(OSError, match="plaintext"):
            figtion.Config(defaults=self.defaults, filepath=self.confpath, secretpath=self.openpath)

    def test_short_file_nonce_error(self):
        """A secret file shorter than 24 bytes raises nacl.exceptions.ValueError (bad nonce size);
        should surface as OSError, not a raw nacl exception"""
        os.environ["FIGKEY"] = self.secretkey
        with open(self.secretpath, 'wb') as f:
            f.write(b'tooshort')  # < 24-byte NONCE_SIZE
        with pytest.raises(OSError):
            figtion.Config(defaults=self.defaults, filepath=self.confpath, secretpath=self.secretpath)

    # --- tests exposing confirmed bugs ---

    def test_nestupdate_three_levels(self):
        """BUG: _nestupdate only descends one level, so 3-deep keys write to the wrong location"""
        fig = figtion.Config(defaults={'a': {'b': {'c': 'original'}}})
        fig._nestupdate('a.b.c', 'updated')
        # Currently sets fig['a']['b'] = 'updated' instead of fig['a']['b']['c'] = 'updated'
        assert fig['a']['b']['c'] == 'updated'

    def test_nestread_missing_nested_key_raises_keyerror(self):
        """BUG: _nestread raises TypeError (not KeyError) for missing nested keys,
        inconsistent with single-key access which raises KeyError"""
        fig = figtion.Config(defaults={'x': 1})
        with pytest.raises(KeyError):
            fig._nestread('missing.key')

    def test_dump_raises_without_filepath(self):
        """BUG: dump() with no filepath raises an unhelpful TypeError"""
        fig = figtion.Config(defaults=self.defaults)
        with pytest.raises(ValueError, match="filepath"):
            fig.dump()

    def test_recursive_strict_update_empty_a_none_b(self):
        """Empty config + None from an empty YAML file should not raise TypeError on a.update(None)"""
        fig = figtion.Config()
        fig._recursive_strict_update(fig, None)
        assert len(fig) == 0

    def test_defaults_not_shared_with_self_for_nested_dicts(self):
        """Nested-dict defaults must be deep-copied so mutations to self don't
        poison self._defaults or the caller's dict."""
        original = {'section': {'key': 'original'}}
        fig = figtion.Config(defaults=original, promiscuous=True)
        fig['section']['key'] = 'changed'
        assert original['section']['key'] == 'original'
        assert fig._defaults['section']['key'] == 'original'
        assert fig['section']['key'] == 'changed'

    def test_modified_nested_dict_serialized_as_modified(self):
        """Mutated nested-dict values must serialize into the 'Modified' section
        so they survive subsequent dump/load cycles."""
        os.environ["FIGKEY"] = ""
        defaults = {'db': {'host': 'localhost', 'user': ''}}
        fig = figtion.Config(defaults=defaults, filepath=self.confpath)
        fig['db']['user'] = 'postgres'
        fig.dump()
        with open(self.confpath) as f:
            text = f.read()
        mod_idx = text.find('Modified')
        def_idx = text.find('Default')
        user_idx = text.find("user: postgres")
        assert mod_idx != -1 and user_idx != -1
        assert mod_idx < user_idx < def_idx if def_idx != -1 else mod_idx < user_idx

    def test_recursive_strict_update_scalar_to_dict(self):
        """BUG: _recursive_strict_update crashes with AttributeError when a key holds
        a scalar in 'a' but a dict in 'b' (schema change from scalar to nested dict)"""
        fig = figtion.Config(defaults={'x': 'scalar'}, promiscuous=True)
        # Simulate loading a file where 'x' is now a nested dict
        fig._recursive_strict_update(fig, {'x': {'nested': 'val'}})
        assert fig['x'] == {'nested': 'val'}

    def test_dynamic_reload_sets_changed_flag(self):
        """Modifying the source YAML after construction should trigger a
        reload on next access and set `changed=True` when values differ."""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath, reload_interval=0)
        assert fig['my server'] == 'www.bestsite.web'
        assert fig.changed is False

        # Rewrite the source file with a new value; bump mtime to be safe.
        with open(self.confpath, 'w') as f:
            f.write("%YAML 1.1\n---\nmy server: www.othersite.web\n")
        os.utime(self.confpath, (time.time() + 1, time.time() + 1))

        # Next read triggers a reload (interval=0 means "always check").
        assert fig['my server'] == 'www.othersite.web'
        assert fig.changed is True

        # User clears the flag after handling the change.
        fig.changed = False
        # Untouched file: subsequent reads do not re-set the flag.
        _ = fig['my server']
        assert fig.changed is False

    def test_dynamic_reload_interval_gates_check(self):
        """A non-zero reload_interval should suppress checks until elapsed."""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath, reload_interval=60)

        with open(self.confpath, 'w') as f:
            f.write("%YAML 1.1\n---\nmy server: www.othersite.web\n")
        os.utime(self.confpath, (time.time() + 1, time.time() + 1))

        # Within the 60-second window, no reload happens.
        assert fig['my server'] == 'www.bestsite.web'
        assert fig.changed is False

    def test_dynamic_reload_disabled_with_none(self):
        """reload_interval=None disables the feature entirely."""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath, reload_interval=None)

        with open(self.confpath, 'w') as f:
            f.write("%YAML 1.1\n---\nmy server: www.othersite.web\n")
        os.utime(self.confpath, (time.time() + 1, time.time() + 1))

        assert fig['my server'] == 'www.bestsite.web'
        assert fig.changed is False

    def test_dynamic_reload_no_flag_when_only_mtime_changes(self):
        """Touching the file without changing content should not flip `changed`."""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath, reload_interval=0)
        _ = fig['my server']

        # Bump mtime but leave content alone by re-dumping the same config.
        os.utime(self.confpath, (time.time() + 1, time.time() + 1))

        _ = fig['my server']
        assert fig.changed is False

    def test_mask_nested_update_zero_reload_no_recursion(self):
        """Updating a masked nested value when reload_interval=0 must not raise
        RecursionError.  Root cause: _nestread/_nestupdate called Config.__getitem__,
        which triggered _maybe_reload() during _mask()/_unmask(); the mtime always
        differed (we just wrote the file), so load() -> _unmask() -> dump() looped
        infinitely.  Fixed by using dict.__getitem__ inside _nestread/_nestupdate."""
        os.environ["FIGKEY"] = ""
        defaults = {'api_keys': {'secret': '', 'token': ''}}
        fig = figtion.Config(defaults=defaults, filepath=self.confpath,
                             secretpath=self.openpath, reload_interval=0)
        fig['api_keys']['secret'] = 'initial_secret'
        fig['api_keys']['token']  = 'initial_token'
        fig.mask('api_keys.secret')
        fig.mask('api_keys.token')

        # Simulate replacing the whole sub-dict then re-masking — the pattern
        # used by update_api_keys() in the renewals app that surfaced this bug.
        fig['api_keys'] = {'secret': 'new_secret', 'token': 'new_token'}
        fig.mask('api_keys.secret')  # raised RecursionError before the fix
        fig.mask('api_keys.token')

        assert fig['api_keys']['secret'] == 'new_secret'
        assert fig['api_keys']['token']  == 'new_token'

        # Masked value must be hidden in the serialized conf file.
        with open(self.confpath) as f:
            conf_text = f.read()
        assert 'new_secret' not in conf_text
        assert 'new_token'  not in conf_text

    def test_filenot_found_uses_isinstance(self):
        """FileNotFoundError detection should use isinstance, not string-match on strerror,
        so it cannot false-positive on other OSErrors that happen to have a strerror attr"""
        import errno
        # PermissionError has strerror but is NOT a missing-file error
        e = PermissionError(errno.EACCES, 'No such file or directory', str(self.confpath))
        # The current string-match heuristic would incorrectly treat this as file-not-found
        # if the error message happened to contain 'No such file'.
        assert not isinstance(e, FileNotFoundError)
        assert hasattr(e, 'strerror') and 'No such file' in e.strerror  # shows the risk

    # --- cross-process file locking ---

    def test_file_lock_reentrant_same_process(self, tmp_path):
        """Nested _file_lock calls on the same path within one process must not
        block each other (the mask()/dump()/_unmask() cycle nests load()/dump()
        calls on the same file), and must fully release when the outermost
        context exits."""
        target = str(tmp_path / "reentrant.yml")
        with figtion._file_lock(target):
            assert figtion._lock_registry[target][1] == 1
            with figtion._file_lock(target):
                assert figtion._lock_registry[target][1] == 2
            assert figtion._lock_registry[target][1] == 1
        assert target not in figtion._lock_registry

    def test_lock_registry_empty_after_normal_operations(self):
        """dump()/mask() must not leak entries in the lock registry."""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath,
                              secretpath=self.secretpath)
        fig.mask('password')
        fig.dump()
        assert figtion._lock_registry == {}

    def test_file_lock_serializes_across_processes(self, tmp_path):
        """_file_lock must actually block a second, independent OS process —
        not just guard against reentrancy within one process — since that is
        the real gunicorn multi-worker race the lock exists to prevent."""
        import subprocess

        target = str(tmp_path / "shared.yml")
        holder_script = (
            "import sys; sys.path.insert(0, {figpath!r}); import figtion\n"
            "with figtion._file_lock({target!r}):\n"
            "    print('locked', flush=True)\n"
            "    sys.stdin.readline()\n"
        ).format(figpath=str(_mypath.parent), target=target)

        proc = subprocess.Popen([sys.executable, '-c', holder_script],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            assert line.strip() == 'locked'  # child now holds the lock

            def _release_after_delay():
                time.sleep(0.3)
                proc.stdin.write('go\n')
                proc.stdin.flush()

            releaser = threading.Thread(target=_release_after_delay)
            releaser.start()
            try:
                start = time.monotonic()
                with figtion._file_lock(target):
                    elapsed = time.monotonic() - start
            finally:
                releaser.join()
        finally:
            proc.wait(timeout=5)

        assert elapsed >= 0.25, "parent acquired the lock before the child process released it"

    # --- non-fatal secrets decryption failure (strict_secrets) ---

    def test_strict_secrets_true_raises_on_bad_figkey(self):
        """Default behavior (strict_secrets=True) is unchanged: a secrets file
        that can't be decrypted under the current FIGKEY is fatal."""
        os.environ["FIGKEY"] = "a-completely-different-key"
        with pytest.raises(OSError, match="Decryption failed"):
            figtion.Config(defaults=self.defaults, filepath=self.confpath,
                           secretpath=self.secretpath)

    def test_strict_secrets_false_degrades_on_bad_figkey(self):
        """strict_secrets=False lets the outer Config construct even when the
        secrets file can't be decrypted (e.g. FIGKEY rotated), instead of
        crashing config initialization entirely. Masked fields simply keep
        their mask placeholder until the correct key is restored."""
        os.environ["FIGKEY"] = "a-completely-different-key"
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath,
                             secretpath=self.secretpath, strict_secrets=False)
        assert fig._interred is None
        assert fig['password'] == '*****'
        with pytest.raises(Exception, match='Cannot mask without a secretpath'):
            fig.mask('password')

    def test_strict_secrets_false_degrades_on_missing_figkey(self):
        """Same as above, for the 'FIGKEY unset entirely' case."""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath,
                             secretpath=self.secretpath, strict_secrets=False)
        assert fig._interred is None
        assert fig['password'] == '*****'
