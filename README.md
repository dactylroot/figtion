# figtion

                .---.
        .-.     |~~~|
        |~|     |~~~|--.
    .---!-|  .--| C |--|
    |===|*|--|%%| f |  |
    |   |*|__|  | g |  |
    |===|*|==|  |   |  |
    |   |_|__|  |~~~|__|
    |===|~|--|%%|~~~|--|
    `---^-^--^--^---`--' hjw


A simple configuration interface with plaintext and encrypted file support.

## Benefits

  * seemless Python `dict` interface
    * unified config definition and defaults
  * YAML text file source for file-system input & serialization
    * nested entries supported
  * simple precedence
    * `defaults` **keys** define config **keys**
    * YAML **values** override `defaults` **values**
  * secrets support
    * secrets saved to private YAML file
    * secrets encrypted at rest via environment variable
    * update & mask from public YAML file

## Examples

### Config Definition and Defaults

    import figtion

    defaults = {'my server'       : 'www.bestsite.web'
               ,'number of nodes' : 5
               ,'password'        : 'huduyutakeme4'
               ,'nested stuff'    : {'breakfast' : 'coffee'}
               ,'listed stuff'    : ['a','b','c']}

    cfg = figtion.Config(defaults=defaults,filepath='./conf.yml')

    print(cfg['my server'])  

This will print either '[_www.bestsite.web_](.)' or the value of 'my server' in `./conf.yml` if it is something else.

*defaults* strictly defines the schema. Only keys present in *defaults* from a serial file will be retained. If you want to risk unspecified input keys and load everything from the YAML file, you can either omit the *defaults* parameter or set `promiscuous=True` when constructing `Config`.

### Self-Documenting Plaintext

Specify if/when you want to update stored plaintext file.

    cfg = figtion.Config(..., promiscuous=True)
    ...
    cfg.dump()

If `concise=True`, only modified values are stored in text file.
If `promiscuous=False` (default behavior), deprecated values are quietly removed.
Otherwise, serialized YAML will clarify default, modified, and deprecated values:
    
	##############################
	####       Modified       ####
	##############################
	my server: www.newsite.web


	##############################
	####       Default        ####
	##############################
	number of nodes: 5


	##############################
	####      Deprecated      ####
	##############################
	fave cat: Zelda


### Config Secrets

When you want a public config file and a separate secret one.
To keep secret encrypted "at rest", set a secret key environment variable *FIGKEY*.

    os.environ["FIGKEY"] = "seepost-itnote"

    cfg = figtion.Config(defaults=defaults,filepath='./conf.yml',secretpath='./creds.yml')
    cfg.mask('password')

    print(cfg['password'])

This will print the value of `'password'`, which is stored in `./creds.yml` and not `./conf.yml`. If the value of `'password'` is changed in either YAML file, the password will be updated in `./creds.yml` and masked from `./conf.yml` the next time the class is loaded in Python. If a secret key is present via environment variable *FIGKEY*, the values in `./creds.yml` will be encrypted using that key.
The dictionary object returned for `cfg` contains the true value.

If you want everything treated as secret, provide a `secretpath` and omit `filepath`:

    cfg = figtion.Config(secretpath='./creds.yml')

In this case, no call to `mask` is needed and everything is encrypted at rest.

#### Encryption Details

This uses the *pynacl* bindings to the *libsodium* library, which uses [the XSalsa20 algorithm](https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xsalsa20) for encryption. The encryption key provided by the *FIGKEY* environment variable is truncated to a 32-byte string.

## Roadmap

  * 0.9 - secrets store in separate location
  * 1.0 - secrets store in encrypted location
  * 1.1 - make default, modified, and unused properties explicit in plaintext
  * 1.? - automatic/dynamic reloading of YAML files
  * 1.? - support cascading configuration files
