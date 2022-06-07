# figtion

                .---.
        .-.     |~~~|
        |_|     |~~~|--.
    .---!~|  .--| C |--|
    |===| |--|%%| f |  |
    |   | |__|  | g |  |
    |===| |==|  |   |  |
    |   |_|__|  |~~~|__|
    |===|~|--|%%|~~~|--|
    `---^-^--^--^---`--' hjw


A simple configuration interface with text file support

## Benefits

  * seemless Python `dict` interface
    * unified config definition and defaults
  * YAML text file source for file-system input & serialization
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
               ,'password'        : 'huduyutakeme4' }
    cfg = figtion.Config(defaults=defaults,filepath='~/conf.yml')

    print(cfg['my server'])  

This will print either '[_www.bestsite.web_](.)' or the value of 'my server' in `~/conf.yml` if it is something else.

### Config Secrets

When you want a public config file and a separate secret one.
To keep secret encrypted "at rest", set a secret key environment variable *FIGKEY*.

    os.environ["FIGKEY"] = "seepost-itnote"

    cfg = figtion.Config(defaults=defaults,filepath='./conf.yml',secretpath='./creds.yml')
    cfg.mask('password')

    print(cfg['password'])

This will print the value of `'password'`, which is stored in `./creds.yml` and not `./conf.yml`. If the value of `'password'` is changed in either YAML file, the password will be updated in `./creds.yml` and masked from `./conf.yml` the next time the class is loaded in Python. If a secret key is present via environment variable *FIGKEY*, the values in `./creds.yml` will be encrypted using that key.
The dictionary object returned for `cfg` contains the true value.

If you want everything treated as secret, only provide a `secretpath`:

    cfg = figtion.Config(defaults=defaults,secretpath='./creds.yml')

In this case no call to `mask` is needed, everything is encrypted at rest.

## Roadmap

  * 0.9 - secrets store in separate location
  * 1.0 - secrets store in encrypted location
    * 1.0.1 - easy support for all-secret config
  * 1.1 - automatic/dynamic reloading of YAML files
