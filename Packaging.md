
## Preparation

    python3 -m pip install --user --upgrade setuptools wheel
    python3 -m pip install --user --upgrade twine

## Distribution

[.pypirc](https://pypi.org/manage/account/token/)

  1. Build: `python3 setup.py sdist bdist_wheel`
  2. Twine Distribution:
  2. Distribute:
    * `twine upload --repository figtion dist/*`
      * [Preview](https://pypi.org/project/figtion/)
    * `twine upload --repository-url https://test.pypi.org/legacy/ dist/*`
      * [Preview](https://test.pypi.org/project/figtion/)
  3. Distribute github backup:
    1. `git tag 1.0.0 -m "tag for PyPI"`
    2. `git push --tags remotename branchname`
