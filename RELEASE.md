# PyPI Release

PyPI filenames and versions are immutable. Version `0.1.0` was previously
uploaded and deleted, so it cannot be reused even though it is absent from the
visible release history. The next release is `0.1.1`.

## Verify

```bash
python3 -m compileall -q r_ascan tests
python3 -m unittest discover -s tests -v
```

## Build

```bash
python3 -m pip install --upgrade build twine
rm -rf build dist R_AScan.egg-info
python3 -m build
python3 -m twine check dist/*
```

Expected artifacts:

```text
dist/r_ascan-0.1.1-py3-none-any.whl
dist/r_ascan-0.1.1.tar.gz
```

## Upload

Create a project-scoped token from:

<https://pypi.org/manage/project/R-AScan/settings/>

Upload with an explicit token username:

```bash
python3 -m twine upload \
  --username __token__ \
  --verbose \
  dist/r_ascan-0.1.1-py3-none-any.whl \
  dist/r_ascan-0.1.1.tar.gz
```

Enter the complete `pypi-...` token when prompted. Do not put the token in the
command line, repository, or shell history.

## Verify publication

```bash
python3 -m venv /tmp/r-ascan-release-test
source /tmp/r-ascan-release-test/bin/activate
python -m pip install --upgrade R-AScan==0.1.1
R-AScan --help
R-AScan --list-scanners
```
