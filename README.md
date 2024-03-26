
# Setting up pre-commit hooks:

The project uses pre-commit hooks to clear outputs of IPython Notebooks before commit.
This reduces the size of commits and removes redundant changes.

To enable this, first ensure that ``pre-commit`` is installed:
```
pip install pre-commit
```
Now simply run:

```
pre-commit install
```

# Required Environment Variables

Please place all relevant environment variables in the ``.env`` file in the project home directory.

- API_KEY_VIRUS_TOTAL: your [virustotal](https://www.virustotal.com/gui/home/upload) API key.
- HF_HOME: set to ``\cache\hf\misc``.
- HF_DATASETS_CACHE: set to ``\cache\hf\datasets``
- TRANSFORMERS_CACHE: set to ``cache\hf\models``

# Transferring wheels to VM environment

On the host, go to the ``wheels`` folder and run the following code:
```
pip download --python-version "PYTHON_VERSION" --only-binary=:all: PKG_NAME 
```
The ``wheels`` folder should be shared between host and VM.
On the VM then run:
```
pip install --no-index --find-links PATH_TO_WHEEL_DIR PKG_NAME
```


#  Supported file types


- #### office files:
  - basic metadata (author, creation date, file size, etc.).
  - file type (docx, xlsx, docm, etc.)
  - extract paragraphs from word files.
  - extract vba code.
  - analyze vba code with oletools.
  - use mraptor to analyze malicious behaviour.
  - Extraction of zip metadata (if possible).
- #### rtf files:
  - basic metadata (author, creation date, file size, etc.).
  - Embedded object analysis with rtfobj.
  - Dumping of file to text with textract.

### Additional notes:
- ``pydantic`` dependency handling:
  - Feature extraction and raw processing requires ``"pydantic~=2.0"``
  - Use of LLMs (transformers) requires ``"pydantic~=1.10"``