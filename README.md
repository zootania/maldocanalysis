
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