# MalwareDoc - Clustering text documents containing malware



# Setting up a secure environment:

Use the following step by step [tutorial](https://oliviagallucci.com/creating-a-vm-for-malware-analysis-in-virtualbox/)
for a windows 10 virtual machine running on Virtualbox. This is safe for static analysis tasks but also 
for most dynamic analysis.

Other tutorials can be found here:

[Flare VM](https://www.mandiant.com/resources/blog/flare-vm-the-windows-malware)

[Remnux](https://remnux.org/) - do not use Remnux in a docker container for dynamic analysis since docker
can potentially get exploited due to root priviliges.

[Virtualbox for dynamic analysis](https://malwareunicorn.org/workshops/re101.html#2)


# Setting up pytorch

First run:

```
nvcc --version
```
to identify your CUDA installed cuda version. Then run the following script with the correct CUDA version specified:

```
pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/<CUDA_VERSION>
```

For example (for CUDA 11.8):

```
pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

For further details see [pytorch homepage](https://pytorch.org).

Then to verify the installation try to execute this [notebook](notebooks/util/check_torch_gpu.ipynb).



# Setting up unrar
You need to download the [UnRaR](www.rarlab.com/rar_add.htm) executable.
Then go to:
```
<PYTHON_ENV_PATH>\Lib\site-packages\rarfile.py
```
and set 
```
UNRAR_TOOL = r"<PATH_TO_UNRAR_EXE>"
```


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

- #### pdf files:
  - basic metadata (author, creation date, file size, etc.).
  - detailed metadata (xmp, encryption).
  - extract images.
  - extract attachments.
  - extract text.
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
- #### zip archives:
  - basic metadata (author, creation date, file size, etc.).
  - Zip specific metadata.
  - Automatic unzip.
  - Recursive parsing and analysis of extracted files.
- #### rar archives:
  - basic metadata (author, creation date, file size, etc.).
  - Rar specific metadata.
  - Automatic unrar.
  - Recursive parsing and analysis of extracted files.
- #### other extracted content:
  - detection and decoding of base64 substrings.
  - detection and decoding of base32 substrings.
  - detection and extraction of ipv4 & ipv6 ips within strings.
  - detection of language.



# General pipeline

1) Extract raw results from files as ``json`` using
[main.py](src/malwaredoc/main.py). The results are currently written to the [results](data/results) folder.

2) Select relevant files using
[select_relevant_files.ipynb](notebooks/results/select_relevant_files.ipynb).
This will write [relevant_models.json](data/clustering/relevant_models.json).

3) Now extract relevant attributes to dataframe columns using
[files_to_dataframe.ipynb](notebooks/results/files_to_dataframe.ipynb).
This will create a dataframe from raw extracted features from the json files and write it to [raw.parquet](data/clustering/raw.parquet).

For the next steps we can configure the feature processing using [feature-config.toml](data/clustering/feature-config.toml).

4) To extract additional features we use
[additional_features.ipynb](notebooks/results/additional_features.ipynb). This extracts additional features from the raw features and saves the results to [features.parquet](data/clustering/features.parquet).
- ``convert_to_numerical_columns`` - columns to convert to float.
- ``byte_columns`` - columns to convert to float from a string with byte unit.
- ``string_analyzer_columns`` - columns to analyze with the string-analyzer.

5) We now preprocess our features in the following way (see ``preproccesing`` config in [feature-config.toml](data/clustering/feature-config.toml)):
- ``input_features`` - are preprocessed automatically (assuming categorical, boolean or numerical).
- ``embedding_columns`` - text is embedded, supports multiple languages, but doesn't work on code.
- ``style_embedding_columns`` - text is embedded, but only works for english language text.
- ``code_analysis_columns`` - code is analyzed by a LLM and the analysis result is embedded.
- ``ner_columns`` - columns that should be analyzed with a NER model.

# Currently supported clustering pipelines:

### Text Clustering 
The following pipeline can be found in ``notebooks\clustering\text_similarity.ipynb``
```
document -> extract text -> summarize text with llm -> calculate embeddings -> cluster by similarity
```


### Behaviour Clustering

```

```

### Feature Clustering
The following pipeline can be found in ``notebooks\clustering\basic_clustering.ipynb``
```
document -> select relevant features (categorical and numerical) -> preprocess & transform features -> cluster
```


### Additional notes:
- ``pydantic`` dependency handling:
  - Feature extraction and raw processing requires ``"pydantic~=2.0"``
  - Use of LLMs (transformers) requires ``"pydantic~=1.10"``